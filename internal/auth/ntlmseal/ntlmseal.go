// Package ntlmseal implements NTLMv2 authentication for WinRM with two
// capabilities go-psrp / Azure-go-ntlmssp lack:
//
//  1. Pass-the-hash: authenticate from a raw NT hash (no plaintext password).
//  2. WinRM message sealing: SEAL/SIGN the SOAP body so it works against a
//     default WinRM listener (AllowUnencrypted=false).
//
// It satisfies go-psrp's auth.Authenticator interface, so it drops in via the
// (patched) client.Config.CustomAuthenticator field.
//
// References: MS-NLMP (NTLM), MS-WSMV 2.2.9.1 (SPNEGO session encryption),
// jborean93/pyspnego + pypsrp encryption.py.
package ntlmseal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"

	"github.com/sresarehumantoo/wsmancer/internal/proxydial"
)

// NTLM negotiate flags.
const (
	negUnicode     = 0x00000001
	negRequestTgt  = 0x00000004
	negSign        = 0x00000010
	negSeal        = 0x00000020
	negNTLM        = 0x00000200
	negAlwaysSign  = 0x00008000
	negExtendedSec = 0x00080000 // NTLM2 session security
	negTargetInfo  = 0x00800000
	negVersion     = 0x02000000
	neg128         = 0x20000000
	negKeyExch     = 0x40000000
	neg56          = 0x80000000
)

var ntlmSig = []byte("NTLMSSP\x00")

var debugOn = os.Getenv("NTLMSEAL_DEBUG") != ""

const (
	boundary = "Encrypted Boundary"
	protocol = "application/HTTP-SPNEGO-session-encrypted"
	// defaultUserAgent is what the genuine Windows WinRM client sends; matching it
	// avoids a trivial network-side tell. -a/--user-agent overrides it.
	defaultUserAgent = "Microsoft WinRM Client"
)

// Config configures the provider.
type Config struct {
	User        string
	Domain      string
	Password    string // used only if NTHash is empty
	NTHash      []byte // 16-byte NT hash; if set, pass-the-hash (Password ignored)
	Workstation string
	UserAgent   string // HTTP User-Agent; empty defaults to the real WinRM client's

	InsecureSkipVerify bool // skip TLS verify for HTTPS/5986 (ignored if TLSConfig is set)

	// TLSConfig, if set, is used verbatim for the HTTPS handshake, it carries
	// the caller's full verification policy (RootCAs, a pinning
	// VerifyPeerCertificate, ServerName, or InsecureSkipVerify). When nil the
	// provider falls back to InsecureSkipVerify and any TLS config on the base
	// transport.
	TLSConfig *tls.Config

	// Dialer, when non-nil, dials the target's TCP connection, that is where
	// --proxy lands. A nil *proxydial.Dialer dials directly and is the normal
	// case, so this needs no branching below.
	Dialer *proxydial.Dialer
}

// Provider is a go-psrp auth.Authenticator.
type Provider struct {
	cfg    Config
	ntHash []byte
}

// New builds a Provider. Supply either Password or NTHash.
func New(cfg Config) (*Provider, error) {
	nt := cfg.NTHash
	if len(nt) == 0 {
		h := md4.New()
		h.Write(utf16le(cfg.Password))
		nt = h.Sum(nil)
	}
	if len(nt) != 16 {
		return nil, fmt.Errorf("NT hash must be 16 bytes, got %d", len(nt))
	}
	if cfg.Workstation == "" {
		cfg.Workstation = "WORKSTATION"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}
	return &Provider{cfg: cfg, ntHash: nt}, nil
}

// Name implements auth.Authenticator.
func (p *Provider) Name() string { return "NTLM" }

// Transport implements auth.Authenticator. It returns a RoundTripper that owns
// a single persistent net.Conn and speaks HTTP/1.1 over it directly, instead of
// wrapping Go's connection-pooling http.Transport. NTLM auth is bound to a TCP
// connection and the RC4 seal handles are stateful, so owning exactly one
// connection is the correct model: WSMan is request/response, serialized
// naturally by the connection. The base transport is ignored (we only borrow
// its TLS config, if any).
func (p *Provider) Transport(base http.RoundTripper) http.RoundTripper {
	rt := &connRoundTripper{p: p, insecure: p.cfg.InsecureSkipVerify}
	if p.cfg.TLSConfig != nil {
		// The caller fully specified TLS policy; use it verbatim.
		rt.tlsCfg = p.cfg.TLSConfig.Clone()
		rt.tlsExplicit = true
	} else if ht, ok := base.(*http.Transport); ok && ht.TLSClientConfig != nil {
		rt.tlsCfg = ht.TLSClientConfig.Clone()
	}
	if debugOn {
		fmt.Fprintf(os.Stderr, "[ntlmseal] Transport: single-connection HTTP/1.1 (base=%T ignored)\n", base)
	}
	return rt
}

// ---- NTLM message construction -------------------------------------------

func (p *Provider) type1() []byte {
	flags := uint32(negUnicode | negRequestTgt | negSign | negSeal | negNTLM |
		negAlwaysSign | negExtendedSec | negVersion | neg128 | negKeyExch | neg56)
	var b bytes.Buffer
	b.Write(ntlmSig)
	binary.Write(&b, binary.LittleEndian, uint32(1))
	binary.Write(&b, binary.LittleEndian, flags)
	b.Write(make([]byte, 8)) // DomainNameFields (empty)
	b.Write(make([]byte, 8)) // WorkstationFields (empty)
	b.Write(osVersion())     // Version
	return b.Bytes()
}

type challenge struct {
	serverChallenge []byte
	targetInfo      []byte
}

func parseType2(b []byte) (*challenge, error) {
	if len(b) < 48 || !bytes.Equal(b[:8], ntlmSig) {
		return nil, errors.New("invalid NTLM type-2 message")
	}
	sc := b[24:32]
	tiLen := binary.LittleEndian.Uint16(b[40:42])
	tiOff := binary.LittleEndian.Uint32(b[44:48])
	var ti []byte
	if tiLen > 0 && int(tiOff)+int(tiLen) <= len(b) {
		ti = b[tiOff : tiOff+uint32(tiLen)]
	}
	return &challenge{serverChallenge: sc, targetInfo: ti}, nil
}

// type3 builds the authenticate message and returns it plus the exported
// session key used to derive the seal/sign keys.
func (p *Provider) type3(ch *challenge, t1, t2 []byte) (msg, exported []byte, err error) {
	respKeyNT := ntowfv2(p.cfg.User, p.cfg.Domain, p.ntHash)

	clientChallenge := make([]byte, 8)
	if _, err = rand.Read(clientChallenge); err != nil {
		return nil, nil, err
	}

	temp := ntlmv2Temp(timestamp(ch.targetInfo), clientChallenge, ch.targetInfo)
	ntProof, ntResponse := ntlmv2Response(respKeyNT, ch.serverChallenge, temp)
	keyExchKey := keyExchangeKey(respKeyNT, ntProof)

	// Key exchange: random ExportedSessionKey, RC4-wrapped with KeyExchangeKey.
	exported = make([]byte, 16)
	if _, err = rand.Read(exported); err != nil {
		return nil, nil, err
	}
	encRandomSessionKey := rc4crypt(keyExchKey, exported)

	// LmChallengeResponse is Z(24), unconditionally. MS-NLMP 3.1.5.1.2 says a
	// client SHOULD do this when the challenge carries an MsvAvTimestamp (every
	// Vista/2008-and-later server sends one, per 2.2.2.1), but the reason it is
	// safe even against an acceptor that sends no timestamp is server-side:
	// 3.2.5.1.2 compares LmChallengeResponse only *inside* the branch taken when
	// the NT response mismatches, so a valid NTLMv2 response means the field is
	// never examined, and 3.4.5.1's KXKEY discards it outright for NTLMv2.
	// Samba's ntlm_password_check short-circuits identically.
	//
	// Sending a real LMv2 alongside NTLMv2 is worse than redundant. It enabled
	// CVE-2019-1338 (a DC skips NTLMv2 AV_Pair validation when an LMv2 response
	// is present, letting a relay strip the MIC and channel bindings), it is why
	// Samba zeroes the field, and it is a recognisable impacket tell, Windows,
	// Chromium, .NET and Samba all put 24 zero bytes on the wire.
	lmResponse := make([]byte, 24)

	domain := utf16le(p.cfg.Domain)
	user := utf16le(p.cfg.User)
	ws := utf16le(p.cfg.Workstation)

	flags := uint32(negUnicode | negRequestTgt | negSign | negSeal | negNTLM |
		negAlwaysSign | negExtendedSec | negTargetInfo | negVersion | neg128 | negKeyExch | neg56)

	const headerLen = 88 // through the 16-byte MIC field
	payload := &bytes.Buffer{}
	off := headerLen
	field := func(data []byte) []byte {
		f := make([]byte, 8)
		binary.LittleEndian.PutUint16(f[0:2], uint16(len(data)))
		binary.LittleEndian.PutUint16(f[2:4], uint16(len(data)))
		binary.LittleEndian.PutUint32(f[4:8], uint32(off))
		off += len(data)
		payload.Write(data)
		return f
	}
	lmF := field(lmResponse)
	ntF := field(ntResponse)
	domF := field(domain)
	userF := field(user)
	wsF := field(ws)
	eskF := field(encRandomSessionKey)

	var h bytes.Buffer
	h.Write(ntlmSig)
	binary.Write(&h, binary.LittleEndian, uint32(3))
	h.Write(lmF)
	h.Write(ntF)
	h.Write(domF)
	h.Write(userF)
	h.Write(wsF)
	h.Write(eskF)
	binary.Write(&h, binary.LittleEndian, flags)
	h.Write(osVersion())
	micOff := h.Len()
	h.Write(make([]byte, 16)) // MIC placeholder
	h.Write(payload.Bytes())
	msg = h.Bytes()

	// MIC = HMAC_MD5(ExportedSessionKey, type1 || type2 || type3-with-zero-MIC)
	micMac := hmac.New(md5.New, exported)
	micMac.Write(t1)
	micMac.Write(t2)
	micMac.Write(msg)
	copy(msg[micOff:micOff+16], micMac.Sum(nil))
	return msg, exported, nil
}

// ---- SEAL / SIGN ----------------------------------------------------------

type sessionKeys struct {
	mu                     sync.Mutex
	clientSeal, serverSeal *rc4.Cipher
	clientSign, serverSign []byte
	clientSeq, serverSeq   uint32
}

func newSessionKeys(exported []byte) *sessionKeys {
	cs, _ := rc4.NewCipher(sealKey(exported, "client-to-server"))
	ss, _ := rc4.NewCipher(sealKey(exported, "server-to-client"))
	return &sessionKeys{
		clientSeal: cs,
		serverSeal: ss,
		clientSign: signKey(exported, "client-to-server"),
		serverSign: signKey(exported, "server-to-client"),
	}
}

// wrap seals plaintext and produces the 16-byte NTLM signature.
func (k *sessionKeys) wrap(plain []byte) (sig, sealed []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	sealed = make([]byte, len(plain))
	k.clientSeal.XORKeyStream(sealed, plain)

	mac := hmac.New(md5.New, k.clientSign)
	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, k.clientSeq)
	mac.Write(seq)
	mac.Write(plain)
	checksum := mac.Sum(nil)[:8]
	enc := make([]byte, 8)
	k.clientSeal.XORKeyStream(enc, checksum) // key-exchange: encrypt checksum too

	sig = make([]byte, 16)
	binary.LittleEndian.PutUint32(sig[0:4], 1)
	copy(sig[4:12], enc)
	binary.LittleEndian.PutUint32(sig[12:16], k.clientSeq)
	k.clientSeq++
	return sig, sealed
}

// errBadSignature means a sealed server message failed its integrity check.
// It is terminal for the connection: RC4 is a stream cipher, so by the time the
// checksum is known to be wrong the keystream has already advanced and cannot
// be rewound. The caller closes the connection and re-handshakes.
var errBadSignature = errors.New("ntlm: message signature verification failed (the response was altered in transit)")

// errOutOfSequence means a sealed server message declared a sequence number
// other than the one expected, a replay or a reorder. Terminal for the same
// reason as errBadSignature: the keystream has already advanced.
var errOutOfSequence = errors.New("ntlm: sealed message out of sequence (replayed or reordered)")

// terminalUnwrapError reports whether an unwrap failure is an integrity failure
// rather than a parse failure. The distinction decides what the transport does
// with the body, so it is not cosmetic: an integrity failure must drop the
// connection, while a body that was never really ours is passed through.
// Getting this wrong is invisible to unwrap's own tests, it returned the right
// error, and the transport ignored it, which is exactly how the sequence case
// was handing callers raw ciphertext dressed up as an XML parse error.
func terminalUnwrapError(err error) bool {
	return errors.Is(err, errBadSignature) || errors.Is(err, errOutOfSequence)
}

// unwrap decrypts a sealed server message and verifies its signature.
//
// MS-NLMP 3.4.2 is normative about this: "On receipt, the message
// authentication code (MAC) value is computed and compared with the received
// value. If they differ, the message MUST be discarded." 3.4.4 says the same
// for the sequence number. Without the check, sealing on plain HTTP/5985 gives
// confidentiality but no integrity, and RC4 is length-preserving and malleable
// , an in-path attacker can XOR chosen deltas into a response and the client
// would render the result as though the target had said it.
//
// Order is load-bearing: the RC4 handle is one continuous keystream, so the
// checksum's 8 bytes are the ones *following* the message's. The body must be
// decrypted first, exactly as wrap seals then signs.
func (k *sessionKeys) unwrap(sig, sealed []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	plain := make([]byte, len(sealed))
	k.serverSeal.XORKeyStream(plain, sealed)

	if len(sig) != 16 {
		return nil, fmt.Errorf("ntlm: signature is %d bytes, want 16", len(sig))
	}
	got := make([]byte, 8)
	k.serverSeal.XORKeyStream(got, sig[4:12])

	mac := hmac.New(md5.New, k.serverSign)
	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, k.serverSeq)
	mac.Write(seq)
	mac.Write(plain)

	// Constant-time, following Samba's ntlmssp_check_packet.
	if !hmac.Equal(got, mac.Sum(nil)[:8]) {
		return nil, errBadSignature
	}
	// The sequence number is checked against our own counter, not merely for
	// self-consistency, so a replayed or reordered message is refused.
	if declared := binary.LittleEndian.Uint32(sig[12:16]); declared != k.serverSeq {
		return nil, fmt.Errorf("%w: got %d, expected %d", errOutOfSequence, declared, k.serverSeq)
	}
	k.serverSeq++
	return plain, nil
}

// wrapHTTP produces the multipart/encrypted body and its Content-Type.
func (k *sessionKeys) wrapHTTP(plain []byte) (contentType string, body []byte) {
	sig, sealed := k.wrap(plain)
	var b bytes.Buffer
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("\tContent-Type: " + protocol + "\r\n")
	fmt.Fprintf(&b, "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n", len(plain))
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("\tContent-Type: application/octet-stream\r\n")
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(sig)))
	b.Write(lenBuf)
	b.Write(sig)
	b.Write(sealed)
	b.WriteString("--" + boundary + "--\r\n")
	return `multipart/encrypted;protocol="` + protocol + `";boundary="` + boundary + `"`, b.Bytes()
}

// unwrapHTTP parses a multipart/encrypted response body and returns plaintext.
func (k *sessionKeys) unwrapHTTP(body []byte) ([]byte, error) {
	plainLen, err := originalLength(body)
	if err != nil {
		return nil, err
	}
	marker := []byte("application/octet-stream\r\n")
	i := bytes.Index(body, marker)
	if i < 0 {
		return nil, errors.New("octet-stream section not found")
	}
	bin := body[i+len(marker):]
	if len(bin) < 4 {
		return nil, errors.New("truncated encrypted body")
	}
	sigLen := int(binary.LittleEndian.Uint32(bin[0:4]))
	if len(bin) < 4+sigLen+plainLen {
		return nil, fmt.Errorf("short body: have %d need %d", len(bin), 4+sigLen+plainLen)
	}
	sig := bin[4 : 4+sigLen]
	sealed := bin[4+sigLen : 4+sigLen+plainLen]
	return k.unwrap(sig, sealed)
}

// ---- single-connection HTTP/1.1 RoundTripper ------------------------------

// connRoundTripper owns one net.Conn for the whole WSMan session. It performs
// the NTLM handshake once on that connection and seals every request over it.
// Because it owns the connection there is no pooling to fight: no MaxConnsPerHost
// tricks, no reactive re-auth. A request whose context is canceled mid-flight
// poisons the connection, so it is closed and transparently re-established (with
// a fresh handshake) on the next request.
type connRoundTripper struct {
	p           *Provider
	insecure    bool
	tlsCfg      *tls.Config
	tlsExplicit bool // tlsCfg fully specifies verification; do not override it

	mu           sync.Mutex // serializes WSMan ops (one HTTP/1.1 conn = one req at a time)
	conn         net.Conn
	br           *bufio.Reader
	keys         *sessionKeys
	pendingType3 string // Authorization header for the first sealed request post-handshake
}

func (t *connRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var plain []byte
	if req.Body != nil {
		var err error
		if plain, err = io.ReadAll(req.Body); err != nil {
			return nil, err
		}
		req.Body.Close()
	}
	if debugOn {
		fmt.Fprintf(os.Stderr, "[ntlmseal] RoundTrip action=%s bodylen=%d haveConn=%v\n",
			soapAction(plain), len(plain), t.conn != nil)
	}

	// One retry: if the live connection is broken (server idle-closed it, or a
	// prior request was canceled), rebuild it and replay this request.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if t.conn == nil {
			if err := t.dialAndHandshake(req); err != nil {
				return nil, err
			}
		}
		resp, err := t.sealed(req, plain)
		if err != nil {
			t.closeConn()
			lastErr = err
			if debugOn {
				fmt.Fprintf(os.Stderr, "[ntlmseal] request failed (%v), attempt=%d\n", err, attempt)
			}
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func (t *connRoundTripper) closeConn() {
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
		t.br = nil
		t.keys = nil
	}
}

func (t *connRoundTripper) dialAndHandshake(req *http.Request) error {
	host := req.URL.Host
	if req.URL.Port() == "" {
		if req.URL.Scheme == "https" {
			host += ":5986"
		} else {
			host += ":5985"
		}
	}
	var conn net.Conn
	var err error
	if req.URL.Scheme == "https" {
		cfg := t.tlsCfg
		if cfg == nil {
			cfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		cfg = cfg.Clone()
		if !t.tlsExplicit {
			cfg.InsecureSkipVerify = t.insecure
		}
		conn, err = proxydial.DialTLS(req.Context(), t.p.cfg.Dialer, "tcp", host, cfg)
	} else {
		conn, err = t.p.cfg.Dialer.DialContext(req.Context(), "tcp", host)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", host, err)
	}
	t.conn = conn
	t.br = bufio.NewReader(conn)

	// Leg 1: Type1 under the Negotiate scheme, empty body -> 401 + Type2.
	t1 := t.p.type1()
	resp, err := t.write(req, nil, "application/soap+xml;charset=UTF-8",
		"Negotiate "+base64.StdEncoding.EncodeToString(t1))
	if err != nil {
		t.closeConn()
		return fmt.Errorf("ntlm leg1: %w", err)
	}
	token := ntlmToken(resp.Header)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if debugOn {
		fmt.Fprintf(os.Stderr, "[ntlmseal] leg1 status=%d challenge=%v\n", resp.StatusCode, token != "")
	}
	if token == "" {
		t.closeConn()
		return fmt.Errorf("ntlm leg1: no challenge (status %d)", resp.StatusCode)
	}
	t2, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.closeConn()
		return fmt.Errorf("ntlm leg1: decode challenge: %w", err)
	}
	ch, err := parseType2(t2)
	if err != nil {
		t.closeConn()
		return err
	}
	t3, exported, err := t.p.type3(ch, t1, t2)
	if err != nil {
		t.closeConn()
		return err
	}
	t.keys = newSessionKeys(exported)
	t.pendingType3 = "Negotiate " + base64.StdEncoding.EncodeToString(t3)
	return nil
}

func (t *connRoundTripper) sealed(req *http.Request, plain []byte) (*http.Response, error) {
	ct, body := t.keys.wrapHTTP(plain)
	auth := ""
	if t.pendingType3 != "" {
		auth = t.pendingType3
		t.pendingType3 = ""
	}
	resp, err := t.write(req, body, ct, auth)
	if err != nil {
		return nil, err
	}
	enc, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(enc) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return resp, nil
	}
	// A WSMan SOAP fault comes back as HTTP 500 but is sealed exactly like a
	// success, so decrypt regardless of status. Two reasons this matters and the
	// old "return the 500 untouched" was wrong: (1) the caller then saw raw
	// ciphertext instead of the real fault; (2) more subtly, the server advanced
	// its RC4 sealing keystream when it sealed the fault, so skipping the
	// client-side unwrap desynced serverSeal for every later response on this
	// (reused) connection. Only unwrap an actually-sealed body, a bare,
	// non-sealed error (proxy 500, etc.) is passed through as-is and leaves the
	// keystream untouched, which is correct because the server didn't seal it.
	if isSealedResponse(resp) {
		plainResp, uerr := t.keys.unwrapHTTP(enc)
		switch {
		case uerr == nil:
			resp.Body = io.NopCloser(bytes.NewReader(plainResp))
			resp.ContentLength = int64(len(plainResp))
			resp.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
			resp.Header.Set("Content-Length", strconv.Itoa(len(plainResp)))
			return resp, nil
		case terminalUnwrapError(uerr):
			// Never fall through to handing the caller the ciphertext: a failed
			// integrity check is the one case that must not look like a parse
			// problem. The keystream is unrecoverable after this, so drop the
			// connection, the next request re-handshakes with fresh keys.
			t.closeConn()
			return nil, uerr
		default:
			// A body we could not parse as sealed at all (truncated, or not
			// really ours). Fall through and let the caller see it.
			if debugOn {
				fmt.Fprintf(os.Stderr, "[ntlmseal] unwrap failed, passing body through: %v\n", uerr)
			}
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(enc))
	return resp, nil
}

// isSealedResponse reports whether the server sealed this response (a WSMan
// multipart/encrypted body). Only such a body should be unwrapped; unwrapping
// advances the stateful server keystream, so it must run exactly once per sealed
// server message and never on an unsealed one.
func isSealedResponse(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "multipart/encrypted")
}

// deadCommsBackstop bounds how long a single request may sit on the connection
// when the caller set no deadline of its own.
//
// Without it a severed connection can hang the shell forever. A command's
// context carries no deadline (it is cancel-only), so the response read had no
// socket deadline at all; when the peer dies *loudly* the read fails with
// ECONNRESET and the transport re-dials, but when the path is silently
// blackholed -- a dropped VPN, a NAT timeout, a firewall discarding the flow --
// no RST ever arrives and the read blocks in netpoll indefinitely. Ctrl-C cannot
// rescue it either, because StopPipelines needs the same connection mutex the
// wedged read is holding. Reproduced with scripts/break-proxy.py.
//
// It must stay comfortably ABOVE every legitimate server-side hold or it would
// recreate the original churn bug (fix (A)): a deadline shorter than the hold
// makes a healthy long-poll look like a dead connection, tearing down the
// connection and re-dialling a fresh WSMan session mid-work. The longest holds
// advertised are PT60S (Create/Command/Send/Signal/Delete) and the Receive poll
// (defaultReceivePoll, 1s by default). 120s clears those with room for a slow
// link, while turning "hangs forever" into "fails in two minutes and recovers".
const deadCommsBackstop = 120 * time.Second

// writeDeadline picks the socket deadline for one request: the caller's, when it
// set one, and otherwise the backstop above. Never zero -- that is the value
// that hangs forever.
func writeDeadline(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Now().Add(deadCommsBackstop)
}

// write sends one HTTP/1.1 request over the owned connection and reads the
// response. It honours the request context's deadline via the conn deadline,
// falling back to deadCommsBackstop so a blackholed connection cannot wedge the
// shell forever.
func (t *connRoundTripper) write(req *http.Request, body []byte, contentType, auth string) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Close = false
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("User-Agent", t.p.cfg.UserAgent)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	} else {
		r.Header.Del("Authorization")
	}

	t.conn.SetDeadline(writeDeadline(req.Context()))

	if err := r.Write(t.conn); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	resp, err := http.ReadResponse(t.br, r)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if debugOn && t.keys != nil {
		fmt.Fprintf(os.Stderr, "[ntlmseal] seq=%d -> status=%d\n", t.keys.clientSeq-1, resp.StatusCode)
	}
	return resp, nil
}

// ---- helpers --------------------------------------------------------------

// ntlmv2Temp builds the NTLMv2 "temp" blob (MS-NLMP 3.3.2):
//
//	Responserversion || HiResponserversion || Z(6) || Time ||
//	ClientChallenge || Z(4) || ServerName || Z(4)
//
// where ServerName is the challenge's AV_PAIR blob, not a hostname. Split out
// of type3 so the vector test can drive it with MS-NLMP 4.2.4's published
// inputs, including its zero FILETIME, which no real clock can produce, and
// compare the result byte for byte. type3 supplies a random client challenge
// and a real clock, neither of which a fixed vector can reach.
func ntlmv2Temp(ts, clientChallenge, targetInfo []byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{1, 1, 0, 0, 0, 0, 0, 0}) // RespType, HiRespType, reserved
	b.Write(ts)                             // 8-byte FILETIME
	b.Write(clientChallenge)
	b.Write([]byte{0, 0, 0, 0})
	b.Write(targetInfo)
	b.Write([]byte{0, 0, 0, 0})
	return b.Bytes()
}

// ntlmv2Response returns NTProofStr and the full NtChallengeResponse
// (NTProofStr || temp). MS-NLMP 3.3.2.
func ntlmv2Response(respKeyNT, serverChallenge, temp []byte) (ntProof, ntResponse []byte) {
	mac := hmac.New(md5.New, respKeyNT)
	mac.Write(serverChallenge)
	mac.Write(temp)
	ntProof = mac.Sum(nil)
	return ntProof, append(append([]byte{}, ntProof...), temp...)
}

// keyExchangeKey returns HMAC_MD5(respKeyNT, NTProofStr), the SessionBaseKey,
// which for NTLMv2 *is* the KeyExchangeKey verbatim (MS-NLMP 3.4.5.1).
func keyExchangeKey(respKeyNT, ntProof []byte) []byte {
	mac := hmac.New(md5.New, respKeyNT)
	mac.Write(ntProof)
	return mac.Sum(nil)
}

func ntowfv2(user, domain string, ntHash []byte) []byte {
	mac := hmac.New(md5.New, ntHash)
	mac.Write(utf16le(strings.ToUpper(user) + domain))
	return mac.Sum(nil)
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

func rc4crypt(key, data []byte) []byte {
	c, _ := rc4.NewCipher(key)
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

func sealKey(exported []byte, dir string) []byte {
	return md5concat(exported, "session key to "+dir+" sealing key magic constant\x00")
}
func signKey(exported []byte, dir string) []byte {
	return md5concat(exported, "session key to "+dir+" signing key magic constant\x00")
}
func md5concat(a []byte, s string) []byte {
	h := md5.New()
	h.Write(a)
	h.Write([]byte(s))
	return h.Sum(nil)
}

func osVersion() []byte {
	// ProductMajor 6, Minor 1, Build 7601, reserved, NTLMRevision 0x0F
	return []byte{6, 1, 0xB1, 0x1D, 0, 0, 0, 0x0F}
}

// timestamp returns the MsvAvTimestamp (AvId 7) from target info, else now.
func timestamp(targetInfo []byte) []byte {
	for i := 0; i+4 <= len(targetInfo); {
		id := binary.LittleEndian.Uint16(targetInfo[i : i+2])
		l := int(binary.LittleEndian.Uint16(targetInfo[i+2 : i+4]))
		i += 4
		if id == 0 { // MsvAvEOL
			break
		}
		if id == 7 && i+l <= len(targetInfo) && l == 8 {
			return targetInfo[i : i+8]
		}
		i += l
	}
	ft := uint64(time.Now().UnixNano()/100) + 116444736000000000
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, ft)
	return b
}

func ntlmToken(h http.Header) string {
	for _, v := range h.Values("Www-Authenticate") {
		if strings.HasPrefix(v, "Negotiate ") {
			return strings.TrimSpace(v[len("Negotiate "):])
		}
	}
	return ""
}

func soapAction(plain []byte) string {
	i := bytes.Index(plain, []byte("<a:Action"))
	if i < 0 {
		return "?"
	}
	rest := plain[i:]
	gt := bytes.IndexByte(rest, '>')
	lt := bytes.Index(rest, []byte("</a:Action"))
	if gt < 0 || lt < 0 || gt+1 > lt {
		return "?"
	}
	uri := string(rest[gt+1 : lt])
	if s := strings.LastIndexByte(uri, '/'); s >= 0 {
		return uri[s+1:]
	}
	return uri
}

func originalLength(body []byte) (int, error) {
	idx := bytes.Index(body, []byte("Length="))
	if idx < 0 {
		return 0, errors.New("no OriginalContent Length")
	}
	rest := body[idx+len("Length="):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	return strconv.Atoi(string(rest[:end]))
}
