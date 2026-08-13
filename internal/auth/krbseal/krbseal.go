// Package krbseal implements Kerberos authentication for WinRM with message
// sealing, the piece go-psrp lacks (its Negotiate/Kerberos path only sets the
// Authorization header and never seals the body, so it fails a default WinRM
// listener with AllowUnencrypted=false).
//
// It does two things go-krb5 does not provide on its own:
//  1. Builds an AP-REQ with a caller-controlled authenticator timestamp (to
//     compensate for host/DC clock skew without touching the system clock) and
//     an initiator sub-session key used for message sealing.
//  2. Implements RFC 4121 §4.2.4 CONFIDENTIALITY wrap tokens (go-krb5 only
//     implements the sign-only wrap), with the Windows RRC rotation, and the
//     WinRM `application/HTTP-Kerberos-session-encrypted` multipart container.
//
// Satisfies go-psrp's auth.Authenticator; reuses the single-connection HTTP/1.1
// transport idea from the NTLM provider.
package krbseal

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

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"

	kasn1 "github.com/go-krb5/x/encoding/asn1"

	"github.com/sresarehumantoo/wsmancer/internal/proxydial"
)

var debugOn = os.Getenv("KRBSEAL_DEBUG") != ""

const (
	boundary = "Encrypted Boundary"
	protocol = "application/HTTP-Kerberos-session-encrypted"
	// defaultUserAgent matches the genuine Windows WinRM client; -a overrides it.
	defaultUserAgent = "Microsoft WinRM Client"
)

// GSS-API context flags (RFC 4121 §4.1.1.1).
const (
	gssDeleg    = 1
	gssMutual   = 2
	gssReplay   = 4
	gssSequence = 8
	gssConf     = 16
	gssInteg    = 32
)

// Config configures the Kerberos provider.
type Config struct {
	TicketPath         string // ccache or kirbi holding the service ticket for SPN
	Krb5ConfPath       string
	SPN                string // e.g. HTTP/dc01.corp.local
	SkewSeconds        int    // add to the AP-REQ authenticator time (DC ahead => positive)
	UserAgent          string // HTTP User-Agent; empty defaults to the real WinRM client's
	InsecureSkipVerify bool   // ignored if TLSConfig is set
	SealEnabled        bool   // false => send plaintext body (only valid vs AllowUnencrypted=true)

	// TLSConfig, if set, is used verbatim for the HTTPS handshake (RootCAs,
	// pinning VerifyPeerCertificate, ServerName, or InsecureSkipVerify). When nil
	// the provider falls back to InsecureSkipVerify and the base transport's TLS.
	TLSConfig *tls.Config

	// Dialer, when non-nil, dials the target's TCP connection, that is where
	// --proxy lands. A nil *proxydial.Dialer dials directly, which is the normal
	// case. Note the ticket is read from a file, so no KDC is contacted and this
	// is the only socket Kerberos auth opens.
	Dialer *proxydial.Dialer
}

// Provider is a go-psrp auth.Authenticator backed by Kerberos + sealing.
type Provider struct {
	cfg     Config
	realm   string
	cname   types.PrincipalName
	tkt     messages.Ticket
	sessKey types.EncryptionKey
}

// New loads a ticket file, a ccache or a kirbi, see loadTicket, and extracts
// the service ticket for the SPN directly (no TGT or live KDC exchange required
// , the ST must already be in the file).
func New(cfg Config) (*Provider, error) {
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}
	creds, err := loadTicket(cfg.TicketPath, cfg.SPN)
	if err != nil {
		return nil, err
	}
	p := &Provider{
		cfg:     cfg,
		realm:   creds.realm,
		cname:   creds.cname,
		tkt:     creds.tkt,
		sessKey: creds.sessKey,
	}
	if debugOn {
		fmt.Fprintf(os.Stderr, "[krbseal] loaded ST for %s (etype %d), skew=%ds seal=%v\n",
			cfg.SPN, p.sessKey.KeyType, cfg.SkewSeconds, cfg.SealEnabled)
	}
	return p, nil
}

// Name implements auth.Authenticator.
func (p *Provider) Name() string { return "Kerberos" }

// Transport implements auth.Authenticator with a single owned connection.
func (p *Provider) Transport(base http.RoundTripper) http.RoundTripper {
	rt := &connRoundTripper{p: p, insecure: p.cfg.InsecureSkipVerify}
	if p.cfg.TLSConfig != nil {
		// The caller fully specified TLS policy; use it verbatim.
		rt.tlsCfg = p.cfg.TLSConfig.Clone()
		rt.tlsExplicit = true
	} else if ht, ok := base.(*http.Transport); ok && ht.TLSClientConfig != nil {
		rt.tlsCfg = ht.TLSClientConfig.Clone()
	}
	return rt
}

// apReq builds a fresh GSS-API AP-REQ token plus the sub-session key used for
// sealing. A fresh authenticator (new time, new subkey) is required per TCP
// connection to avoid Kerberos replay rejection.
func (p *Provider) apReq() (token []byte, wrapKey types.EncryptionKey, err error) {
	auth, err := types.NewAuthenticator(p.realm, p.cname)
	if err != nil {
		return nil, wrapKey, err
	}
	// Clock-skew compensation: stamp the authenticator with DC-aligned time.
	t := time.Now().UTC().Add(time.Duration(p.cfg.SkewSeconds) * time.Second)
	auth.CTime = t
	auth.Cusec = int(t.Nanosecond() / 1000)
	// Initiator sub-session key: becomes the per-message seal key. Optional,
	// without it, per-message tokens use the ticket session key (matches how
	// go-krb5's own SPNEGO builds the AP-REQ).
	wrapKey = p.sessKey
	if os.Getenv("KRBSEAL_NOSUBKEY") == "" {
		if err = auth.GenerateSeqNumberAndSubKey(p.sessKey.KeyType, keySize(p.sessKey.KeyType)); err != nil {
			return nil, wrapKey, err
		}
		wrapKey = auth.SubKey
	}
	// Flags: INTEG|CONF only, matching go-krb5's own SPNEGO. Adding MUTUAL/SEQUENCE
	// makes Windows reject the AP-REQ with STATUS_INVALID_PARAMETER.
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  gssChecksum(gssInteg | gssConf),
	}
	apreq, err := messages.NewAPReq(p.tkt, p.sessKey, auth)
	if err != nil {
		return nil, wrapKey, err
	}
	token, err = marshalKRB5APReq(apreq)
	if err != nil {
		return nil, wrapKey, err
	}
	return token, wrapKey, nil
}

// gssChecksum builds the 24-byte RFC 4121 §4.1.1 authenticator checksum.
func gssChecksum(flags int) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:4], 16) // Lgth of channel bindings field
	binary.LittleEndian.PutUint32(b[20:24], uint32(flags))
	return b
}

// marshalKRB5APReq wraps an AP-REQ in the GSS-API framing (OID + tok-id 0x0100).
func marshalKRB5APReq(apreq messages.APReq) ([]byte, error) {
	oid, err := kasn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	ab, err := apreq.Marshal()
	if err != nil {
		return nil, err
	}
	inner := append(oid, 0x01, 0x00) // TOK_ID_KRB_AP_REQ
	inner = append(inner, ab...)
	return appTag0(inner), nil
}

// appTag0 wraps bytes in an ASN.1 [APPLICATION 0] tag (0x60 || len || body).
func appTag0(body []byte) []byte {
	return append(derTagLen(0x60, len(body)), body...)
}

func derTagLen(tag byte, n int) []byte {
	return append([]byte{tag}, derLenBytes(n)...)
}

// derLenBytes encodes a DER length (short or long form).
func derLenBytes(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var l []byte
	for n > 0 {
		l = append([]byte{byte(n & 0xff)}, l...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(l))}, l...)
}

func keySize(etype int32) int {
	switch etype {
	case 18: // aes256-cts-hmac-sha1-96
		return 32
	case 17: // aes128-cts-hmac-sha1-96
		return 16
	case 16: // des3-cbc-sha1
		return 24
	case 23: // rc4-hmac
		return 16
	default:
		return 32
	}
}

// ---- GSS wrap tokens: AES (RFC 4121 §4.2.4) and RC4-HMAC (RFC 4757) --------

type sealer struct {
	mu     sync.Mutex
	key    types.EncryptionKey
	sndSeq uint64
	isRC4  bool
	hdrLen int // AES: confounder + HMAC == RRC
}

func newSealer(key types.EncryptionKey) (*sealer, error) {
	s := &sealer{key: key, isRC4: key.KeyType == 23}
	if !s.isRC4 {
		et, err := crypto.GetEtype(key.KeyType)
		if err != nil {
			return nil, err
		}
		s.hdrLen = et.GetConfounderByteSize() + et.GetHMACBitLength()/8
	}
	return s, nil
}

// wrap seals plaintext into (signature, data). The WinRM container is
// packLen(sig) || sig || data; for both mechanisms sig||data is what the
// server reassembles and GSS_Unwraps.
func (s *sealer) wrap(plain []byte) (sig, data []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sig, data, err = s.wrapAs(plain, s.sndSeq, false)
	if err != nil {
		return nil, nil, err
	}
	s.sndSeq++
	return sig, data, nil
}

// wrapAs builds one wrap token at an explicit sequence number and direction.
// Direction is a field of both wire formats (RFC 4121's SentByAcceptor flag,
// RFC 1964's trailing sequence bytes) and unwrap enforces it, so producing an
// acceptor token has to be expressible, that is how the tests build the server
// side. Production only ever seals as the initiator.
func (s *sealer) wrapAs(plain []byte, seq uint64, acceptor bool) (sig, data []byte, err error) {
	if s.isRC4 {
		sig, data = s.wrapRC4(plain, uint32(seq), acceptor)
		return sig, data, nil
	}

	hdr := make([]byte, 16)
	hdr[0], hdr[1] = 0x05, 0x04
	hdr[2] = 0x02 // Flags: Sealed
	if acceptor {
		hdr[2] |= 0x01 // SentByAcceptor
	}
	hdr[3] = 0xFF
	binary.BigEndian.PutUint16(hdr[4:6], 0)
	binary.BigEndian.PutUint16(hdr[6:8], 0) // RRC during encryption
	binary.BigEndian.PutUint64(hdr[8:16], seq)

	usage := uint32(keyusage.GSSAPI_INITIATOR_SEAL)
	if acceptor {
		usage = keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	ed, err := crypto.GetEncryptedData(append(append([]byte{}, plain...), hdr...), s.key, usage, 0)
	if err != nil {
		return nil, nil, err
	}
	rrc := uint16(s.hdrLen)
	binary.BigEndian.PutUint16(hdr[6:8], rrc)
	token := append(hdr, rotateRight(ed.Cipher, int(rrc))...)
	// Split so the last len(plain) bytes are "data" (WinRM convention).
	off := len(token) - len(plain)
	return token[:off], token[off:], nil
}

// errBadSignature is a sealed response that failed integrity verification: the
// bytes on the wire are not the bytes the server sealed. It is never a
// diagnostic to render, the caller must fail the request rather than surface
// unauthenticated content as though the target had said it.
var errBadSignature = errors.New("krbseal: wrap token failed integrity check")

// unwrap reverses wrap for an acceptor (server) token, and verifies it.
//
// Verification is not optional. Sealing gives confidentiality; on plain
// HTTP/5985 an in-path attacker still sees and can rewrite the ciphertext, and
// both mechanisms here are length-preserving, so an unverified unwrap lets that
// attacker choose what the operator reads. RFC 4121 §4.2.6.2 and RFC 4757 §7.3
// both make the receiver's check mandatory. See the sibling reasoning in
// internal/auth/ntlmseal.
//
// The AES path gets its integrity from the etype: crypto.DecryptMessage
// verifies the ciphertext's HMAC and errors if it fails. What that does *not*
// cover is the 16-byte token header, which travels in the clear alongside it,
// so RFC 4121 has the sender append a copy of the header inside the encrypted
// payload, and §4.2.6.2 requires the receiver to compare the two. Without that
// comparison the header's flags and EC/RRC fields are attacker-writable.
func (s *sealer) unwrap(sig, data []byte, plainLen int) ([]byte, error) {
	if s.isRC4 {
		return s.unwrapRC4(sig, data, plainLen)
	}
	token := append(append([]byte{}, sig...), data...)
	if len(token) < 16 {
		return nil, errors.New("wrap token too short")
	}
	hdr := token[:16]
	// These two are early rejects for a better error, not the guarantee. Both
	// are redundant here and the mutation differential says so: deleting either
	// leaves every test passing, because a token that reaches this path and is
	// *not* an acceptor-sealed 0504 token fails either the ACCEPTOR_SEAL usage
	// or the echoed-header comparison below. Keep them for the message; do not
	// mistake them for what makes the AES path safe.
	if hdr[0] != 0x05 || hdr[1] != 0x04 {
		return nil, fmt.Errorf("%w: TOK_ID %x%x, want 0504", errBadSignature, hdr[0], hdr[1])
	}
	if hdr[2]&0x01 == 0 || hdr[2]&0x02 == 0 {
		return nil, fmt.Errorf("%w: header flags %#02x, want SentByAcceptor|Sealed", errBadSignature, hdr[2])
	}
	rrc := int(binary.BigEndian.Uint16(hdr[6:8]))
	cipher := rotateLeft(token[16:], rrc)
	dec, err := crypto.DecryptMessage(cipher, s.key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		// The etype's own HMAC failed: the ciphertext was altered.
		return nil, fmt.Errorf("%w: %v", errBadSignature, err)
	}
	// RFC 4121 §4.2.6.2: the plaintext is payload || the sender's copy of the
	// 16-byte header. Compare it with the header we received in the clear, so
	// the cleartext header is bound to the authenticated ciphertext.
	if len(dec) < plainLen+16 {
		return nil, fmt.Errorf("%w: plaintext %d bytes, need %d + header", errBadSignature, len(dec), plainLen)
	}
	echoed := dec[len(dec)-16:]
	// Bytes 4:8 are EC and RRC, which the sender rewrites *after* encrypting,
	// so the echoed copy holds their pre-rotation values while the cleartext
	// header holds the final ones. Skipping them is not a guess: Forest's
	// echoed header is 050403ff0000000000000000 0000, TOK_ID 0504, flags 0x03
	// (SentByAcceptor|Sealed), EC and RRC both zero, and a live mutant that
	// additionally required echoed[4:8]==hdr[4:8] refused every response.
	//
	// That measurement means the RFC's stricter form (require the echoed pair
	// be *zero*) would also work here. It is deliberately not adopted: it buys
	// no security, because RRC is already load-bearing for decryption (a wrong
	// one mis-rotates and fails the etype HMAC) and EC is unused on this path,
	// while it would reject any conforming sender that differs. Everything that
	// is both attacker-writable and unbound, flags and the 64-bit sequence
	// number, is compared.
	if !hmac.Equal(echoed[:4], hdr[:4]) || !hmac.Equal(echoed[8:], hdr[8:]) {
		return nil, fmt.Errorf("%w: echoed header %x != received %x", errBadSignature, echoed, hdr)
	}
	return dec[:plainLen], nil
}

// wrapRC4 implements RFC 4757 §7.3 GSS_Wrap (arcfour-hmac). WinRM uses SSPI
// in-place (SECBUFFER_DATA) encryption, which for the RC4 stream cipher adds no
// RFC 1964 padding, the data buffer stays exactly len(plaintext).
func (s *sealer) wrapRC4(plain []byte, seq uint32, acceptor bool) (sig, data []byte) {
	d := plain

	first8 := []byte{0x02, 0x01, 0x11, 0x00, 0x10, 0x00, 0xff, 0xff} // TOK_ID|SGN_ALG|SEAL_ALG|Filler
	sndSeq := make([]byte, 8)
	binary.BigEndian.PutUint32(sndSeq[0:4], seq)
	if acceptor {
		// RFC 1964 §1.2.1 direction tag: 0xFF filler from the acceptor, zero
		// from the initiator.
		copy(sndSeq[4:8], []byte{0xff, 0xff, 0xff, 0xff})
	}
	conf := make([]byte, 8)
	rand.Read(conf)
	key := s.key.KeyValue

	ksign := hmacMD5(key, []byte("signaturekey\x00"))
	m := md5.New()
	m.Write(le32(13))
	m.Write(first8)
	m.Write(conf)
	m.Write(d)
	sgn := hmacMD5(ksign, m.Sum(nil))[:8]

	kseq := hmacMD5(hmacMD5(key, le32(0)), sgn)
	sndSeqEnc := rc4crypt(kseq, sndSeq)

	kcrypt := hmacMD5(hmacMD5(xorF0(key), le32(0)), be32(seq))
	c, _ := rc4.NewCipher(kcrypt)
	confEnc := make([]byte, 8)
	c.XORKeyStream(confEnc, conf)
	cipherText := make([]byte, len(d))
	c.XORKeyStream(cipherText, d)

	token := concat(first8, sndSeqEnc, sgn, confEnc) // 32-byte RFC 1964 wrap token

	// RFC 1964 wrap tokens carry the GSS-API {0x60, len, OID, ...} framing
	// (unlike RFC 4121/AES which is raw). In WinRM's IOV layout the framed
	// length counts the separate data buffer too.
	oid := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	bodyLen := len(oid) + len(token) + len(cipherText)
	sig = append([]byte{0x60}, derLenBytes(bodyLen)...)
	sig = append(sig, oid...)
	sig = append(sig, token...)
	return sig, cipherText
}

// rc4TokenOID locates the 32-byte RFC 1964 wrap token after the OID in a
// GSS-framed signature.
var rc4OID = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

// unwrapRC4 reverses wrapRC4 and verifies the token's SGN_CKSUM.
//
// The checksum is what makes this path safe, and its absence was a real hole:
// RC4 is a length-preserving stream cipher, so XORing a chosen delta into the
// ciphertext XORs that same delta into the plaintext. SGN_CKSUM is the only
// thing covering the payload, decrypting without checking it means an in-path
// attacker on 5985 picks, byte for byte, what the operator sees the target say.
//
// Order is forced by the construction: SGN_CKSUM is itself the key input that
// decrypts SND_SEQ, which derives the payload key. So the received checksum has
// to be used to decrypt, and only then can it be recomputed over the recovered
// confounder and plaintext and compared. Tampering with the checksum therefore
// garbles the plaintext rather than being caught directly, that is still a
// detection, because the recomputed value will not match, but the compare is
// what turns it into one.
func (s *sealer) unwrapRC4(sig, data []byte, plainLen int) ([]byte, error) {
	i := bytes.Index(sig, rc4OID)
	if i < 0 || len(sig) < i+len(rc4OID)+32 {
		return nil, errors.New("rc4 wrap token not found")
	}
	token := sig[i+len(rc4OID) : i+len(rc4OID)+32]
	first8, sndSeqEnc, sgn, confEnc := token[0:8], token[8:16], token[16:24], token[24:32]
	key := s.key.KeyValue

	kseq := hmacMD5(hmacMD5(key, le32(0)), sgn)
	sndSeq := rc4crypt(kseq, sndSeqEnc)
	seq := binary.BigEndian.Uint32(sndSeq[0:4])

	// RFC 1964 §1.2.1: the sequence number's trailing 4 bytes are the direction
	// tag, 0xFF from the acceptor, zero from the initiator.
	//
	// Unlike the AES path's equivalent flag, this check is load-bearing, and
	// the asymmetry is worth understanding before anyone trims it. AES derives
	// separate keys per direction (GSSAPI_INITIATOR_SEAL vs ACCEPTOR_SEAL), so
	// a reflected client token simply fails to decrypt. RFC 4757 has no such
	// separation, both directions use the same key and the same derivation, so
	// the client's own sealed request replayed back at it would recompute a
	// perfectly valid SGN_CKSUM. This tag is the only thing that says otherwise.
	if !hmac.Equal(sndSeq[4:8], []byte{0xff, 0xff, 0xff, 0xff}) {
		return nil, fmt.Errorf("%w: direction tag %x, want ffffffff (sent by acceptor)", errBadSignature, sndSeq[4:8])
	}

	kcrypt := hmacMD5(hmacMD5(xorF0(key), le32(0)), be32(seq))
	c, _ := rc4.NewCipher(kcrypt)
	conf := make([]byte, 8)
	c.XORKeyStream(conf, confEnc) // decrypt the confounder; it feeds the checksum
	dec := make([]byte, len(data))
	c.XORKeyStream(dec, data)
	if plainLen > len(dec) {
		return nil, errors.New("rc4 unwrap: short plaintext")
	}
	plain := dec[:plainLen]

	// RFC 4757 §7.3: SGN_CKSUM = HMAC-MD5(Ksign, MD5(le32(13) || first8 ||
	// confounder || plaintext))[:8], over the *received* first8 so the token's
	// algorithm identifiers are bound too.
	ksign := hmacMD5(key, []byte("signaturekey\x00"))
	m := md5.New()
	m.Write(le32(13))
	m.Write(first8)
	m.Write(conf)
	m.Write(plain)
	if !hmac.Equal(sgn, hmacMD5(ksign, m.Sum(nil))[:8]) {
		return nil, errBadSignature
	}
	return plain, nil
}

func rotateRight(b []byte, n int) []byte {
	if len(b) == 0 {
		return b
	}
	n %= len(b)
	out := make([]byte, len(b))
	copy(out, b[len(b)-n:])
	copy(out[n:], b[:len(b)-n])
	return out
}

func rotateLeft(b []byte, n int) []byte {
	if len(b) == 0 {
		return b
	}
	n %= len(b)
	out := make([]byte, len(b))
	copy(out, b[n:])
	copy(out[len(b)-n:], b[:n])
	return out
}

// ---- WinRM multipart container --------------------------------------------

func (s *sealer) wrapHTTP(plain []byte) (string, []byte, error) {
	sig, data, err := s.wrap(plain)
	if err != nil {
		return "", nil, err
	}
	var b bytes.Buffer
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("\tContent-Type: " + protocol + "\r\n")
	fmt.Fprintf(&b, "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n", len(plain))
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("\tContent-Type: application/octet-stream\r\n")
	lb := make([]byte, 4)
	binary.LittleEndian.PutUint32(lb, uint32(len(sig)))
	b.Write(lb)
	b.Write(sig)
	b.Write(data)
	b.WriteString("--" + boundary + "--\r\n")
	return `multipart/encrypted;protocol="` + protocol + `";boundary="` + boundary + `"`, b.Bytes(), nil
}

func (s *sealer) unwrapHTTP(body []byte) ([]byte, error) {
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
	dataLen := plainLen // in-place stream/CTS encryption: ciphertext len == plaintext len
	if len(bin) < 4+sigLen+dataLen {
		return nil, fmt.Errorf("short body: have %d need %d", len(bin), 4+sigLen+dataLen)
	}
	return s.unwrap(bin[4:4+sigLen], bin[4+sigLen:4+sigLen+dataLen], plainLen)
}

func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}
func rc4crypt(key, data []byte) []byte {
	c, _ := rc4.NewCipher(key)
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}
func xorF0(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[i] = b[i] ^ 0xF0
	}
	return o
}
func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
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

// ---- single-connection HTTP/1.1 transport ---------------------------------

type connRoundTripper struct {
	p           *Provider
	insecure    bool
	tlsCfg      *tls.Config
	tlsExplicit bool // tlsCfg fully specifies verification; do not override it

	mu           sync.Mutex
	conn         net.Conn
	br           *bufio.Reader
	sealer       *sealer
	pendingAPReq string // Authorization header for the first request of a connection
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

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if t.conn == nil {
			if err := t.dialAndAuth(req); err != nil {
				return nil, err
			}
		}
		resp, err := t.send(req, plain)
		if err != nil {
			t.closeConn()
			lastErr = err
			if debugOn {
				fmt.Fprintf(os.Stderr, "[krbseal] request failed (%v) attempt=%d\n", err, attempt)
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
		t.sealer = nil
	}
}

func (t *connRoundTripper) dialAndAuth(req *http.Request) error {
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

	token, wrapKey, err := t.p.apReq()
	if err != nil {
		t.closeConn()
		return fmt.Errorf("build AP-REQ: %w", err)
	}
	t.sealer, err = newSealer(wrapKey)
	if err != nil {
		t.closeConn()
		return err
	}
	scheme := os.Getenv("KRBSEAL_SCHEME")
	if scheme == "" {
		scheme = "Kerberos"
	}
	t.pendingAPReq = scheme + " " + base64.StdEncoding.EncodeToString(token)
	if debugOn {
		n := len(token)
		if n > 24 {
			n = 24
		}
		fmt.Fprintf(os.Stderr, "[krbseal] dialed %s, scheme=%s AP-REQ %d bytes, head=%x\n",
			host, scheme, len(token), token[:n])
	}
	return nil
}

func (t *connRoundTripper) send(req *http.Request, plain []byte) (*http.Response, error) {
	var body []byte
	var ct string
	if t.p.cfg.SealEnabled {
		var err error
		ct, body, err = t.sealer.wrapHTTP(plain)
		if err != nil {
			return nil, err
		}
	} else {
		body, ct = plain, "application/soap+xml;charset=UTF-8"
	}

	auth := ""
	if t.pendingAPReq != "" {
		auth = t.pendingAPReq
		t.pendingAPReq = ""
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
	if debugOn && resp.StatusCode != http.StatusOK {
		snippet := string(enc)
		if len(snippet) > 400 {
			snippet = snippet[:400]
		}
		fmt.Fprintf(os.Stderr, "[krbseal] %d body: %s\n", resp.StatusCode, snippet)
	}
	// Decrypt sealed bodies regardless of status, so a WSMan SOAP fault (HTTP
	// 500, still sealed) surfaces as readable XML instead of ciphertext. Unlike
	// NTLM's streaming RC4, Kerberos wrap tokens are self-describing (each
	// carries its own sequence), so skipping one never desyncs, this is purely
	// for diagnosis. A non-sealed body (sealing off, or a bare error) passes
	// through untouched.
	if len(enc) == 0 || !t.p.cfg.SealEnabled || !isSealedResponse(resp) {
		resp.Body = io.NopCloser(bytes.NewReader(enc))
		return resp, nil
	}
	dec, err := t.sealer.unwrapHTTP(enc)
	if err != nil {
		if debugOn {
			fmt.Fprintf(os.Stderr, "[krbseal] response unwrap failed: %v\n", err)
		}
		// A failed *integrity check* is an attack or a corrupted path, never a
		// diagnostic: passing the body on would hand unauthenticated bytes to
		// the SOAP parser, which is the whole thing the check exists to stop.
		// Fail the request and drop the connection, the next one re-handshakes
		// with fresh keys.
		if errors.Is(err, errBadSignature) {
			t.closeConn()
			return nil, fmt.Errorf("krbseal: refusing response from %s: %w", req.URL.Host, err)
		}
		// Anything else (a body that is not the container we expect) stays
		// best-effort, as before, so a malformed error page is still readable.
		resp.Body = io.NopCloser(bytes.NewReader(enc))
		return resp, nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(dec))
	resp.ContentLength = int64(len(dec))
	resp.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	resp.Header.Set("Content-Length", strconv.Itoa(len(dec)))
	return resp, nil
}

// isSealedResponse reports whether the server sealed this response (a WSMan
// multipart/encrypted body), so only such a body is run through unwrapHTTP.
func isSealedResponse(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "multipart/encrypted")
}

// deadCommsBackstop bounds how long a single request may sit on the connection
// when the caller set no deadline of its own. Identical rationale to the
// ntlmseal copy: a command's context is cancel-only, so without this a silently
// blackholed connection (dropped VPN, NAT timeout) leaves the response read
// blocked in netpoll forever, and Ctrl-C cannot rescue it because StopPipelines
// wants the same connection mutex. It must stay well above the longest
// legitimate server hold (PT60S) or it would recreate the connection churn that
// fix (A) removed.
const deadCommsBackstop = 120 * time.Second

// writeDeadline picks the socket deadline for one request: the caller's, when it
// set one, and otherwise the backstop above. Never zero -- that hangs forever.
func writeDeadline(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Now().Add(deadCommsBackstop)
}

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
	if debugOn {
		fmt.Fprintf(os.Stderr, "[krbseal] -> status=%d\n", resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized {
			fmt.Fprintf(os.Stderr, "[krbseal]    WWW-Authenticate=%q\n", resp.Header.Values("Www-Authenticate"))
		}
	}
	return resp, nil
}
