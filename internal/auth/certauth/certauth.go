// Package certauth implements WinRM client-certificate authentication: the
// certificate presented in the TLS handshake *is* the credential, and there is
// no user, password, hash or ticket at all.
//
// It is the odd one out among this tool's auth providers. ntlmseal and krbseal
// exist because a stock listener demands a sealed message body; here the target
// demands the opposite. The mode only works over HTTPS, TLS is what satisfies
// AllowUnencrypted=false, and a sealed body would have nothing to seal it with,
// no handshake happens, so no session key is ever derived. So this provider
// carries no crypto of its own: a TLS config with the client certificate, one
// fixed header, and the transport hygiene the other two learned the hard way.
//
// The wire protocol is a single header on every request (MS-WSMV; the same one
// Ruby evil-winrm sends via the winrm gem's ClientCertAuthSSL transport):
//
//	Authorization: http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual
//
// The server maps the certificate to an account it was configured with in
// advance (WSMan:\localhost\ClientCertificate), so who you end up as is the
// target's decision, not the client's.
package certauth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/sresarehumantoo/wsmancer/internal/proxydial"
)

var debugOn = os.Getenv("CERTAUTH_DEBUG") != ""

const (
	// certAuthHeader is the fixed Authorization value for HTTPS mutual
	// (certificate) authentication. It is a URI, not a scheme + token: there is
	// no token, because the credential was presented in the TLS handshake.
	certAuthHeader = "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"

	// defaultUserAgent matches the genuine Windows WinRM client; -a overrides it.
	defaultUserAgent = "Microsoft WinRM Client"

	// deadCommsBackstop bounds how long one request may wait for response
	// headers. Same reasoning, and the same relationship to the server's own
	// holds, as ntlmseal's constant of the same name: a command's context is
	// cancel-only, so without a bound a *silently* blackholed connection (a
	// dropped VPN, a NAT timeout) leaves the read blocked forever with no RST to
	// end it. It must stay well above the longest legitimate server hold (PT60S
	// plus the Receive poll) or it recreates the connection churn
	// an earlier fix removed.
	deadCommsBackstop = 120 * time.Second
)

// Config configures the certificate provider.
type Config struct {
	// TLSConfig must already carry the client certificate (built by
	// internal/session/tls.go, which also owns how the *server* is verified).
	// Unlike Ruby evil-winrm, which hardcodes no_ssl_peer_verification on this
	// path, so the client proves itself to a server it never authenticates,
	// server verification here is whatever the operator asked for, verified by
	// default.
	TLSConfig *tls.Config
	UserAgent string

	// Dialer, when non-nil, dials the target's TCP connection, that is where
	// --proxy lands. A nil *proxydial.Dialer dials directly. Unlike the sealing
	// providers this is handed to an http.Transport, which layers TLS over
	// whatever DialContext returns, so the client certificate and the
	// renegotiation below behave identically proxied or not.
	Dialer *proxydial.Dialer
}

// Provider is a go-psrp auth.Authenticator backed by a client certificate.
type Provider struct{ cfg Config }

// New validates that a client certificate is actually present. Without one the
// handshake would offer nothing, and the target answers that with a 401 whose
// text says only that authentication failed, true, unhelpful, and a long way
// from "you passed no certificate".
func New(cfg Config) (*Provider, error) {
	if cfg.TLSConfig == nil || len(cfg.TLSConfig.Certificates) == 0 {
		return nil, errors.New("certificate authentication needs a client certificate (-c/--pub-key and -k/--priv-key)")
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}
	return &Provider{cfg: cfg}, nil
}

// Name implements auth.Authenticator.
func (p *Provider) Name() string { return "Certificate" }

// Transport implements auth.Authenticator.
//
// Unlike the sealing providers this does not write raw HTTP onto a socket it
// owns, there is no handshake to sequence and no body to seal, so net/http can
// do the work.
//
// It still pins itself to one connection, but *not* for the reason the sealing
// providers do. Theirs own a socket because NTLM and Kerberos authenticate a
// connection: a second one would need its own handshake, and the WSMan terminate
// that Ctrl-C sends has to reach the shell over a connection the server accepts
// as the same client. A certificate is different, every connection presents the
// same credential in its own handshake, so any of them is the same client. That
// was measured, not assumed: a build with pooling left on (MaxConnsPerHost 0)
// passes the whole of scripts/certauth-test.py, Ctrl-C included.
//
// So one connection is a deliberate conservative choice rather than a
// requirement: it matches the other two providers' behavior, keeps request
// ordering predictable, and avoids paying for a fresh TLS handshake *and*
// renegotiation on every extra connection. If Ctrl-C latency here ever needs
// improving, allowing a second connection is a legitimate thing to try, the
// terminate would no longer wait out the in-flight Receive poll.
func (p *Provider) Transport(base http.RoundTripper) http.RoundTripper {
	tr := &http.Transport{
		TLSClientConfig: renegotiable(p.cfg.TLSConfig),
		DialContext:     p.cfg.Dialer.DialContext,
		// One connection, so a shell and the signal that stops it share it.
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		DisableKeepAlives:   false,
		// The blackhole backstop; see deadCommsBackstop.
		ResponseHeaderTimeout: deadCommsBackstop,
		IdleConnTimeout:       90 * time.Second,
	}
	return &roundTripper{next: tr, cfg: p.cfg}
}

// renegotiable returns cfg with the two settings Schannel's certificate request
// requires. Both were found the hard way, against a real listener.
//
// Windows does not ask for the client certificate in the initial handshake. It
// completes the handshake anonymously, sees a request for an endpoint that
// requires certificate auth, and only then **renegotiates** to demand one. Go
// refuses renegotiation by default (RenegotiateNever) and the connection dies
// with "local error: tls: no renegotiation", an error that names TLS and says
// nothing about client certificates, which is why it is worth a comment.
//
// Renegotiation exists only in TLS 1.2 and below; TLS 1.3 replaced it with
// post-handshake authentication, which Go's client does not implement. So this
// path is pinned to a 1.2 maximum: not a preference, the only version in which
// the mechanism exists at all for a Go client. It applies solely to certificate
// auth, every other mode keeps whatever the two ends negotiate, and TLS 1.2
// with a modern cipher suite is what a Windows listener offers in practice
// anyway (Server 2016, the reference target here, does not speak 1.3).
func renegotiable(cfg *tls.Config) *tls.Config {
	out := cfg.Clone()
	out.Renegotiation = tls.RenegotiateOnceAsClient
	out.MaxVersion = tls.VersionTLS12
	return out
}

// roundTripper stamps every request with the certificate-auth header and the
// User-Agent. Both belong here for the same reason they live in the other
// providers: this layer owns the request as it goes out.
type roundTripper struct {
	next *http.Transport
	cfg  Config
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", certAuthHeader)
	req.Header.Set("User-Agent", rt.cfg.UserAgent)

	resp, err := rt.next.RoundTrip(req)
	if debugOn && resp != nil {
		fmt.Fprintf(os.Stderr, "[certauth] %s -> status=%d\n", req.URL.Path, resp.StatusCode)
	}
	return resp, err
}
