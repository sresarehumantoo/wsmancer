package certauth

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dummyCert is enough for New, which checks only that a certificate is present
// -- it never parses one. The real certificate is exercised end-to-end by
// scripts/certauth-test.py, which is the only place a target can map it.
func dummyCert() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{{}}}
}

func TestNewRequiresAClientCertificate(t *testing.T) {
	// Without a certificate the handshake offers nothing and the target answers
	// with a 401 whose text says only "authentication failed" -- true, and a long
	// way from "you passed no certificate". So the error has to name the flags.
	cases := map[string]*tls.Config{
		"nil TLS config":     nil,
		"no certificates":    {},
		"empty certificates": {Certificates: []tls.Certificate{}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := New(Config{TLSConfig: cfg})
			if err == nil {
				t.Fatalf("New() accepted a config with %s; a 401 at runtime is the alternative", name)
			}
			if p != nil {
				t.Errorf("New() returned a provider %v alongside an error", p)
			}
			for _, flag := range []string{"-c", "-k"} {
				if !strings.Contains(err.Error(), flag) {
					t.Errorf("error %q does not name %s; the operator is left guessing", err, flag)
				}
			}
		})
	}
}

func TestNewDefaultsTheUserAgent(t *testing.T) {
	// Spelled out rather than compared to defaultUserAgent: checking the constant
	// against itself would pass no matter what it said, and the point of this
	// value is that it is not an IOC (the old psrp-spike default was).
	p, err := New(Config{TLSConfig: dummyCert()})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	if got, want := p.cfg.UserAgent, "Microsoft WinRM Client"; got != want {
		t.Errorf("default User-Agent = %q, want %q", got, want)
	}
}

func TestNewKeepsAnExplicitUserAgent(t *testing.T) {
	p, err := New(Config{TLSConfig: dummyCert(), UserAgent: "curl/8.7.1"})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	if got := p.cfg.UserAgent; got != "curl/8.7.1" {
		t.Errorf("User-Agent = %q, want the caller's -a value", got)
	}
}

func TestNameIsCertificate(t *testing.T) {
	p, err := New(Config{TLSConfig: dummyCert()})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	if got := p.Name(); got != "Certificate" {
		t.Errorf("Name() = %q, want %q", got, "Certificate")
	}
}

// Windows completes the first handshake anonymously and only then renegotiates
// to demand the client certificate. Go refuses renegotiation by default, and the
// connection dies with "local error: tls: no renegotiation" -- an error naming
// TLS and not certificates. Renegotiation exists only in TLS 1.2 and below, so
// the version cap is the mechanism's precondition, not a preference.
func TestRenegotiableEnablesTheSchannelHandshake(t *testing.T) {
	out := renegotiable(dummyCert())
	if out.Renegotiation != tls.RenegotiateOnceAsClient {
		t.Errorf("Renegotiation = %v, want RenegotiateOnceAsClient: Schannel's "+
			"certificate request arrives in a renegotiation Go would refuse",
			out.Renegotiation)
	}
	if out.MaxVersion != tls.VersionTLS12 {
		t.Errorf("MaxVersion = %#04x, want TLS 1.2 (%#04x): renegotiation does not "+
			"exist in 1.3, and Go's client has no post-handshake auth",
			out.MaxVersion, tls.VersionTLS12)
	}
}

// tls.go hands the provider the operator's config and it is authoritative
// (tlsExplicit). Mutating it in place would reach back into the caller's copy,
// so renegotiable clones -- and the clone is what makes that safe.
func TestRenegotiableDoesNotMutateTheCallersConfig(t *testing.T) {
	in := dummyCert()
	in.Renegotiation = tls.RenegotiateNever
	in.MaxVersion = tls.VersionTLS13

	renegotiable(in)

	if in.Renegotiation != tls.RenegotiateNever {
		t.Errorf("caller's Renegotiation changed to %v: renegotiable mutated its input", in.Renegotiation)
	}
	if in.MaxVersion != tls.VersionTLS13 {
		t.Errorf("caller's MaxVersion changed to %#04x: renegotiable mutated its input", in.MaxVersion)
	}
}

// The dangerous failure here is silent: drop these on the way through and the
// client still authenticates itself perfectly to a server it no longer verifies
// -- which is exactly the bug Ruby evil-winrm has on this path (it hardcodes
// no_ssl_peer_verification). Nothing at runtime would look wrong.
func TestRenegotiablePreservesServerVerification(t *testing.T) {
	pool := x509.NewCertPool()
	verifyCalled := false
	in := &tls.Config{
		Certificates:       []tls.Certificate{{}},
		RootCAs:            pool,
		ServerName:         "dc01.corp.local",
		InsecureSkipVerify: true, // how pinVerifier/chainVerifier run at all
		VerifyConnection: func(tls.ConnectionState) error {
			verifyCalled = true
			return nil
		},
	}

	out := renegotiable(in)

	if out.RootCAs != pool {
		t.Error("RootCAs dropped: --ca-cert's private anchor would be ignored")
	}
	if out.ServerName != "dc01.corp.local" {
		t.Errorf("ServerName = %q, want it carried through: SNI still has to go out", out.ServerName)
	}
	if !out.InsecureSkipVerify {
		t.Error("InsecureSkipVerify cleared: the built-in check would abort before VerifyConnection could name the peer")
	}
	if out.VerifyConnection == nil {
		t.Fatal("VerifyConnection dropped: --accept-fingerprint and --ca-cert would silently stop verifying")
	}
	if err := out.VerifyConnection(tls.ConnectionState{}); err != nil || !verifyCalled {
		t.Error("VerifyConnection is not the operator's callback")
	}
	if len(out.Certificates) != 1 {
		t.Error("client certificate dropped: the credential itself would be gone")
	}
}

// The header is the whole wire protocol for this mode. The URI is written out in
// full here on purpose: asserting against certAuthHeader would compare the
// constant to itself and pass a typo that a live target would reject as a 401.
func TestRoundTripStampsTheCertAuthHeader(t *testing.T) {
	const wantAuth = "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"

	var gotAuth, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	p, err := New(Config{TLSConfig: dummyCert(), UserAgent: "Microsoft WinRM Client"})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/wsman", nil)
	if err != nil {
		t.Fatalf("NewRequest() = %v", err)
	}
	resp, err := p.Transport(nil).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() = %v", err)
	}
	defer resp.Body.Close()

	if gotAuth != wantAuth {
		t.Errorf("Authorization = %q, want %q", gotAuth, wantAuth)
	}
	if gotUA != "Microsoft WinRM Client" {
		t.Errorf("User-Agent = %q, want the configured value", gotUA)
	}
}

// -a has to reach the wire, not just the struct.
func TestRoundTripSendsTheConfiguredUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	p, err := New(Config{TLSConfig: dummyCert(), UserAgent: "Mozilla/5.0"})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/wsman", nil)
	resp, err := p.Transport(nil).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() = %v", err)
	}
	defer resp.Body.Close()

	if gotUA != "Mozilla/5.0" {
		t.Errorf("User-Agent = %q, want %q", gotUA, "Mozilla/5.0")
	}
}

// Same invariant the sealing providers pin, for the same reason: a command's
// context is cancel-only, so a silently blackholed connection (dropped VPN, NAT
// timeout) has nothing but this bound to end the read. The relationship is what
// matters, not the literal 120s.
func TestResponseHeaderTimeoutExceedsServerHolds(t *testing.T) {
	// WSMan advertises PT60S on Create/Command/Send/Signal/Delete.
	const longestAdvertisedHold = 60 * time.Second
	if deadCommsBackstop <= longestAdvertisedHold {
		t.Fatalf("deadCommsBackstop %v <= longest advertised hold %v: healthy "+
			"long-polls would be torn down as dead connections",
			deadCommsBackstop, longestAdvertisedHold)
	}
	if deadCommsBackstop == 0 {
		t.Fatal("deadCommsBackstop is zero: a blackholed connection would block the read forever")
	}
}

// The backstop and the one-connection pin are only real if Transport actually
// installs them -- the constant being right buys nothing on its own.
func TestTransportInstallsTheBackstopAndPinsOneConnection(t *testing.T) {
	p, err := New(Config{TLSConfig: dummyCert()})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	rt, ok := p.Transport(nil).(*roundTripper)
	if !ok {
		t.Fatalf("Transport() returned %T, want *roundTripper", p.Transport(nil))
	}
	if got := rt.next.ResponseHeaderTimeout; got != deadCommsBackstop {
		t.Errorf("ResponseHeaderTimeout = %v, want the backstop %v", got, deadCommsBackstop)
	}
	if got := rt.next.MaxConnsPerHost; got != 1 {
		t.Errorf("MaxConnsPerHost = %d, want 1 so a shell and the Ctrl-C that stops it share a connection", got)
	}
	if rt.next.TLSClientConfig.Renegotiation != tls.RenegotiateOnceAsClient {
		t.Error("Transport did not install the renegotiable config: Schannel's certificate request would be refused")
	}
}
