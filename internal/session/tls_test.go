package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
)

// buildServerTLSConfig produces a *tls.Config; the only way to know it is right
// is to complete a real handshake with it. Each case dials an httptest TLS
// server (self-signed, IP SAN 127.0.0.1) and asserts whether the handshake is
// accepted, exercising the actual crypto/tls verification path.
func TestBuildServerTLSConfig(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	leaf := srv.Certificate()
	fp := sha256.Sum256(leaf.Raw)
	goodFP := cli.FormatFingerprint(fp[:])
	wrongFP := cli.FormatFingerprint(make([]byte, 32)) // all zeroes

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		opts       *cli.Options
		wantAccept bool
	}{
		{"default verify rejects self-signed", &cli.Options{IP: "127.0.0.1", SSL: true}, false},
		{"insecure accepts anything", &cli.Options{IP: "127.0.0.1", SSL: true, Insecure: true}, true},
		{"correct fingerprint accepts", &cli.Options{IP: "127.0.0.1", SSL: true, AcceptFingerprint: goodFP}, true},
		{"wrong fingerprint rejects", &cli.Options{IP: "127.0.0.1", SSL: true, AcceptFingerprint: wrongFP}, false},
		{"ca-cert trusts the pinned CA", &cli.Options{IP: "127.0.0.1", SSL: true, CACert: caFile}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := buildServerTLSConfig(c.opts)
			if err != nil {
				t.Fatalf("buildServerTLSConfig: %v", err)
			}
			conn, err := tls.Dial("tcp", addr, cfg)
			if err == nil {
				conn.Close()
			}
			if accepted := err == nil; accepted != c.wantAccept {
				t.Errorf("handshake accepted=%v, want %v (err=%v)", accepted, c.wantAccept, err)
			}
		})
	}
}

// A bad fingerprint string is a config error, surfaced before any dial.
func TestBuildServerTLSConfigBadFingerprint(t *testing.T) {
	_, err := buildServerTLSConfig(&cli.Options{IP: "127.0.0.1", SSL: true, AcceptFingerprint: "nothex"})
	if err == nil {
		t.Fatal("expected an error for a non-hex fingerprint")
	}
}

// -c/-k must load into the handshake's client certificates, and a bad pair must
// be a clear config error rather than a silent miss.
func TestClientCertificate(t *testing.T) {
	dir := t.TempDir()
	crt, key := writeKeyPair(t, dir)

	cfg, err := buildServerTLSConfig(&cli.Options{IP: "127.0.0.1", SSL: true, PubKey: crt, PrivKey: key})
	if err != nil {
		t.Fatalf("loading a valid keypair: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 client certificate, got %d", len(cfg.Certificates))
	}

	// A cert file where the key should be is a mismatch, and must error.
	if _, err := buildServerTLSConfig(&cli.Options{IP: "127.0.0.1", SSL: true, PubKey: crt, PrivKey: crt}); err == nil {
		t.Error("expected an error when the key file is not a private key")
	}
}

// writeKeyPair writes a throwaway client cert + PKCS#8 key to dir and returns
// their paths.
func writeKeyPair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// When default verification fails, the error must hand the operator the server's
// fingerprint and the flags to proceed, the whole point of routing through
// VerifyConnection instead of the stock chain check.
func TestVerifyFailureNamesFingerprintAndFix(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	fp := sha256.Sum256(srv.Certificate().Raw)
	wantHex := cli.FormatFingerprint(fp[:])

	cfg, err := buildServerTLSConfig(&cli.Options{IP: "127.0.0.1", SSL: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tls.Dial("tcp", addr, cfg)
	if err == nil {
		t.Fatal("expected the self-signed handshake to be rejected")
	}
	msg := err.Error()
	for _, want := range []string{wantHex, "--accept-fingerprint", "--ca-cert", "--insecure", "self-signed"} {
		if !strings.Contains(msg, want) {
			t.Errorf("verification error missing %q\n  got: %s", want, msg)
		}
	}
}
