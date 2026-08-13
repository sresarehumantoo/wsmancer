package session

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
)

// buildServerTLSConfig turns the CLI's TLS options into a *tls.Config for the
// HTTPS path. The default is to verify the target certificate against the
// system roots, like any TLS client; --ca-cert adds a private anchor,
// --accept-fingerprint pins one exact cert, and --insecure turns verification
// off. It is built only when -S/--ssl is set, plain WinRM (5985) never does a
// TLS handshake, so there is nothing to verify and no warning to print.
//
// Verification is done in a VerifyConnection callback rather than by the stock
// chain check. Two reasons: it keeps pinning and CA/system verification in one
// place, and, unlike the built-in path, which aborts before any of our code
// runs, it always has the presented certificate in hand, so a failure can tell
// the operator the server's fingerprint and how to proceed instead of a bare
// "unknown authority". SNI still goes out (ServerName is set); InsecureSkipVerify
// only turns off the *built-in* check so our callback becomes authoritative.
func buildServerTLSConfig(o *cli.Options) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         o.IP, // SNI, and the name the certificate is checked against
		InsecureSkipVerify: true, // real checking happens in VerifyConnection below
	}

	// -c/-k: present a client certificate in the handshake (mutual TLS). This is
	// alongside NTLM/Kerberos, matching evil-winrm, the cert is not the
	// credential, it just satisfies a listener that requires client certs.
	if o.PubKey != "" && o.PrivKey != "" {
		cert, err := tls.LoadX509KeyPair(o.PubKey, o.PrivKey)
		if err != nil {
			return nil, fmt.Errorf("client certificate (-c/--pub-key, -k/--priv-key): %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	switch {
	case o.Insecure:
		// Accept any certificate. The caller already printed the warning; leave
		// VerifyConnection nil so nothing rejects the handshake.

	case o.AcceptFingerprint != "":
		want, err := cli.NormalizeFingerprint(o.AcceptFingerprint)
		if err != nil {
			return nil, fmt.Errorf("--accept-fingerprint: %w", err)
		}
		// Pin: the fingerprint is the sole criterion. Secure (a MITM's substitute
		// cert has a different hash) and, unlike trust-on-first-use, safe on the
		// first connection because the operator supplies the known-good hash out
		// of band.
		cfg.VerifyConnection = pinVerifier(want)

	case o.CACert != "":
		pem, err := os.ReadFile(o.CACert)
		if err != nil {
			return nil, fmt.Errorf("--ca-cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca-cert: no PEM certificates found in %s", o.CACert)
		}
		cfg.VerifyConnection = chainVerifier(pool, o.IP)

	default:
		// Secure by default: verify against the system roots. A self-signed target
		// cert fails here on purpose; the error names the fingerprint and the
		// flags to proceed.
		cfg.VerifyConnection = chainVerifier(nil, o.IP)
	}
	return cfg, nil
}

// pinVerifier accepts the connection only when the leaf certificate's SHA-256
// equals want.
func pinVerifier(want []byte) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("tls: server presented no certificate to pin")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if !bytes.Equal(got[:], want) {
			return fmt.Errorf("tls: certificate fingerprint mismatch\n  pinned: %s\n  server: %s",
				cli.FormatFingerprint(want), cli.FormatFingerprint(got[:]))
		}
		return nil
	}
}

// chainVerifier verifies the presented chain against roots (nil => the system
// store) and the expected server name. On failure it enriches the error with the
// server certificate's SHA-256 and the exact flags to proceed, so an operator
// who meets a self-signed target can pin or trust it without reaching for
// openssl. (The shown fingerprint arrived over the same connection as the cert,
// so it proves continuity, not first-contact identity, verify it out of band if
// MITM is in scope. See README.)
func chainVerifier(roots *x509.CertPool, serverName string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("tls: server presented no certificate")
		}
		leaf := cs.PeerCertificates[0]
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots, // nil => system roots
			Intermediates: inter,
			DNSName:       serverName,
		}); err != nil {
			fp := sha256.Sum256(leaf.Raw)
			hex := cli.FormatFingerprint(fp[:])
			return fmt.Errorf("%w\n  server cert SHA-256: %s (%s)\n"+
				"  to proceed: --accept-fingerprint %s to pin it, "+
				"--ca-cert <pem> to trust its CA, or --insecure to skip verification",
				err, hex, describeCert(leaf), hex)
		}
		return nil
	}
}

// describeCert gives a short hint about who issued a certificate, for the
// verification-failure message.
func describeCert(c *x509.Certificate) string {
	cn := c.Subject.CommonName
	if cn == "" {
		cn = "no CN"
	}
	if bytes.Equal(c.RawSubject, c.RawIssuer) {
		return fmt.Sprintf("CN=%s, self-signed", cn)
	}
	issuer := c.Issuer.CommonName
	if issuer == "" {
		issuer = "unknown issuer"
	}
	return fmt.Sprintf("CN=%s, issued by %s", cn, issuer)
}
