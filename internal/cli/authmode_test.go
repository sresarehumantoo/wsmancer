package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// certPair writes two files so the -c/-k existence checks pass; their contents
// never matter to option parsing.
func certPair(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	pub, priv := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	for _, p := range []string{pub, priv} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return pub, priv
}

func parse(t *testing.T, args ...string) (*Options, error) {
	t.Helper()
	return Parse(args, os.Stderr)
}

// A certificate on its own is the credential. This is the mode Ruby evil-winrm
// means by -c/-k, and the reason -u is not required with it: the target maps the
// certificate to an account, so the client never names one.
func TestCertificateAloneSelectsCertificateAuth(t *testing.T) {
	pub, priv := certPair(t)
	o, err := parse(t, "-i", "host", "-S", "-c", pub, "-k", priv)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if o.AuthMode() != AuthCertificate {
		t.Errorf("AuthMode = %v, want AuthCertificate", o.AuthMode())
	}
	// The password prompt must not fire here: there is no password to ask for,
	// and asking would stall a scripted cert login at a prompt.
	if o.NeedsPassword() {
		t.Error("a certificate login should never be prompted for a password")
	}
}

// The pre-existing behavior, a client certificate presented *alongside* NTLM
// or Kerberos, is a different and stronger thing than upstream's cert auth, and
// carrying credentials must keep selecting it.
func TestCertificateWithCredentialsKeepsTheCredentialMode(t *testing.T) {
	pub, priv := certPair(t)
	cases := map[string]struct {
		args []string
		want AuthMode
	}{
		"with a password": {[]string{"-u", "u", "-p", "pw"}, AuthPassword},
		"with a hash":     {[]string{"-u", "u", "-H", "aabb"}, AuthHash},
		"with a ticket":   {[]string{"-K", "/dev/null"}, AuthKerberos},
	}
	for name, tc := range cases {
		args := append([]string{"-i", "host", "-S", "-c", pub, "-k", priv}, tc.args...)
		o, err := parse(t, args...)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if got := o.AuthMode(); got != tc.want {
			t.Errorf("%s: AuthMode = %v, want %v", name, got, tc.want)
		}
	}
}

// $WSMANCER_PASSWORD is read before the mode is decided, so an exported
// password would otherwise turn a cert login into an NTLM one without a word.
func TestCertificateAuthIsNotDerailedByThePasswordEnvVar(t *testing.T) {
	pub, priv := certPair(t)
	t.Setenv("WSMANCER_PASSWORD", "leftover")

	o, err := parse(t, "-i", "host", "-S", "-c", pub, "-k", priv, "-u", "u")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if o.AuthMode() != AuthPassword {
		t.Errorf("AuthMode = %v, want AuthPassword: an exported password is still a password",
			o.AuthMode())
	}
}

// -u is required for the NTLM modes and not for the two that never name a user.
func TestUserRequirementFollowsTheMode(t *testing.T) {
	pub, priv := certPair(t)
	if _, err := parse(t, "-i", "host", "-S", "-c", pub, "-k", priv); err != nil {
		t.Errorf("certificate auth should not require -u: %v", err)
	}
	_, err := parse(t, "-i", "host", "-p", "pw")
	if err == nil || !strings.Contains(err.Error(), "-u/--user is required") {
		t.Errorf("a password login without -u should be refused, got: %v", err)
	}
}

// A certificate is only ever presented in a TLS handshake, so without -S there
// is no handshake to present it in.
func TestCertificateAuthRequiresTLS(t *testing.T) {
	pub, priv := certPair(t)
	_, err := parse(t, "-i", "host", "-c", pub, "-k", priv)
	if err == nil || !strings.Contains(err.Error(), "-S/--ssl") {
		t.Errorf("cert auth without -S should be refused, got: %v", err)
	}
}
