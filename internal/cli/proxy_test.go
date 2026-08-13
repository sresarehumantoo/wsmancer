package cli

import (
	"io"
	"strings"
	"testing"
)

func parseProxyOpts(t *testing.T, argv ...string) (*Options, error) {
	t.Helper()
	base := []string{"-i", "10.10.10.5", "-u", "admin", "-p", "pw"}
	return Parse(append(base, argv...), io.Discard)
}

func TestProxyFlagParses(t *testing.T) {
	o, err := parseProxyOpts(t, "--proxy", "socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o.Proxy != "socks5://127.0.0.1:1080" {
		t.Errorf("Proxy = %q, want the URL as given", o.Proxy)
	}
}

// A bad URL must be rejected at parse time. The alternative, finding out on
// the first dial, reports "connection refused" against an address the operator
// never typed, long after the banner claimed it was connecting through a proxy.
func TestProxyBadURLRejectedAtParse(t *testing.T) {
	_, err := parseProxyOpts(t, "--proxy", "http://127.0.0.1:8080")
	if err == nil {
		t.Fatal("Parse accepted an http:// proxy, want an error")
	}
	if !strings.Contains(err.Error(), "socks5") {
		t.Errorf("error = %q, want it to say what is supported", err)
	}
}

func TestProxyFromEnv(t *testing.T) {
	t.Setenv("WSMANCER_PROXY", "socks5://10.0.0.9:1080")
	o, err := parseProxyOpts(t)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o.Proxy != "socks5://10.0.0.9:1080" {
		t.Errorf("Proxy = %q, want it taken from WSMANCER_PROXY", o.Proxy)
	}
}

// The flag wins, so one exported proxy for the engagement can still be
// overridden for a single target.
func TestProxyFlagBeatsEnv(t *testing.T) {
	t.Setenv("WSMANCER_PROXY", "socks5://10.0.0.9:1080")
	o, err := parseProxyOpts(t, "--proxy", "socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o.Proxy != "socks5://127.0.0.1:1080" {
		t.Errorf("Proxy = %q, want the flag to win over the environment", o.Proxy)
	}
}

// No proxy anywhere is the overwhelmingly common case and must stay a direct
// connection rather than an error.
func TestNoProxyIsFine(t *testing.T) {
	t.Setenv("WSMANCER_PROXY", "")
	o, err := parseProxyOpts(t)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if o.Proxy != "" {
		t.Errorf("Proxy = %q, want empty", o.Proxy)
	}
}
