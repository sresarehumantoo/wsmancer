package ntlmseal

import "testing"

// The User-Agent must default to the genuine WinRM client's string (the old
// hardcoded "ntlmseal-spike" was a network-side tell), and -a must override it.
func TestUserAgentDefaultAndOverride(t *testing.T) {
	p, err := New(Config{User: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if p.cfg.UserAgent != defaultUserAgent {
		t.Errorf("default User-Agent = %q, want %q", p.cfg.UserAgent, defaultUserAgent)
	}
	if defaultUserAgent != "Microsoft WinRM Client" {
		t.Errorf("default should mimic the real client, got %q", defaultUserAgent)
	}

	p2, err := New(Config{User: "u", Password: "p", UserAgent: "curl/8.0"})
	if err != nil {
		t.Fatal(err)
	}
	if p2.cfg.UserAgent != "curl/8.0" {
		t.Errorf("override User-Agent = %q, want %q", p2.cfg.UserAgent, "curl/8.0")
	}
}
