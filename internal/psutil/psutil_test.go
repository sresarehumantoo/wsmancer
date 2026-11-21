package psutil

import "testing"

func TestQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"simple", "'simple'"},
		{"", "''"},
		{"it's", "'it''s'"},
		{"a'b'c", "'a''b''c'"},
		{"$(whoami)", "'$(whoami)'"},
		{`'; calc.exe; '`, `'''; calc.exe; '''`},
	}
	for _, c := range cases {
		if got := Quote(c.in); got != c.want {
			t.Errorf("Quote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseNTHash(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantNil bool
		wantErr bool
	}{
		{"empty returns nil", "", true, false},
		{"bare 32-hex hash", "aad3b435b51404eeaad3b435b51404ee", false, false},
		{"LM:NT form", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", false, false},
		{"with spaces", "  aad3b435b51404eeaad3b435b51404ee  ", false, false},
		{"short hash", "aad3b435b51404ee", false, true},
		{"not hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", false, true},
		{"odd length", "aad3b435b51404eeaad3b435b51404e", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := ParseNTHash(c.in)
			if c.wantErr && err == nil {
				t.Fatalf("ParseNTHash(%q) = nil error, want error", c.in)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("ParseNTHash(%q) = %v", c.in, err)
			}
			if c.wantNil && b != nil {
				t.Fatalf("ParseNTHash(%q) = %x, want nil", c.in, b)
			}
			if !c.wantNil && !c.wantErr && len(b) != 16 {
				t.Fatalf("ParseNTHash(%q) = %d bytes, want 16", c.in, len(b))
			}
		})
	}
}
