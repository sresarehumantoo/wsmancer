package shell

import (
	"strings"
	"testing"
)

func TestSanitizeTerminal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "transport: HTTP 500: access denied", "transport: HTTP 500: access denied"},
		{"keeps newlines and tabs", "line1\nline2\tcol", "line1\nline2\tcol"},
		// Only the ESC (0x1b) is a control byte; the "[31m" tail is printable
		// and harmless once the ESC is gone (no cursor move, no color change).
		{"defuses an escape by dropping ESC", "a\x1b[31m\x00\x07b", "a.[31m.b"},
		{"strips lone escape", "before\x1bafter", "before.after"},
		{"drops carriage returns (would rewind the line)", "a\rb", "a.b"},
		// ESC and the C1/binary run collapse; the printable "[" survives between them.
		{"collapses binary runs", "HTTP 500: " + string([]byte{0x1b, 0x5b, 0x00, 0xff, 0xfe, 0x9b, 0x07}), "HTTP 500: .[."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sanitizeTerminal(c.in)
			if got != c.want {
				t.Fatalf("sanitizeTerminal(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// A realistic encrypted HTTP-500 body (the actual failure that scrambled the
// terminal): after sanitizing, no ESC/CSI byte may survive to reach the terminal.
func TestSanitizeTerminalNeutralizesEscapes(t *testing.T) {
	body := "transport: HTTP 500: --Encrypted Boundary\r\n\x1b[2J\x1b[Happlication/octet-stream\x00\x1b\x9b" +
		string([]byte{0x80, 0x1b, 0x5b, 0x33, 0x6d, 0x07, 0xfe, 0xff})
	got := sanitizeTerminal(body)
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\r') {
		t.Fatalf("sanitized output still contains ESC or CR: %q", got)
	}
	for _, r := range got {
		if r != '\n' && r != '\t' && !isPrintableForTest(r) {
			t.Fatalf("sanitized output contains a non-printable rune %U in %q", r, got)
		}
	}
}

func isPrintableForTest(r rune) bool {
	// Mirror the sanitizer's notion of "safe": graphic runes plus the dot marker.
	return r == '.' || (r >= 0x20 && r != 0x7f)
}
