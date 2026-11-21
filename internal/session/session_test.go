package session

import "testing"

func TestSafeForHereString(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		{"ordinary command", "Get-Process", true},
		{"multiline safe", "line1\nline2\nline3", true},
		{"terminator at start", "'@ | malicious", false},
		{"leading spaces before terminator", "  '@ oops", true},
		{"terminator with trailing whitespace", "'@ \t", false},
		{"terminator mid-line is safe", "echo 'something'@ here", true},
		{"empty", "", true},
		{"only newlines", "\n\n\n", true},
		{"pipe after safe quote", "echo 'hello' | sort", true},
		{"terminator on second line", "line1\n'@\nline3", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := safeForHereString(c.cmd); got != c.want {
				t.Errorf("safeForHereString(%q) = %v, want %v", c.cmd, got, c.want)
			}
		})
	}
}
