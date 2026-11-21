package shell

import "testing"

func TestChangesLocation(t *testing.T) {
	yes := []string{
		"cd C:\\Users",
		"CD ..",
		"chdir /tmp",
		"sl ~",
		"Set-Location C:\\",
		"pushd .",
		"popd",
		"Push-Location foo",
		"Pop-Location",
	}
	for _, line := range yes {
		t.Run(line, func(t *testing.T) {
			if !changesLocation(line) {
				t.Errorf("changesLocation(%q) = false, want true", line)
			}
		})
	}

	no := []string{
		"Get-ChildItem",
		"echo cd",
		"Get-Location",
		"ls",
		"dir",
	}
	for _, line := range no {
		t.Run(line, func(t *testing.T) {
			if changesLocation(line) {
				t.Errorf("changesLocation(%q) = true, want false", line)
			}
		})
	}
}

func TestSanitizeTerminalAttackerInputs(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"OSC title change", "\x1b]0;pwned\x07"},
		{"CSI cursor move", "\x1b[2J\x1b[H"},
		{"DCS sequence", "\x1bPmalicious\x1b\\"},
		{"null bytes", "hello\x00world"},
		{"raw 0x9b CSI", "text\x9bmalicious"},
		{"bell flood", "\x07\x07\x07"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sanitizeTerminal(c.in)
			for _, r := range got {
				if r < 0x20 && r != '\n' && r != '\t' {
					t.Errorf("sanitizeTerminal(%q) contains control char %U in %q", c.in, r, got)
				}
			}
		})
	}
}
