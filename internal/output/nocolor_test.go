package output

import (
	"os"
	"testing"
)

// EnvDisablesColor is a policy decision, so pin the policy rather than the
// implementation. The NO_COLOR=0 case is the one worth stating explicitly: the
// convention is presence-based, and "0 means colors on" is the plausible
// misreading that would break anyone exporting it globally.
func TestEnvDisablesColor(t *testing.T) {
	cases := []struct {
		name    string
		noColor *string
		term    string
		want    bool
	}{
		{"capable terminal, nothing set", nil, "xterm-256color", false},
		{"NO_COLOR empty", strptr(""), "xterm-256color", true},
		{"NO_COLOR=1", strptr("1"), "xterm-256color", true},
		{"NO_COLOR=0 still disables", strptr("0"), "xterm-256color", true},
		{"TERM=dumb", nil, "dumb", true},
		{"TERM unset", nil, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.noColor == nil {
				// t.Setenv first so the cleanup that restores the original
				// value is registered, then actually unset it.
				t.Setenv("NO_COLOR", "")
				if err := os.Unsetenv("NO_COLOR"); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Setenv("NO_COLOR", *tc.noColor)
			}
			t.Setenv("TERM", tc.term)
			if got := EnvDisablesColor(); got != tc.want {
				t.Errorf("EnvDisablesColor() = %v, want %v", got, tc.want)
			}
		})
	}
}

func strptr(s string) *string { return &s }
