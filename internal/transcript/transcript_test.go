package transcript

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestOpenWritesTranscript(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WSMANCER_LOG_DIR", dir)

	lg, err := Open("10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(lg.Path(), filepath.Join(dir, "10.0.0.5")) {
		t.Errorf("path %q not under host dir", lg.Path())
	}
	lg.Event("PS C:\\> %s", "whoami")
	lg.Output("corp\\alice\n\n") // trailing blanks trimmed
	lg.Output("")                // empty block dropped
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(lg.Path())
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"PS C:\\> whoami", "corp\\alice", "session end"} {
		if !strings.Contains(text, want) {
			t.Errorf("transcript missing %q\n---\n%s", want, text)
		}
	}
	// Event lines carry an ISO-ish timestamp; the output block does not.
	if !regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}  PS`).MatchString(text) {
		t.Errorf("event line missing timestamp:\n%s", text)
	}
	if strings.Count(text, "corp\\alice") != 1 {
		t.Errorf("output should appear once (empty block dropped):\n%s", text)
	}
}

// Every method must be safe on a nil *Log, so callers log unconditionally.
func TestNilLogIsNoop(t *testing.T) {
	var lg *Log
	lg.Event("x %d", 1)
	lg.Output("y")
	if lg.Path() != "" {
		t.Error("nil Path should be empty")
	}
	if err := lg.Close(); err != nil {
		t.Errorf("nil Close should be nil, got %v", err)
	}
}

// A hostile host name must stay a single path element, no traversal, no
// separators escaping the log root.
func TestSanitizeHost(t *testing.T) {
	cases := map[string]string{
		"dc01.corp.local": "dc01.corp.local",
		"10.0.0.1":        "10.0.0.1",
		"../../etc":       ".._.._etc", // dots are safe in a filename; separators are not
		`a/b\c`:           "a_b_c",
		"..":              "unknown", // a whole-name .. would be traversal
		"":                "unknown",
	}
	for in, want := range cases {
		if got := sanitizeHost(in); got != want {
			t.Errorf("sanitizeHost(%q) = %q, want %q", in, got, want)
		}
		if strings.ContainsAny(sanitizeHost(in), `/\`) {
			t.Errorf("sanitizeHost(%q) still contains a separator", in)
		}
	}
}

// Same reasoning as history's TestDefaultHistoryRoot: every other test here
// overrides $WSMANCER_LOG_DIR, so the default path is otherwise unasserted.
func TestDefaultLogRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("WSMANCER_LOG_DIR", "")

	got, err := logRoot()
	if err != nil {
		t.Fatalf("logRoot: %v", err)
	}
	if want := filepath.Join(home, ".wsmancer", "logs"); got != want {
		t.Errorf("logRoot() = %q, want %q", got, want)
	}
}
