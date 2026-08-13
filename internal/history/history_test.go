package history

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func openIn(t *testing.T, dir, tag string) *Store {
	t.Helper()
	t.Setenv("WSMANCER_HISTORY_DIR", dir)
	st, err := Open(tag)
	if err != nil {
		t.Fatalf("Open(%q): %v", tag, err)
	}
	return st
}

// The point of the feature: what you ran last session is there the next time you
// connect to the same box.
func TestHistorySurvivesReconnect(t *testing.T) {
	dir := t.TempDir()
	st := openIn(t, dir, "dc01.corp.local")
	for _, l := range []string{"whoami", "net user"} {
		if _, err := st.Write(l); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	again := openIn(t, dir, "dc01.corp.local")
	defer again.Close()
	if got := again.Lines(); !slices.Equal(got, []string{"whoami", "net user"}) {
		t.Errorf("after reconnect Lines() = %v, want [whoami net user]", got)
	}
	if again.Len() != 2 {
		t.Errorf("Len() = %d, want 2", again.Len())
	}
	if l, _ := again.GetLine(0); l != "whoami" {
		t.Errorf("GetLine(0) = %q, want whoami (oldest first)", l)
	}
	// Appending to a reloaded store must extend the file, not truncate it.
	if _, err := again.Write("hostname"); err != nil {
		t.Fatal(err)
	}
	third := openIn(t, dir, "dc01.corp.local")
	defer third.Close()
	if got := third.Lines(); !slices.Equal(got, []string{"whoami", "net user", "hostname"}) {
		t.Errorf("Lines() = %v, want the earlier two plus hostname", got)
	}
}

// Different targets must not share a history.
func TestTagsAreSeparate(t *testing.T) {
	dir := t.TempDir()
	a := openIn(t, dir, "boxA")
	if _, err := a.Write("from-a"); err != nil {
		t.Fatal(err)
	}
	a.Close()
	b := openIn(t, dir, "boxB")
	defer b.Close()
	if got := b.Lines(); len(got) != 0 {
		t.Errorf("boxB sees %v, want an empty history", got)
	}
}

// The per-command opt-out. This is the escape hatch the banner advertises, so it
// has to hold for a tab as well as a space, and it must be judged on the RAW
// line -- the shell trims before dispatch, which would erase the signal.
func TestLeadingWhitespaceIsNotRecorded(t *testing.T) {
	dir := t.TempDir()
	st := openIn(t, dir, "box")
	defer st.Close()
	for _, l := range []string{" net user bob P@ssw0rd", "\tsecret-thing", "whoami", "   ", ""} {
		if _, err := st.Write(l); err != nil {
			t.Fatal(err)
		}
	}
	if got := st.Lines(); !slices.Equal(got, []string{"whoami"}) {
		t.Errorf("Lines() = %v, want only [whoami]", got)
	}
	// And nothing sensitive reached the file either.
	raw, err := os.ReadFile(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	if s := string(raw); s != "whoami\n" {
		t.Errorf("file = %q, want %q", s, "whoami\n")
	}
}

func TestRecordable(t *testing.T) {
	cases := map[string]bool{
		"whoami": true, " whoami": false, "\twhoami": false,
		"": false, "   ": false, "a b": true, "whoami ": true,
	}
	for line, want := range cases {
		if got := Recordable(line); got != want {
			t.Errorf("Recordable(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestConsecutiveDuplicatesCollapse(t *testing.T) {
	dir := t.TempDir()
	st := openIn(t, dir, "box")
	defer st.Close()
	for _, l := range []string{"whoami", "whoami", "hostname", "whoami"} {
		if _, err := st.Write(l); err != nil {
			t.Fatal(err)
		}
	}
	if got := st.Lines(); !slices.Equal(got, []string{"whoami", "hostname", "whoami"}) {
		t.Errorf("Lines() = %v, want consecutive dupes collapsed but the later repeat kept", got)
	}
}

// A file of commands run against a target is sensitive; it must not be readable
// by other users on a shared box.
func TestFilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hist")
	st := openIn(t, dir, "box")
	defer st.Close()
	if _, err := st.Write("whoami"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("history file mode = %o, want 600", perm)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("history dir mode = %o, want 700", perm)
	}
}

// A tag can come from --history-tag or from the target's own name, so it must
// never be able to escape the history directory.
func TestSanitizeTag(t *testing.T) {
	cases := map[string]string{
		"dc01.corp.local":  "dc01.corp.local",
		"user@host":        "user@host",
		"../../etc/passwd": ".._.._etc_passwd",
		`a/b\c`:            "a_b_c",
		"..":               "unknown",
		".":                "unknown",
		"":                 "unknown",
	}
	for in, want := range cases {
		if got := SanitizeTag(in); got != want {
			t.Errorf("SanitizeTag(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"../../etc/passwd", `a/b\c`, "..", ""} {
		got := SanitizeTag(bad)
		if filepath.Base(got) != got || got == "." || got == ".." {
			t.Errorf("SanitizeTag(%q) = %q, which is not a plain filename", bad, got)
		}
	}
}

func TestNilStoreIsNoop(t *testing.T) {
	var st *Store
	if n, err := st.Write("whoami"); n != 0 || err != nil {
		t.Errorf("Write on nil = (%d, %v)", n, err)
	}
	if l, err := st.GetLine(0); l != "" || err != nil {
		t.Errorf("GetLine on nil = (%q, %v)", l, err)
	}
	if st.Len() != 0 || st.Lines() != nil || st.Path() != "" || st.Dump() != nil {
		t.Error("a nil store is not fully inert")
	}
	if err := st.Close(); err != nil {
		t.Errorf("Close on nil = %v", err)
	}
}

// The default location is user-visible: it is where an operator looks for the
// file, and it appears in --help and the README. The rest of this package's
// tests all go through $WSMANCER_HISTORY_DIR, so without this one a typo in the
// fallback would reach a release unnoticed.
func TestDefaultHistoryRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("WSMANCER_HISTORY_DIR", "")

	got, err := historyRoot()
	if err != nil {
		t.Fatalf("historyRoot: %v", err)
	}
	if want := filepath.Join(home, ".wsmancer", "history"); got != want {
		t.Errorf("historyRoot() = %q, want %q", got, want)
	}
}
