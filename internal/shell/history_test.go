package shell

import (
	"io"
	"os"
	"testing"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
	"github.com/sresarehumantoo/wsmancer/internal/output"
)

// The invariant this feature reverses, pinned so it cannot regress by accident:
// without -Y/--history nothing about a session reaches disk. A session's
// commands routinely carry hashes and passwords, so "off" has to mean off --
// no file, no directory, no empty placeholder.
func TestHistoryOffTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WSMANCER_HISTORY_DIR", dir)
	sh := &Shell{o: &cli.Options{IP: "dc01.corp.local"}, out: io.Discard, c: output.NewColors(false)}

	if got := sh.openHistory(); got != nil {
		t.Fatalf("openHistory() = %v with the flag off, want nil", got)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("history dir has %d entries with the flag off, want none", len(ents))
	}
}

func TestHistoryOnUsesTheTargetAsDefaultTag(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WSMANCER_HISTORY_DIR", dir)
	sh := &Shell{o: &cli.Options{IP: "dc01.corp.local", History: true},
		out: io.Discard, c: output.NewColors(false)}

	st := sh.openHistory()
	if st == nil {
		t.Fatal("openHistory() = nil with -Y set")
	}
	defer st.Close()
	if want := dir + "/dc01.corp.local.hist"; st.Path() != want {
		t.Errorf("Path() = %q, want %q", st.Path(), want)
	}
}

// --history-tag lets several boxes share one history, or one box keep several.
func TestHistoryTagOverridesTheTarget(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WSMANCER_HISTORY_DIR", dir)
	sh := &Shell{o: &cli.Options{IP: "10.10.10.5", History: true, HistoryTag: "corp-engagement"},
		out: io.Discard, c: output.NewColors(false)}

	st := sh.openHistory()
	if st == nil {
		t.Fatal("openHistory() = nil")
	}
	defer st.Close()
	if want := dir + "/corp-engagement.hist"; st.Path() != want {
		t.Errorf("Path() = %q, want %q", st.Path(), want)
	}
}
