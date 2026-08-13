package lineedit

import (
	"testing"

	"github.com/sresarehumantoo/wsmancer/internal/complete"
)

// The reeflective editor is terminal-driven, so the interactive read path can
// only be proven against a real PTY (scripts/reef-pty-test.py). These tests guard
// the wiring that does not need a terminal: construction, the Editor contract,
// that the completer adapter passes the line/cursor through, and the candidate
// requoting that makes whitespace-bearing paths completable.

func TestReeflectiveEditorSatisfiesInterface(t *testing.T) {
	var _ Editor = newReeflectiveEditor(nil, nil)
}

func TestReeflectiveEditorConstruction(t *testing.T) {
	e := newReeflectiveEditor(nil, nil)
	if !e.Interactive() {
		t.Fatal("reeflective editor should report Interactive() == true")
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	// history-autosuggest (the ghost text) must be enabled.
	if v, _ := e.rl.Config.Vars["history-autosuggest"].(bool); !v {
		t.Fatal("history-autosuggest should be enabled on the reeflective editor")
	}
}

func TestReeflectiveCompleterAdapterPassesThrough(t *testing.T) {
	var gotLine string
	var gotPos int
	wc := func(line string, pos int) (string, []string, string) {
		gotLine, gotPos = line, pos
		return line[:pos], []string{"upload", "download"}, line[pos:]
	}
	adapter := adaptCompleter(wc)
	// reeflective calls the completer with the rune slice and cursor position.
	adapter([]rune("up"), 2)
	if gotLine != "up" || gotPos != 2 {
		t.Fatalf("adapter passed (line=%q,pos=%d), want (\"up\",2)", gotLine, gotPos)
	}
}

// A whitespace-bearing candidate has to satisfy two constraints at once, and the
// only assertion that really proves it is a round-trip: reeflective keeps the
// candidate only if it literally prefix-matches what was typed, and the shell
// only runs the right command if the inserted line tokenizes back to the true
// path. Checking the string shape alone would pass for a value that parses wrong.
func TestRequoteAfterRoundTrips(t *testing.T) {
	const path = `C:\My Files\report.txt`
	cases := []struct{ name, typed string }{
		{"unquoted partial word", `C:\My`},
		{"empty word (fresh arg)", ``},
		{"word already opened a quote", `"C:\My`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cand := requoteAfter(tc.typed, complete.Quote(path))

			// 1. reeflective's filter: RawValues.FilterPrefix is a plain HasPrefix
			// against the candidate value, so a non-matching candidate is silently
			// dropped and the path becomes uncompletable.
			if len(cand) < len(tc.typed) || cand[:len(tc.typed)] != tc.typed {
				t.Fatalf("candidate %q does not start with typed %q: reeflective would filter it out", cand, tc.typed)
			}

			// 2. The shell's parse: acceptCandidate replaces the typed span with
			// the candidate verbatim, so this is the literal resulting line.
			line := "download " + cand
			args := complete.Tokenize(line)
			if len(args) != 2 {
				t.Fatalf("line %q tokenized to %d tokens, want 2", line, len(args))
			}
			if args[1].Text != path {
				t.Fatalf("line %q parsed to %q, want %q", line, args[1].Text, path)
			}
		})
	}
}

// Candidates that need no rewriting must pass through untouched, or an ordinary
// completion would be corrupted by the whitespace fix.
func TestRequoteAfterLeavesPlainCandidates(t *testing.T) {
	for _, c := range []string{"upload", `C:\Windows\`, `.\bin.exe`} {
		if got := requoteAfter("C:", c); got != c {
			t.Errorf("requoteAfter(%q) = %q, want it unchanged", c, got)
		}
	}
}
