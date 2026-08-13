package shell

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
)

// cachedShell is a shell with the command cache already warm and no session, so
// completion can be exercised without a target. remoteCommandNames returns the
// cache without touching sh.s, which is what makes this possible.
func cachedShell(o *cli.Options, cmds ...string) *Shell {
	return &Shell{o: o, remoteCmds: cmds}
}

var sampleCmds = []string{"Invoke-Command", "Invoke-Expression", "Invoke-WebRequest", "Get-Process"}

func TestCompleteWordOffersRemoteCommands(t *testing.T) {
	sh := cachedShell(&cli.Options{}, sampleCmds...)
	head, cands, tail := sh.completeWord("Invok", 5)
	if head != "" || tail != "" {
		t.Errorf("head/tail = %q/%q, want empty", head, tail)
	}
	// The target's cmdlets and the shell's own built-ins are one merged, sorted
	// list -- `invoke-binary` matches "Invok" too, and hiding it would be worse
	// than the mixed casing. Verbs sorts, so PascalCase leads on an ASCII sort.
	want := []string{"Invoke-Command", "Invoke-Expression", "Invoke-WebRequest", "invoke-binary"}
	if !slices.Equal(cands, want) {
		t.Errorf("cands = %v, want %v", cands, want)
	}
}

// complete.Verbs matches case-insensitively and reeflective sets
// completion-ignore-case, so a lowercase prefix must still reach a PascalCase
// cmdlet -- the way anyone actually types PowerShell.
func TestCompleteWordMatchesCommandsCaseInsensitively(t *testing.T) {
	sh := cachedShell(&cli.Options{}, sampleCmds...)
	_, cands, _ := sh.completeWord("invoke-w", 8)
	if !slices.Contains(cands, "Invoke-WebRequest") {
		t.Errorf("cands = %v, want it to contain Invoke-WebRequest", cands)
	}
}

// A bare Tab must stay useful: the built-ins are a usable menu, ~1900 cmdlets
// are not. It also avoids paying the fetch for a keystroke that narrows nothing.
func TestCompleteWordOmitsRemoteCommandsOnEmptyWord(t *testing.T) {
	sh := cachedShell(&cli.Options{}, sampleCmds...)
	_, cands, _ := sh.completeWord("", 0)
	for _, c := range cands {
		if slices.Contains(sampleCmds, c) {
			t.Errorf("empty word offered remote command %q; cands = %v", c, cands)
		}
	}
	if !slices.Contains(cands, "upload") {
		t.Errorf("empty word dropped the built-ins; cands = %v", cands)
	}
}

// -N promises to disable remote completion *entirely*, not just remote paths.
func TestNoRPathSuppressesRemoteCommands(t *testing.T) {
	sh := cachedShell(&cli.Options{NoRPath: true}, sampleCmds...)
	if got := sh.remoteCommandNames(); got != nil {
		t.Errorf("remoteCommandNames() = %v with -N, want nil", got)
	}
	// Not "no candidates at all": the built-in `invoke-binary` legitimately
	// matches "Invok" case-insensitively. What -N must remove is the target's.
	_, cands, _ := sh.completeWord("Invok", 5)
	for _, c := range cands {
		if slices.Contains(sampleCmds, c) {
			t.Errorf("-N still offered remote command %q; cands = %v", c, cands)
		}
	}
}

// The built-ins must keep completing even when the target never answers -- the
// fetch failing is not allowed to take the local vocabulary down with it.
func TestBuiltinsStillCompleteWithoutACache(t *testing.T) {
	sh := &Shell{o: &cli.Options{}} // nil session: the fetch is skipped entirely
	_, cands, _ := sh.completeWord("uplo", 4)
	if !slices.Contains(cands, "upload") {
		t.Errorf("cands = %v, want upload", cands)
	}
}

// A failed fetch must neither latch for the session nor re-pay the timeout on
// every keystroke.
func TestFailedFetchBacksOffThenRetries(t *testing.T) {
	sh := &Shell{o: &cli.Options{}}
	if !sh.commandFetchDue() {
		t.Error("a fresh shell should attempt the first fetch")
	}
	sh.remoteCmdsAt = time.Now() // an attempt that just failed
	if sh.commandFetchDue() {
		t.Error("retried immediately after a failure; that re-pays the timeout every Tab")
	}
	sh.remoteCmdsAt = time.Now().Add(-remoteCommandRetry - time.Second)
	if !sh.commandFetchDue() {
		t.Error("never retried after the cooldown; one hiccup would latch for the session")
	}
	// A warm cache short-circuits before the back-off is ever consulted.
	warm := cachedShell(&cli.Options{}, sampleCmds...)
	warm.remoteCmdsAt = time.Now()
	if got := warm.remoteCommandNames(); len(got) != len(sampleCmds) {
		t.Errorf("warm cache = %v, want it served during the cooldown", got)
	}
}

func TestInvalidateRemoteCommands(t *testing.T) {
	sh := cachedShell(&cli.Options{}, sampleCmds...)
	sh.remoteCmdsAt = time.Now()
	sh.invalidateRemoteCommands()
	if len(sh.remoteCmds) != 0 || !sh.remoteCmdsAt.IsZero() {
		t.Errorf("cache not cleared: cmds=%v at=%v", sh.remoteCmds, sh.remoteCmdsAt)
	}
}

// The script the fetch runs must project to plain names; a CommandInfo rendered
// by ToString() would put noise into the candidate list.
func TestRemoteCommandScriptProjectsNames(t *testing.T) {
	if !strings.Contains(remoteCommandScript, "$_.Name") {
		t.Errorf("script does not project $_.Name: %q", remoteCommandScript)
	}
	if !strings.Contains(remoteCommandScript, "SilentlyContinue") {
		t.Errorf("script does not tolerate a broken module: %q", remoteCommandScript)
	}
}
