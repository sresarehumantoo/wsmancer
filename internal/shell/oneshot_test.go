package shell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
)

// once builds a one-shot Shell with no session. Every test here exercises a path
// that must not reach the target, which is the point: a nil session turns "this
// talked to the box" into a crash rather than a silent pass.
func once(t *testing.T, o *cli.Options) (*Shell, *bytes.Buffer) {
	t.Helper()
	if o == nil {
		o = &cli.Options{}
	}
	o.NoColors = true
	var buf bytes.Buffer
	return NewOnce(nil, o, &buf), &buf
}

// The feature: a built-in is reachable from -x at all. Before this, -x wrote the
// line straight to the runspace, so `help` meant the target's Get-Help and
// `services` meant a cmdlet that does not exist.
func TestOnceRunsABuiltIn(t *testing.T) {
	sh, out := once(t, nil)

	if code := sh.Once(context.Background(), "help"); code != 0 {
		t.Errorf("Once(help) = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "Any PowerShell command") {
		t.Errorf("-x help did not print the port's help; got:\n%s", out.String())
	}
}

func TestOnceExitVerbSucceeds(t *testing.T) {
	sh, _ := once(t, nil)
	if code := sh.Once(context.Background(), "exit"); code != 0 {
		t.Errorf("Once(exit) = %d, want 0", code)
	}
}

// dispatch indexes Fields(line)[0]. An all-whitespace -x reaches Once (cli only
// checks for empty), so without the trim it panics instead of exiting.
func TestOnceIgnoresAWhitespaceOnlyCommand(t *testing.T) {
	sh, _ := once(t, nil)
	if code := sh.Once(context.Background(), "   \t "); code != 0 {
		t.Errorf("Once(whitespace) = %d, want 0", code)
	}
}

// A failing built-in must exit non-zero: a script's only signal is the code.
func TestOnceReportsABuiltInErrorAsExitOne(t *testing.T) {
	sh, out := once(t, nil)

	code := sh.Once(context.Background(), "upload")
	if code != 1 {
		t.Errorf("Once(upload) with no arguments = %d, want 1", code)
	}
	if !strings.Contains(out.String(), "usage: upload") {
		t.Errorf("no usage message; got:\n%s", out.String())
	}
}

// The other half of the exit code, and the half a naive port drops: executeAs
// renders a PowerShell error record (or a canceled pipeline, or a reported
// transport fault) and returns nil, so only sh.failed separates it from success.
func TestOnceExitsOneWhenTheCommandFailedWithoutAnError(t *testing.T) {
	sh, _ := once(t, nil)
	sh.failed = true // what executeAs sets for res.HadErrors

	if code := sh.Once(context.Background(), "clear"); code != 1 {
		t.Errorf("Once() = %d with a failed command, want 1", code)
	}
}

// -o json promises a parseable object on every path, errors included, a
// consumer must never have to scrape prose to find out what happened.
func TestOnceReportsErrorsAsJSON(t *testing.T) {
	sh, out := once(t, &cli.Options{Output: "json"})

	if code := sh.Once(context.Background(), "upload"); code != 1 {
		t.Errorf("Once(upload) = %d, want 1", code)
	}
	var got struct {
		Command   string   `json:"command"`
		Errors    []string `json:"errors"`
		HadErrors bool     `json:"had_errors"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON (%v):\n%s", err, out.String())
	}
	if got.Command != "upload" || !got.HadErrors || len(got.Errors) == 0 {
		t.Errorf("JSON error object = %+v, want the command, had_errors and a message", got)
	}
	if !strings.Contains(got.Errors[0], "usage: upload") {
		t.Errorf("errors[0] = %q, want the usage message", got.Errors[0])
	}
}

// -x with -Y must not create the history file: history exists to be recalled at
// a prompt a one-shot never shows, so opening it would be a side effect with no
// reader. Same invariant TestHistoryOffTouchesNothing pins for the flag itself.
func TestOnceKeepsNoHistoryOrEditor(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WSMANCER_HISTORY_DIR", dir)
	sh, _ := once(t, &cli.Options{IP: "dc01.corp.local", History: true})

	if sh.hist != nil {
		t.Error("one-shot opened a history store")
	}
	if sh.ed != nil {
		t.Error("one-shot built a line editor")
	}
	if code := sh.Once(context.Background(), "clear"); code != 0 {
		t.Fatalf("Once(clear) = %d, want 0", code)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("history dir has %d entries after a one-shot, want none", len(ents))
	}
}

// A forgotten shell is reported, not recovered from: there is no next command to
// protect and the failed one is never re-run, so a fresh shell would only
// announce state the exiting process cannot use. The nil session is the teeth,
// recoverShell would dereference it.
func TestOnceReportsAForgottenShellInsteadOfRecovering(t *testing.T) {
	sh, out := once(t, nil)

	sh.reportErr("whoami", errors.New(shellNotFoundSummary))

	if s := out.String(); !strings.Contains(s, "shell was not found") {
		t.Errorf("forgotten shell not reported; got:\n%s", s)
	}
	if s := out.String(); strings.Contains(s, "new shell has been opened") {
		t.Errorf("one-shot recovered onto a new shell; got:\n%s", s)
	}
	if !sh.failed {
		t.Error("reportErr did not mark the command failed")
	}
}
