//go:build linux

package lineedit_test

// The terminal that never answers.
//
// New() falls back to a plain reader when stdin/stdout are not character
// devices, which covers pipes, files, -x and CI. It does NOT cover a real but
// uncooperative tty, and that gap is not theoretical: reeflective's
// GetCursorPos (internal/core/keys_unix.go) writes ESC[6n and then loops on
// os.Stdin.Read with **no timeout**, feeding anything that is not a cursor
// report into the key buffer and waiting again. Its only guard is
// !term.IsTerminal, so a char device that never replies blocks there forever
// and the shell hangs at startup with no output -- indistinguishable from a
// transport hang, which is the most expensive way for this tool to fail.
//
// This is the inverse of every other PTY harness here: those must answer the
// DSR query to work at all (docs/verification.md's DSR trap), so none of them can see this.
// This one deliberately stays silent, which is the only way the hang is
// reachable. It needs no target, so unlike almost everything in
// docs/verification.md it runs in CI.
//
// The child runs in a subprocess rather than in-process because GetCursorPos
// reads the package-level os.Stdin, not the io.Reader passed to New -- an
// in-process test would have to swap os.Stdin, and a hang would take the whole
// test binary down with it rather than failing one case.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sresarehumantoo/wsmancer/internal/lineedit"
)

const (
	helperEnv    = "WSM_LINEEDIT_HELPER"
	helperPrompt = "HELPER-READY> "
	probeLine    = "probe-line-42"
)

// TestMain lets this binary re-exec itself as the child under test.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		// Exactly what the shell does: build an editor over the process's own
		// stdin/stdout and ask for a line. Reaching the prompt at all is the
		// property under test.
		ed := lineedit.New(os.Stdin, os.Stdout, nil, nil)
		line, err := ed.Prompt(helperPrompt)
		fmt.Fprintf(os.Stdout, "\nHELPER-DONE line=%q err=%v\n", line, err)
		_ = ed.Close()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// openPTY returns the master and the slave's name. Hand-rolled rather than
// pulling in a pty module: this is the whole of what is needed, and the module
// would be a new dependency for one test.
func openPTY(t *testing.T) (*os.File, string) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		t.Fatalf("unlockpt: %v", err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		master.Close()
		t.Fatalf("ptsname: %v", err)
	}
	return master, fmt.Sprintf("/dev/pts/%d", n)
}

// runOnSilentTTY starts the helper on a real pty whose other end answers
// NOTHING -- in particular it never replies to ESC[6n -- types a line, and
// reports whether the editor actually RETURNED that line.
//
// The assertion is deliberately the returned line and not the appearance of the
// prompt. The first version of this test waited for the prompt and passed on
// unguarded code, because the prompt string is written to the terminal *before*
// the cursor query is issued -- so it shows up whether or not the editor then
// blocks forever waiting for a reply. Only a completed read proves the editor
// is usable.
func runOnSilentTTY(t *testing.T, env []string, wait time.Duration) (readLine bool, saw string) {
	t.Helper()
	master, name := openPTY(t)
	defer master.Close()

	slave, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open slave: %v", err)
	}
	defer slave.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestNothingMatchesThis")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	// Scrub an inherited WSMANCER_EDITOR before applying the case's own env,
	// so a value in the developer's or runner's environment cannot silently
	// turn the sanity control into a guarded run. pty-test.py does the same.
	cmd.Env = append(os.Environ(), helperEnv+"=1", "WSMANCER_EDITOR=")
	cmd.Env = append(cmd.Env, env...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// Read whatever the child emits, and pointedly do not answer the DSR query.
	type readResult struct{ b []byte }
	out := make(chan readResult, 32)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				out <- readResult{b}
			}
			if err != nil {
				return
			}
		}
	}()

	deadline := time.After(wait)
	var acc strings.Builder
	typed := false
	for {
		select {
		case r := <-out:
			acc.Write(r.b)
			// Type only once the prompt is on screen, so the line cannot be
			// consumed before the editor is reading.
			if !typed && strings.Contains(acc.String(), helperPrompt) {
				typed = true
				if _, err := master.WriteString(probeLine + "\r"); err != nil {
					t.Fatalf("write to pty: %v", err)
				}
			}
			// The marker is what the CHILD prints after Prompt returns, and it
			// carries the line back. The terminal editor echoes keystrokes, so
			// matching the typed text alone would match that echo -- the classic
			// wrong-reason pass this repo keeps rediscovering.
			if strings.Contains(acc.String(), `HELPER-DONE line="`+probeLine+`"`) {
				return true, acc.String()
			}
		case <-deadline:
			return false, acc.String()
		}
	}
}

// TestSilentTTYReachesPrompt is the guard. Each case is a terminal that never
// answers the cursor query; the editor must still reach a prompt, by falling
// back to the plain reader rather than blocking on a reply that is not coming.
func TestSilentTTYReachesPrompt(t *testing.T) {
	cases := []struct {
		name string
		env  []string
	}{
		{"TERM=dumb", []string{"TERM=dumb"}},
		{"TERM unset", []string{"TERM="}},
		{"forced plain editor", []string{"TERM=xterm-256color", "WSMANCER_EDITOR=plain"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, saw := runOnSilentTTY(t, tc.env, 8*time.Second)
			if !ok {
				t.Fatalf("the editor never returned a typed line within 8s on a "+
					"tty that ignores ESC[6n -- it is blocked waiting for a "+
					"cursor report.\nsaw: %q", saw)
			}
		})
	}
}

// TestSilentTTYSanity is the anti-vacuity control, and it is the reason the test
// above means anything. It asserts the harness can observe the failure it
// claims to prevent: with a capable TERM and no override, the terminal editor is
// selected, and on a tty that never answers the query it does NOT reach a
// prompt. If this ever starts passing, either the dependency grew a timeout or
// the harness stopped exercising the terminal path -- and in both cases the
// guard above is no longer testing what it says.
func TestSilentTTYSanity(t *testing.T) {
	// Shorter than the guarded cases on purpose: this one is *expected* to burn
	// its whole budget, and it is the only thing this package's tests wait on.
	// 4s is many orders above the 0.01s a guarded run takes, so it is not a
	// race with a merely-slow start.
	ok, saw := runOnSilentTTY(t, []string{"TERM=xterm-256color"}, 4*time.Second)
	if ok {
		t.Skipf("the terminal editor now completes a read without a cursor "+
			"report -- re-check whether the guard is still load-bearing.\nsaw: %q", saw)
	}
}
