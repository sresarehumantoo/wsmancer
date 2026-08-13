package shell

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
	"github.com/sresarehumantoo/wsmancer/internal/output"
	"github.com/sresarehumantoo/wsmancer/internal/session"
	"github.com/sresarehumantoo/wsmancer/internal/transcript"
	"github.com/sresarehumantoo/wsmancer/internal/transfer"
)

// NewOnce builds a Shell for -x: the same built-in dispatch as the interactive
// REPL, with no line editor and no history.
//
// Both are omitted rather than merely unused. The editor grabs the terminal when
// stdin and stdout are both TTYs, which a one-shot has no business doing; and
// history exists to be recalled at a prompt there will never be, so opening
// (and creating) the on-disk file for -Y would be a side effect with no reader.
// sh.ed and sh.hist therefore stay nil here, which is why Once must not call
// anything that reaches them, Run is the only such path.
func NewOnce(s *session.Session, o *cli.Options, stdout io.Writer) *Shell {
	sh := newShell(s, o, stdout)
	sh.once = true
	return sh
}

// Once runs a single command line through the shell's own dispatch and returns
// the process exit code: 0 on success, 1 if the command failed.
//
// Going through dispatch is the whole point. Before it did, -x wrote the line
// straight to the runspace, so no built-in was reachable from a script or an
// agent: `-x services` ran a cmdlet that does not exist, and upload, download,
// invoke-binary, donut-loader, menu and bypass-4msi had no non-interactive form
// at all. The trade is that the built-ins now shadow their remote namesakes here
// exactly as they already do interactively, `-x help` and `-x clear` are this
// tool's, not the target's. `-x 'Get-Help ...'` and `-x Clear-Host` are the way
// to reach those, and one consistent rule is worth more than two modes that
// disagree about what a word means.
func (sh *Shell) Once(ctx context.Context, line string) int {
	// Ctrl-C terminates the remote pipeline rather than abandoning it: the same
	// handling as the interactive shell, and the reason the caller hands over its
	// signal registration first. Exiting on a canceled context instead would
	// leave the command running on the target with nothing left to stop it.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)

	sh.startOnceLog(line)
	defer sh.log.Close()

	// dispatch indexes Fields(line)[0], so an all-whitespace -x must not reach it.
	line = strings.TrimSpace(line)
	if line == "" {
		return 0
	}

	if _, err := sh.dispatch(ctx, sigs, line); err != nil {
		sh.reportErr(line, err)
		return 1
	}
	// A command can fail without returning an error: a PowerShell error record,
	// a canceled pipeline or a reported transport fault all render and return
	// nil, and only sh.failed distinguishes them from success. Dropping that
	// distinction would hand every script and agent exit code 0 for a command
	// that plainly did not work.
	if sh.failed {
		return 1
	}
	return 0
}

// startOnceLog opens the -l transcript for a one-shot. It is Run's startLog
// without the terminal chatter: the "session log: <path>" line belongs on a
// prompt, not in the output a script is about to parse.
func (sh *Shell) startOnceLog(line string) {
	if !sh.o.Log {
		return
	}
	lg, err := transcript.Open(sh.o.IP)
	if err != nil {
		if !sh.json {
			fmt.Fprintln(os.Stderr, sh.c.Yellow("Warning: could not open session log: "+err.Error()))
		}
		return
	}
	sh.log = lg
	sh.log.Event("=== one-shot: %s (%s) ===", sh.o.IP, sh.s.AuthMode())
	sh.log.Event("PS > %s", line)
}

// newShell builds the parts both modes share. Split out of New so the one-shot
// constructor cannot drift from it, every field that is not the editor or the
// history is set in exactly one place.
func newShell(s *session.Session, o *cli.Options, stdout io.Writer) *Shell {
	return &Shell{
		s:    s,
		o:    o,
		c:    output.NewColors(!o.NoColors && !output.EnvDisablesColor()),
		out:  stdout,
		json: o.Output == "json",
		tty:  isTerminal(stdout),
		tx:   transfer.NewWithChunk(s, o.ChunkKB*1024),
	}
}
