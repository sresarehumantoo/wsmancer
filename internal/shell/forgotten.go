package shell

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/smnsjas/go-psrp/client"

	"github.com/sresarehumantoo/wsmancer/internal/output"
)

// shellForgotten reports whether err is the target saying it no longer has our
// shell, a WinRM service restart, an administrator removing it, or the shell's
// IdleTimeout (PT30M by default) elapsing.
//
// This is a different failure from connectionLost, and the difference is the
// whole point. A dropped connection is *recoverable in place*: the transport
// re-dials, WinRM re-attaches the same shell, and the runspace survives with its
// variables, functions, working directory and -s scripts intact. A forgotten
// shell cannot be re-attached at all, the ShellId is gone, so every later
// command fails identically and the prompt is dead while still looking alive.
// Recovery means a new shell, which means the runspace state is gone.
//
// Matching is on the message text, deliberately NOT on the fault code. WinRM
// reports this as w:InvalidSelectors with WSManFault code 2150858843, but that
// same code also means "command identifier that does not exist", see the
// fork's isCommandGone, which treats it as the benign already-finished-command
// race that StopPipelines routinely provokes. Keying on the code would make an
// ordinary Ctrl-C look like a lost shell and tear down a perfectly good
// runspace, destroying exactly the state this function exists to warn about. So
// the shell-specific wording is the discriminator, and the code is ignored.
func shellForgotten(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	// Both phrasings come from the one Windows message ("... failed because the
	// shell was not found on the server. Possible causes are: ... or the shell
	// no longer exists on the server."), but they are matched separately so a
	// truncated or localised variant carrying only one of them still counts.
	// clean() caps each fault field at 600 chars, which can cut the sentence.
	return strings.Contains(s, "shell was not found") ||
		strings.Contains(s, "shell no longer exists")
}

// resultShellForgotten returns the forgotten-shell error carried in a result's
// error stream, or nil. It mirrors resultConnectionLost, and for the same
// reason: a transport failure aborts the pipeline, so it surfaces as an error
// record rather than a returned error.
//
// Like that function it only inspects a result that produced no output, so a
// command that streamed something and then failed still renders normally.
func resultShellForgotten(res *client.Result) error {
	if res == nil || len(res.Output) > 0 || len(res.Errors) == 0 {
		return nil
	}
	for _, e := range res.Errors {
		if err, ok := e.(error); ok && shellForgotten(err) {
			return err
		}
		if s, ok := e.(string); ok && shellForgotten(errors.New(s)) {
			return errors.New(s)
		}
	}
	return nil
}

// recoverShell opens a fresh shell after the target has forgotten ours, and
// tells the operator plainly what that cost them.
//
// The warning is not politeness. Everything the operator built up in the old
// runspace is gone, the working directory, variables, functions, scripts
// loaded with -s, the functions menu registered, and any bypass-4msi patch.
// The AMSI patch is the one that matters most: it lives in the process the
// shell was running in, so a new shell is unpatched. An operator who believed
// otherwise would run their next post-ex command straight into AMSI. Silently
// re-creating the shell would be the dangerous choice precisely because
// everything would look like it still worked.
//
// It runs on its own context rather than the failed command's, which may
// already be canceled, a Ctrl-C that raced the failure must not also cancel
// the reconnect.
//
// In json mode the notice is a structured `event` record on sh.out (the object
// stream), so a batch consumer reading only stdout learns that state was lost
// without a human-readable block making the stream unparseable. In text mode it
// is the colored prose an operator expects. Both carry the same fact: the
// runspace's accumulated state is gone and must be re-established.
func (sh *Shell) recoverShell() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const lostMsg = "the target no longer had this shell (it was restarted or timed out); a new one was opened. " +
		"Session state was LOST: working directory, variables, functions, any -s scripts, and any bypass-4msi patch. Re-load what you need."

	if err := sh.s.Renew(ctx); err != nil {
		sh.log.Event("Shell lost; reconnect failed: %s", err.Error())
		if sh.json {
			_ = output.RenderEvent(sh.out, "shell_recovery_failed",
				"the target no longer has this shell, and opening a new one failed: "+err.Error(), true)
			return
		}
		fmt.Fprintln(sh.out, sh.c.Red("Error: the target no longer has this shell, and opening a new one failed:"))
		fmt.Fprintln(sh.out, sh.c.Red("   "+sanitizeTerminal(err.Error())))
		fmt.Fprintln(sh.out, sh.c.Yellow("   The session cannot continue; reconnect to carry on."))
		return
	}

	sh.log.Event("Shell lost; a new shell was opened and session state was discarded")
	if sh.json {
		_ = output.RenderEvent(sh.out, "shell_recovered", lostMsg, true)
		// The new runspace starts wherever the target puts it; keep the cached
		// prompt path honest even though json mode never prints it.
		sh.refreshCwd(ctx)
		return
	}

	fmt.Fprintln(sh.out, sh.c.Red("Error: the target no longer has this shell (it was restarted or timed out)."))
	fmt.Fprintln(sh.out, sh.c.Yellow("   A new shell has been opened."))
	fmt.Fprintln(sh.out, sh.c.Yellow("   Session state was LOST: working directory, variables, functions,"))
	fmt.Fprintln(sh.out, sh.c.Yellow("   any -s scripts, and any bypass-4msi patch. Re-load what you need."))

	// The new runspace starts wherever the target puts it, so the cached prompt
	// path is now a lie. Refresh it rather than leaving the operator to believe
	// they are still in the directory they cd'd to.
	sh.refreshCwd(ctx)
}
