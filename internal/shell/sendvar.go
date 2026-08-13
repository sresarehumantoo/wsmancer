package shell

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sresarehumantoo/wsmancer/internal/output"
)

// scriptChunk is the base64 payload appended per command while streaming a
// payload into a remote variable. It must stay well inside the target's
// MaxEnvelopeSizekb (500KB default) after PSRP framing; 60 KiB leaves ample
// headroom.
const scriptChunk = 60 * 1024

// errPayloadCancelled reports a Ctrl-C during the streaming phase. It wraps
// context.Canceled so that reportErr stays silent: sendB64Var has already told
// the operator what happened, and every caller re-wraps this with %w.
var errPayloadCancelled = fmt.Errorf("canceled before the payload was run: %w", context.Canceled)

// sendB64Var streams a base64 string into a global variable on the target in
// envelope-sized chunks, so a payload larger than one PSRP message (a big script
// or assembly) can be assembled remotely before use. The caller removes the
// variable afterwards.
//
// Ctrl-C aborts the stream between chunks. It deliberately does *not* cancel the
// in-flight chunk's context, for two reasons. A chunk is one small string append,
// so waiting for it costs a single round trip, less than the ~0.74s a
// StopPipelines terminate would cost, and it leaves no abandoned pipeline to
// terminate, which the one-runspace pool would otherwise queue the caller's
// cleanup behind. More importantly, canceling mid-Execute is *undetectable
// here*: the fork returns (result, nil) with "context canceled" as a plain string
// in Result.Errors, so the err check below would see success and, on the last
// chunk, hand the caller a silently truncated payload.
//
// Aborting is always safe: nothing has been executed at this point, the payload
// is only accumulating in a variable, so a cancel costs the upload and nothing
// else. That is exactly what an operator who changes their mind mid-`donut-loader`
// needs.
func (sh *Shell) sendB64Var(ctx context.Context, sigs <-chan os.Signal, name, b64 string) error {
	err := streamB64Var(name, b64, sigs, func(script string) error {
		_, runErr := sh.s.RunRaw(ctx, script)
		return runErr
	})
	if errors.Is(err, errPayloadCancelled) && !sh.json {
		fmt.Fprintln(sh.out, sh.c.Yellow("^C (canceled; nothing was run on the target)"))
	}
	if err != nil {
		return err
	}
	return sh.verifyB64Var(ctx, name, len(b64))
}

// streamB64Var is the chunk loop, split out from the session so it can be tested
// without a live target. run sends one command; sigs, when it fires, aborts the
// stream.
//
// The signal is checked *after* each chunk rather than before, so that a Ctrl-C
// arriving during the final chunk is still consumed here. Checking only at the
// top of the loop would leave that signal buffered (the channel has cap 1 and
// nothing drains it between commands) for the next executeAs to pick up, which
// would then terminate a command the operator never meant to stop, the original
// bug this guards against.
func streamB64Var(name, b64 string, sigs <-chan os.Signal, run func(script string) error) error {
	first := true
	for len(b64) > 0 {
		n := scriptChunk
		if n > len(b64) {
			n = len(b64)
		}
		part := b64[:n]
		b64 = b64[n:]
		op := "+="
		if first {
			op = "="
			first = false
		}
		// The base64 alphabet contains no single quote, so quoting is safe.
		if err := run(fmt.Sprintf("$global:%s %s '%s'", name, op, part)); err != nil {
			return err
		}
		select {
		case <-sigs:
			return errPayloadCancelled
		default:
		}
	}
	return nil
}

// verifyB64Var checks that the remote variable holds every character that was
// sent. A dropped or short chunk otherwise surfaces only much later, as a
// base64-decode failure for a script, or, for donut-loader, not at all: a
// truncated shellcode blob is injected and executed just the same. One round trip
// buys the same guarantee the file-transfer path gets from its SHA-256 check.
func (sh *Shell) verifyB64Var(ctx context.Context, name string, want int) error {
	res, err := sh.s.RunRaw(ctx, fmt.Sprintf(`'{0}' -f $global:%s.Length`, name))
	if err != nil {
		return err
	}
	for _, v := range res.Output {
		got, convErr := strconv.Atoi(strings.TrimSpace(output.Text(v)))
		if convErr != nil {
			continue
		}
		if got != want {
			return fmt.Errorf("payload truncated in transit: the target holds %d of %d bytes", got, want)
		}
		return nil
	}
	// An unparseable answer is not treated as failure: better to let the payload
	// run than to block on a quirk of the target's formatting.
	return nil
}
