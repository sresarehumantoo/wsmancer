// Command wsmancer is a Go port of evil-winrm.
//
// Beyond being a single static binary, the reason it exists is -o json: because
// the transport speaks PSRP, command results are real objects, so they can be
// emitted as structured JSON instead of a console table someone has to scrape.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
	"github.com/sresarehumantoo/wsmancer/internal/output"
	"github.com/sresarehumantoo/wsmancer/internal/session"
	"github.com/sresarehumantoo/wsmancer/internal/shell"
)

func main() {
	os.Exit(run())
}

func run() int {
	opts, err := cli.Parse(os.Args[1:], os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wsmancer: %v\n", err)
		return 2
	}
	switch {
	case opts.Help:
		cli.PrintUsage(os.Stdout)
		return 0
	case opts.Version:
		fmt.Println("wsmancer " + cli.Version)
		return 0
	}

	c := output.NewColors(!opts.NoColors && !output.EnvDisablesColor())
	jsonMode := opts.Output == "json"

	// `-x -` reads commands from stdin, so stdin cannot also be the source of an
	// interactively-typed password, the prompt would silently eat the first
	// command. Require the credential up front in that case, with a message that
	// names the fix rather than hanging on a read that will never come.
	if opts.NeedsPassword() {
		if opts.Command == "-" {
			return fail(c, jsonMode, "",
				fmt.Errorf("-x - reads commands from stdin, so a password cannot be prompted; pass -p, -H, or -K"))
		}
		if pw, ok := promptPassword(os.Stdin, os.Stderr); ok {
			opts.Password = pw
		}
	}

	sess, err := session.New(opts)
	if err != nil {
		return fail(c, jsonMode, "", err)
	}

	// Ctrl-C during connect should abort rather than hang on a dead host.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !jsonMode {
		fmt.Fprintf(os.Stderr, "%s %s\n", c.Blue("Info:"), "auth: "+sess.AuthMode())
		via := "connecting to " + sess.Endpoint()
		if sess.ProxyAddr() != "" {
			// Worth a line of its own: the whole failure mode --proxy exists to
			// prevent is a dial quietly going out of the wrong interface, so the
			// operator should be able to see that it did not.
			via += " via socks5 " + sess.ProxyAddr()
		}
		fmt.Fprintf(os.Stderr, "%s %s\n", c.Blue("Info:"), via)
	}
	connCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := sess.Connect(connCtx); err != nil {
		return fail(c, jsonMode, "", fmt.Errorf("connect: %w", err))
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = sess.Close(closeCtx)
	}()

	// One-shot mode: -x is what makes this usable from a script or an agent, so
	// it runs the line through the shell's own dispatch, a built-in behaves
	// exactly as it does interactively, rather than being sent to PowerShell as a
	// cmdlet that does not exist. stop() first for the same reason the
	// interactive shell does it: Ctrl-C must cancel the command (terminating the
	// remote pipeline) instead of the whole session.
	// Batch mode: `-x -` streams commands from stdin through the same dispatch,
	// over this one connection, so an agent or script drives a whole session
	// without re-authenticating per command and the runspace state persists. It
	// runs before the single-command case because "-" is not a command.
	if opts.Command == "-" {
		// context.Background() for the same reason the one-shot uses it, below.
		stop()
		return shell.NewBatch(sess, opts, os.Stdout).Batch(context.Background(), os.Stdin)
	}
	if opts.Command != "" {
		// context.Background(), not ctx: stop() *cancels* the context it returned,
		// so handing ctx on would abort the command before it ran, an empty
		// result and a bare exit 1, which is exactly what it looks like when the
		// target rejects a command. The interactive path below does the same.
		stop()
		return shell.NewOnce(sess, opts, os.Stdout).Once(context.Background(), opts.Command)
	}

	// signal.NotifyContext would cancel the whole session on Ctrl-C; the
	// interactive shell wants per-command cancellation, so hand it a plain ctx.
	stop()
	if err := shell.New(sess, opts, os.Stdin, os.Stdout).Run(context.Background()); err != nil {
		return fail(c, jsonMode, "", err)
	}
	return 0
}

// fail reports in whichever format the caller asked for, so a -o json consumer
// never has to parse prose off stderr.
func fail(c output.Colors, jsonMode bool, cmd string, err error) int {
	if jsonMode {
		_ = output.JSONError(os.Stdout, cmd, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "%s %v\n", c.Red("Error:"), err)
	return 1
}
