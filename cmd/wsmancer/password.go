package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"

	"golang.org/x/term"
)

// promptPassword asks for a password on the terminal, with echo off.
//
// It is the last resort, after -p and $WSMANCER_PASSWORD: a password on the
// command line is visible in ps output and lands in shell history, so being
// able to leave it off matters. Upstream evil-winrm prompts the same way.
//
// Three details:
//   - the prompt goes to stderr, never stdout. Under -o json stdout is a
//     machine-readable stream and a prompt written into it would corrupt the
//     first object.
//   - it prompts only when stdin is a terminal. Piped or scripted use (which is
//     what -x exists for) must fail with the "no credentials" error rather than
//     block forever on a read nobody is there to answer.
//   - Ctrl-C at the prompt restores the terminal before exiting. Go kills the
//     process on SIGINT by default, which would skip ReadPassword's own restore
//     and leave the operator's shell with echo off, the sort of thing that
//     makes a tool feel broken long after it has exited.
func promptPassword(stdin *os.File, stderr io.Writer) (string, bool) {
	fd := int(stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", false
	}
	state, err := term.GetState(fd)
	if err != nil {
		return "", false
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	done := make(chan struct{})
	go func() {
		select {
		case <-sigs:
			_ = term.Restore(fd, state)
			fmt.Fprintln(stderr)
			os.Exit(130) // 128+SIGINT, what a shell reports for an interrupt
		case <-done:
		}
	}()
	defer func() {
		close(done)
		signal.Stop(sigs)
	}()

	fmt.Fprint(stderr, "Enter Password: ")
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return "", false
	}
	return string(pw), true
}
