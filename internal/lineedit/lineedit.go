// Package lineedit provides the shell's line reader.
//
// On a terminal it wraps reeflective/readline, which gives emacs-style editing,
// arrow-key history, zsh-style inline autosuggestion ("ghost text") and a
// colored prompt. Elsewhere, piped stdin, a redirected file, a test, it falls
// back to plain line reading so scripted use behaves exactly as before.
//
// The terminal editor has to satisfy one non-negotiable constraint: it must
// enter raw mode only for the duration of a single read and restore the terminal
// (including termios ISIG) on return. That way, while a command is running the
// terminal is back in its normal mode, so Ctrl-C raises a real SIGINT and the
// shell's cancel-the-command handler still works. A library that held raw mode
// for its whole lifetime would swallow that. This was verified in reeflective's
// source before adopting it, and must be re-verified after any dependency bump.
package lineedit

import (
	"bufio"
	"errors"
	"io"
	"os"
)

// ErrInterrupted is returned when Ctrl-C is pressed at the prompt. The caller
// should discard the line and print a fresh prompt, not exit.
var ErrInterrupted = errors.New("interrupted")

// History is the opt-in persistent store, declared here as an interface so this
// package states what it needs without importing internal/history, and so the
// four-method shape reeflective requires is satisfied by the same type.
//
// A nil History means the shipped default: memory only, nothing on disk.
type History interface {
	Write(line string) (int, error)
	GetLine(pos int) (string, error)
	Len() int
	Dump() interface{}
}

// WordCompleter is the completion contract: given the line and cursor position,
// return the text before the word, the candidate words, and the text after. The
// explicit (head, candidates, tail) split is what internal/complete produces;
// reeflective's own model is reached through the adapter in reeflective.go.
type WordCompleter func(line string, pos int) (head string, completions []string, tail string)

type Editor interface {
	// Prompt displays p and reads a line. Returns ErrInterrupted on Ctrl-C and
	// io.EOF on Ctrl-D or end of input.
	Prompt(p string) (string, error)
	// Interactive reports whether real line editing is active.
	Interactive() bool
	Close() error
}

// New returns a terminal line editor when stdin and stdout are both terminals
// and the terminal looks capable, and a plain reader otherwise.
//
// hist is the opt-in persistent store, or nil for the shipped memory-only
// behavior. The terminal editor honours it; the plain reader has no history at
// all, so a piped session records nothing either way.
func New(stdin io.Reader, stdout io.Writer, completer WordCompleter, hist History) Editor {
	if isTerminal(stdin) && isTerminal(stdout) && !preferPlain() {
		return newReeflectiveEditor(completer, hist)
	}
	sc := bufio.NewScanner(stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return &plainEditor{sc: sc, out: stdout}
}

// preferPlain reports whether to use the plain reader even though stdin and
// stdout are character devices.
//
// The char-device test alone is not enough, and the failure it misses is severe
// rather than cosmetic. reeflective asks the terminal where the cursor is
// (ESC[6n) and waits for the reply on os.Stdin with no timeout, its only guard
// is that stdin is a tty. A tty that never answers therefore blocks the editor
// forever, at startup, with the prompt already printed: the shell looks hung in
// exactly the way a dead transport looks hung, which is the most expensive way
// for this tool to fail on an operator. dumbterm_test.go reproduces it.
//
// Two escapes, because no single check covers the case:
//
//   - TERM empty or "dumb" is the declared-incapable terminal, and matches how
//     reeflective itself decides a terminal has no effects (its
//     internal/color.HasEffects), though note it still issues the query on a
//     dumb TERM, which is why this has to be decided here instead.
//   - WSMANCER_EDITOR=plain is the manual override, for the terminal that
//     claims to be capable and is not. That is unfixable by heuristic: the query
//     has to be sent to discover the answer, and by then it is too late. The
//     name is deliberately the one the liner fallback used, so anything that
//     already sets it keeps working.
func preferPlain() bool {
	if os.Getenv("WSMANCER_EDITOR") == "plain" {
		return true
	}
	switch os.Getenv("TERM") {
	case "", "dumb":
		return true
	}
	return false
}

func isTerminal(f interface{}) bool {
	file, ok := f.(*os.File)
	if !ok {
		return false
	}
	st, err := file.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// plainEditor reads lines with no editing, for pipes and scripts.
type plainEditor struct {
	sc  *bufio.Scanner
	out io.Writer
}

func (e *plainEditor) Prompt(p string) (string, error) {
	if p != "" {
		if _, err := io.WriteString(e.out, p); err != nil {
			return "", err
		}
	}
	if !e.sc.Scan() {
		if err := e.sc.Err(); err != nil {
			return "", err
		}
		return "", io.EOF
	}
	return e.sc.Text(), nil
}

func (e *plainEditor) Interactive() bool { return false }
func (e *plainEditor) Close() error      { return nil }
