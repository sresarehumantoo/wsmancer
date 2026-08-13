package lineedit

import (
	"errors"
	"io"
	"strings"

	"github.com/reeflective/readline"
	"github.com/reeflective/readline/inputrc"
)

// reeflectiveEditor is the terminal line editor, built on
// github.com/reeflective/readline. It preserves the source-verified Ctrl-C
// invariant (per-read raw mode, so SIGINT reaches the shell's handler between
// reads) and adapts our path/command completion into reeflective's model.
//
// The two things it does that peterh/liner, the editor it replaced, could not:
//   - zsh-style inline autosuggestion ("ghost text") from history, enabled here
//     via the history-autosuggest inputrc var;
//   - a colored prompt (liner rejected control runes in the prompt string).
//
// The Ctrl-C invariant the shell depends on holds because Readline() enters raw
// mode only for the duration of the call (MakeRaw on entry, deferred Restore on
// return) and installs no SIGINT handler, so Ctrl-C while a remote command runs
// (outside Readline) reaches the shell's own handler. Ctrl-C at the prompt comes
// back as readline.ErrInterrupt, which we map to ErrInterrupted.
type reeflectiveEditor struct {
	rl     *readline.Shell
	prompt string
}

// newReeflectiveEditor builds the reeflective-backed editor, wiring the shell's
// WordCompleter through an adapter and turning on inline autosuggestion.
func newReeflectiveEditor(completer WordCompleter, hist History) *reeflectiveEditor {
	rl := readline.NewShell()

	// Opt-in persistence. Add replaces reeflective's default in-memory source
	// while it is the only one, so this becomes THE history: Up-arrow, Ctrl-R
	// and the ghost text all read the persisted lines, and the library writes
	// every accepted line back through the store, which is exactly why the
	// leading-space filter lives in the store and not in the shell. With no
	// store registered the default in-memory source stands and nothing is
	// written to disk, which remains the shipped behavior.
	if hist != nil {
		rl.History.Add("wsmancer", hist)
	}

	// The ghost text: as-you-type suggestion drawn from the in-memory history.
	rl.Config.Vars["history-autosuggest"] = true
	// Windows paths are case-insensitive, and our remote/local completers match
	// case-insensitively, so reeflective must too, otherwise a candidate whose
	// case differs from what was typed (C:\Users vs c:\users) gets filtered out.
	rl.Config.Vars["completion-ignore-case"] = true
	bindCtrlEAcceptsSuggestion(rl)

	e := &reeflectiveEditor{rl: rl}

	// A dynamic primary prompt: Prompt(p) stores the string, the callback
	// returns it. reeflective renders ANSI in the prompt, so the caller's
	// colored prompt is honoured.
	rl.Prompt.Primary(func() string { return e.prompt })

	if completer != nil {
		rl.Completer = adaptCompleter(completer)
	}
	return e
}

// emacsKeymap is the keymap name whose binds we amend; the editor runs in emacs
// mode (reeflective's own default, and what the shell's help advertises).
const emacsKeymap = "emacs"

// bindCtrlEAcceptsSuggestion makes Ctrl-E accept the inline autosuggestion in
// addition to moving to end of line, zsh-autosuggestions behaves this way
// (end-of-line is one of its accept widgets), and an operator coming from zsh
// expects the ghost text to be taken without reaching for an arrow key.
//
// It cannot be a plain rebind. Only reeflective's forward-char accepts the
// suggestion (via autosuggestAccept, when the cursor is at the end of the line);
// end-of-line just moves the cursor, and autosuggest-accept on its own does
// nothing at all when no suggestion is pending, which would cost us end-of-line
// in the common case. So bind Ctrl-E to a *macro*, reeflective re-feeds a
// macro's key sequence through the keymap, expanding to End then Right:
// end-of-line first, then forward-char at the end of the line, which is exactly
// the accept path. With no suggestion pending the trailing Right has nowhere to
// go and is a no-op, so plain end-of-line is unchanged.
func bindCtrlEAcceptsSuggestion(rl *readline.Shell) {
	binds, ok := rl.Config.Binds[emacsKeymap]
	if !ok {
		return // no emacs keymap to amend; leave the defaults alone
	}
	binds[inputrc.Unescape(`\C-e`)] = inputrc.Bind{Action: `\e[F\e[C`, Macro: true}
}

// adaptCompleter bridges the shell's WordCompleter, which returns an explicit
// (head, candidates, tail) split, with candidates already shell-quoted, onto
// reeflective's model, where the completer returns candidate values and the
// engine matches/inserts them itself.
//
// Two mismatches to reconcile. First, reeflective's cursor is a rune index but
// the WordCompleter (via complete.Analyze) works in byte offsets, so convert.
// Second, and more important, reeflective would otherwise re-tokenise the line
// with shell rules that treat `\` as an escape, wrong for the Windows paths we
// complete (`C:\Users\…`, `.\bin.exe`). So we set Completions.PREFIX explicitly
// to the already-typed word (the span the WordCompleter would replace), which
// overrides reeflective's tokeniser, and let it prefix-match/insert against that.
//
// Candidates are passed as the shell completer produced them, except for the
// whitespace case handled by requoteAfter below.
func adaptCompleter(wc WordCompleter) func(line []rune, cursor int) readline.Completions {
	return func(line []rune, cursor int) readline.Completions {
		if cursor > len(line) {
			cursor = len(line)
		}
		s := string(line)
		bytePos := len(string(line[:cursor])) // rune index -> byte offset
		head, cands, _ := wc(s, bytePos)
		word := ""
		if len(head) <= bytePos && bytePos <= len(s) {
			word = s[len(head):bytePos] // the span reeflective must replace
		}
		for i, c := range cands {
			cands[i] = requoteAfter(word, c)
		}
		comps := readline.CompleteValues(cands...)
		comps.PREFIX = word
		return comps
	}
}

// requoteAfter rewrites a shell-quoted candidate so it still begins with the
// literal text the user has typed.
//
// The shell completer quotes a whitespace-bearing path by wrapping the whole
// value, `"C:\My Files\"`. reeflective keeps only candidates that literally
// prefix-match the typed word and inserts them verbatim (engine.acceptCandidate
// deletes exactly len(PREFIX) bytes and writes the value in full), so a value
// starting with `"` never matches an unquoted `C:\My` and the path simply cannot
// be completed. That was this editor's one functional gap next to liner, which
// replaced the whole word span and so never had to prefix-match.
//
// The fix leans on our tokenizer accepting a quote that opens *mid-token*
// (complete.Tokenize toggles quote state wherever it finds the quote rune, and
// drops it from the token text). So quoting after the typed prefix,
// `C:\My" Files\"`, parses back to exactly `C:\My Files\` while still starting
// with the literal `C:\My`. Both constraints satisfied, no custom Tab handler
// and no change to the WordCompleter contract liner shares.
//
// Only the unquoted-typed-word case needs rewriting: if the user already opened
// a quote, the conventional whole-value form starts with that quote and matches
// as-is. A candidate that doesn't extend the typed word is left alone (it would
// be filtered out anyway, which is the correct-or-absent behavior).
func requoteAfter(word, cand string) string {
	if len(cand) < 2 || cand[0] != '"' || cand[len(cand)-1] != '"' {
		return cand // not whole-value quoted: nothing to do
	}
	if strings.ContainsAny(word, `"'`) {
		return cand // the typed span already opened a quote; it matches already
	}
	inner := strings.ReplaceAll(cand[1:len(cand)-1], `\"`, `"`)
	if !strings.HasPrefix(inner, word) {
		return cand
	}
	rest := strings.ReplaceAll(inner[len(word):], `"`, `\"`)
	return word + `"` + rest + `"`
}

// Prompt displays p and reads a line, mapping reeflective's return conventions
// onto the Editor contract: Ctrl-C -> ErrInterrupted, Ctrl-D/EOF -> io.EOF.
func (e *reeflectiveEditor) Prompt(p string) (string, error) {
	e.prompt = p
	line, err := e.rl.Readline()
	switch {
	case errors.Is(err, readline.ErrInterrupt):
		return "", ErrInterrupted
	case errors.Is(err, io.EOF):
		return "", io.EOF
	case err != nil:
		return "", err
	}
	return line, nil
}

// The shell never records history itself: reeflective auto-saves accepted lines
// to whichever source is registered (its in-memory default, or the opt-in store
// from -Y), with consecutive-dedup, and does not save a line that came back from
// Readline with an error (Ctrl-C/D). That is exactly the semantics the shell
// wants, and without -Y it keeps history off disk.

func (e *reeflectiveEditor) Interactive() bool { return true }

func (e *reeflectiveEditor) Close() error { return nil }
