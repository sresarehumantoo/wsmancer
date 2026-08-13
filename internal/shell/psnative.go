package shell

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/smnsjas/go-psrp/client"

	"github.com/sresarehumantoo/wsmancer/internal/output"
)

// psCompleteTimeout bounds one TabExpansion2 round trip. Measured at 13-99ms
// warm against a stock Server 2016 box (656ms on the very first call, which
// warms PowerShell's command discovery), so 5s is generous, and it is the same
// budget every other remote completion gets, because the rule is the same: Tab
// must never make the prompt hang.
const psCompleteTimeout = 5 * time.Second

// psCompleteRetry is the back-off after a failure. TabExpansion2 is one of the
// first things a ConstrainedLanguage or JEA endpoint takes away, and on such a
// target every single Tab would otherwise pay the full timeout.
const psCompleteRetry = 30 * time.Second

// psCompleteScript asks PowerShell to complete the line itself. The scriptblock
// scopes $r so the probe leaves nothing behind in the runspace the operator is
// working in.
//
// Output is line-oriented like the other remote listers: one "I|<index>" giving
// the replacement offset PowerShell chose, then one "C|<text>" per candidate.
const psCompleteScript = `& { $r = TabExpansion2 -inputScript %s -cursorColumn %d; ` +
	`if ($r) { 'I|' + $r.ReplacementIndex; foreach ($m in $r.CompletionMatches) { 'C|' + $m.CompletionText } } }`

// psComplete asks the target to complete the line, returning the byte offset the
// replacement starts at and the candidate list.
//
// The offset comes from PowerShell rather than from complete.Analyze: at these
// sites PowerShell's own parser is the authority on where the word begins (it
// understands `-Param`, `$var.`, sub-expressions and quoting), and the editor
// replaces exactly the span between the returned head and the cursor. Disagreeing
// with it would corrupt the line.
//
// Like every completion path it never returns an error, a failure is no
// candidates and an undisturbed prompt.
func (sh *Shell) psComplete(line string, pos int) (int, []string) {
	if sh.s == nil || sh.o == nil || sh.o.NoRPath {
		return 0, nil
	}
	if !sh.psFailedAt.IsZero() && time.Since(sh.psFailedAt) < psCompleteRetry {
		return 0, nil
	}
	if pos > len(line) {
		pos = len(line)
	}
	// TabExpansion2 counts the cursor in characters; pos is a byte offset.
	charPos := utf8.RuneCountInString(line[:pos])

	ctx, cancel := context.WithTimeout(context.Background(), psCompleteTimeout)
	defer cancel()
	res, err := sh.s.RunRaw(ctx, fmt.Sprintf(psCompleteScript, psQuote(line), charPos))
	if err != nil || res == nil {
		sh.psFailedAt = time.Now()
		return 0, nil
	}

	replIdx, cands := parsePSCompletion(collectLines(res))
	if len(cands) == 0 {
		// No candidates is a normal answer (nothing matches), but so is a target
		// that has no TabExpansion2 at all, and only the second should cost a
		// back-off. An error record distinguishes them: RunRaw reports a
		// PowerShell failure as a record, not as a Go error.
		if len(res.Errors) > 0 {
			sh.psFailedAt = time.Now()
		}
		return 0, nil
	}
	sh.psFailedAt = time.Time{}

	// Convert PowerShell's character index back to a byte offset, and refuse an
	// index that would not land inside the line, a head we cannot trust is worse
	// than no completion, because the editor would splice the candidate at the
	// wrong place.
	head := byteOffsetForRune(line, replIdx)
	if head < 0 || head > pos {
		return 0, nil
	}
	return head, cands
}

// collectLines flattens a result's output objects into trimmed lines.
func collectLines(res *client.Result) []string {
	var out []string
	for _, v := range res.Output {
		for _, ln := range strings.Split(output.Text(v), "\n") {
			if s := strings.TrimSpace(ln); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// parsePSCompletion reads the "I|"/"C|" protocol, unquoting each candidate.
func parsePSCompletion(lines []string) (int, []string) {
	replIdx := -1
	var cands []string
	for _, ln := range lines {
		tag, rest, ok := strings.Cut(ln, "|")
		if !ok {
			continue
		}
		switch tag {
		case "I":
			if n, err := strconv.Atoi(rest); err == nil {
				replIdx = n
			}
		case "C":
			if rest != "" {
				cands = append(cands, unquotePS(rest))
			}
		}
	}
	if replIdx < 0 {
		return 0, nil
	}
	return replIdx, cands
}

// unquotePS turns PowerShell's own quoting back into a raw value.
//
// TabExpansion2 returns a CompletionText ready to paste into a command line, so
// a value containing a space arrives single-quoted ('Windows Update'). Left as
// is, the shell would quote it a second time and the tokenizer would parse back
// a different string. Normalising to the raw value here lets it flow through the
// same Quote/requote pipeline as every other candidate, so one quoting rule
// covers the lot.
func unquotePS(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// byteOffsetForRune converts a rune index into a byte offset, or -1 if it is out
// of range.
func byteOffsetForRune(s string, runeIdx int) int {
	if runeIdx < 0 {
		return -1
	}
	if runeIdx == 0 {
		return 0
	}
	n := 0
	for i := range s {
		if n == runeIdx {
			return i
		}
		n++
	}
	if n == runeIdx {
		return len(s)
	}
	return -1
}
