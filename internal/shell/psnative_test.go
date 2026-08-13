package shell

import (
	"slices"
	"testing"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
)

func TestParsePSCompletion(t *testing.T) {
	idx, cands := parsePSCompletion([]string{"I|12", "C|-Name", "C|-Id", "C|-InputObject"})
	if idx != 12 {
		t.Errorf("index = %d, want 12", idx)
	}
	if want := []string{"-Name", "-Id", "-InputObject"}; !slices.Equal(cands, want) {
		t.Errorf("cands = %v, want %v", cands, want)
	}
}

// Without a replacement index there is no safe place to splice the candidate, so
// the whole answer must be discarded rather than guessed at.
func TestParsePSCompletionRequiresAnIndex(t *testing.T) {
	if idx, cands := parsePSCompletion([]string{"C|-Name"}); idx != 0 || cands != nil {
		t.Errorf("got (%d, %v), want (0, nil) when no index was reported", idx, cands)
	}
	// Index 0 is legitimate: completing the very start of the line.
	if idx, cands := parsePSCompletion([]string{"I|0", "C|Get-Process"}); idx != 0 || len(cands) != 1 {
		t.Errorf("got (%d, %v), want index 0 with one candidate", idx, cands)
	}
}

func TestParsePSCompletionIgnoresNoise(t *testing.T) {
	idx, cands := parsePSCompletion([]string{"warning text with no pipe", "I|3", "C|-Name", ""})
	if idx != 3 || !slices.Equal(cands, []string{"-Name"}) {
		t.Errorf("got (%d, %v), want (3, [-Name])", idx, cands)
	}
}

// PowerShell hands back text ready to paste, so a value with a space arrives
// already single-quoted. Normalising to the raw value is what lets it flow
// through the same quoting pipeline as every other candidate instead of being
// wrapped a second time.
func TestUnquotePS(t *testing.T) {
	cases := map[string]string{
		`'Windows Update'`:     "Windows Update",
		`'C:\Program Files'`:   `C:\Program Files`,
		`conhost`:              "conhost",
		`-Name`:                "-Name",
		`'it''s'`:              "it's",
		`"quoted"`:             "quoted",
		`'`:                    `'`,
		``:                     ``,
		`'unterminated`:        `'unterminated`,
		`C:\NoSpaces\file.txt`: `C:\NoSpaces\file.txt`,
	}
	for in, want := range cases {
		if got := unquotePS(in); got != want {
			t.Errorf("unquotePS(%q) = %q, want %q", in, got, want)
		}
	}
}

// The cursor and the replacement index cross the wire as character counts, but
// the shell splices by byte offset. They differ the moment a line holds a
// non-ASCII rune, and getting it wrong splices mid-rune.
func TestByteOffsetForRune(t *testing.T) {
	// 'ü' is rune 5 and occupies bytes 5-6, so every rune after it sits one byte
	// further along than its index: rune 6 ('c') is byte 7, and the end of the
	// 14-rune string is byte 15.
	const s = "Ge-Prücess -Na"
	cases := map[int]int{0: 0, 1: 1, 5: 5, 6: 7, 7: 8, 14: 15}
	for runeIdx, want := range cases {
		if got := byteOffsetForRune(s, runeIdx); got != want {
			t.Errorf("byteOffsetForRune(%q, %d) = %d, want %d", s, runeIdx, got, want)
		}
	}
	if got := byteOffsetForRune("abc", 3); got != 3 {
		t.Errorf("end-of-string index = %d, want 3", got)
	}
	for _, bad := range []int{-1, 4, 99} {
		if got := byteOffsetForRune("abc", bad); got != -1 {
			t.Errorf("byteOffsetForRune(abc, %d) = %d, want -1", bad, got)
		}
	}
}

// -N disables remote completion entirely, this site included.
func TestPSCompleteRespectsNoRPath(t *testing.T) {
	sh := cachedShell(optsNoRPath())
	if head, cands := sh.psComplete("Get-Process -", 13); head != 0 || cands != nil {
		t.Errorf("got (%d, %v) with -N, want (0, nil)", head, cands)
	}
}

func optsNoRPath() *cli.Options { return &cli.Options{NoRPath: true} }
