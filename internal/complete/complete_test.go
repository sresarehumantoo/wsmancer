package complete

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAnalyzePicksTheRightSide(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		pos    int // -1 means end of line
		target Target
		word   string
	}{
		{"first word", "upl", -1, TargetVerb, "upl"},
		{"empty line", "", 0, TargetVerb, ""},
		{"upload arg1 is local", "upload /et", -1, TargetLocal, "/et"},
		{"upload arg2 is remote", `upload /etc/hosts C:\te`, -1, TargetRemote, `C:\te`},
		{"download arg1 is remote", `download C:\Wind`, -1, TargetRemote, `C:\Wind`},
		{"download arg2 is local", `download C:\hosts /tm`, -1, TargetLocal, "/tm"},
		{"new word after space", "upload ", -1, TargetLocal, ""},
		{"third upload arg has no target", "upload a b c", -1, TargetNone, "c"},
		{"third download arg has no target", "download a b c", -1, TargetNone, "c"},
		// Any other command runs on the target, so its path arguments are remote.
		{"arbitrary command arg is remote", `dir C:\Wind`, -1, TargetRemote, `C:\Wind`},
		{"type arg is remote", `type .\notes`, -1, TargetRemote, `.\notes`},
		{"unknown verb arg is remote", "Get-Content foo", -1, TargetRemote, "foo"},
		// A path-shaped first word is an executable on the target, not a verb.
		{"dot-slash first word is remote", `.\mimi`, -1, TargetRemote, `.\mimi`},
		{"drive path first word is remote", `C:\tools\x`, -1, TargetRemote, `C:\tools\x`},
		{"bare drive first word is remote", `C:`, -1, TargetRemote, `C:`},
		// A plain first word is still a command name, offered the built-in verbs.
		{"plain first word is a verb", "Get-Pro", -1, TargetVerb, "Get-Pro"},
		{"quoted local path", `upload "my fi`, -1, TargetLocal, "my fi"},
		// invoke-binary's exe (arg 1) is a local assembly; its own arguments are
		// not completable paths.
		{"invoke-binary exe is executable", "invoke-binary Rub", -1, TargetExecutable, "Rub"},
		{"invoke-binary arg has no target", "invoke-binary Rubeus.exe kerb", -1, TargetNone, "kerb"},
		// donut-loader's shellcode is local, and which word holds it is decided
		// by the preceding flag rather than by position.
		{"donut flag completes as an option", "donut-loader -pro", -1, TargetOptions, "-pro"},
		{"donut empty first arg offers flags", "donut-loader ", -1, TargetOptions, ""},
		{"donut empty arg after a pair offers flags", "donut-loader -process_id 1234 ", -1, TargetOptions, ""},
		{"donut positional empty file arg is local", "donut-loader 1234 ", -1, TargetLocal, ""},
		{"donut pid has no target", "donut-loader -process_id 12", -1, TargetNone, "12"},
		{"donut second flag completes", "donut-loader -process_id 1234 -don", -1, TargetOptions, "-don"},
		{"donutfile is local", "donut-loader -process_id 1234 -donutfile /opt/d", -1, TargetLocal, "/opt/d"},
		{"donutfile is local whatever the flag order", "donut-loader -donutfile /opt/d", -1, TargetLocal, "/opt/d"},
		{"donut positional file is local", "donut-loader 1234 /opt/d", -1, TargetLocal, "/opt/d"},
		{"donut positional pid has no target", "donut-loader 12", -1, TargetNone, "12"},
		// The cursor may sit before the end of the line.
		{"cursor mid-line", "upload /etc/hosts", 10, TargetLocal, "/et"},
	}
	for _, c := range cases {
		pos := c.pos
		if pos < 0 {
			pos = len(c.line)
		}
		got := Analyze(c.line, pos)
		if got.Target != c.target || got.Word != c.word {
			t.Errorf("%s: Analyze(%q,%d) = target %v word %q, want target %v word %q",
				c.name, c.line, pos, got.Target, got.Word, c.target, c.word)
		}
	}
}

// WordStart must point at the start of the word being replaced, including its
// opening quote, or completing a quoted path corrupts the line.
func TestAnalyzeWordStart(t *testing.T) {
	line := `upload "my fi`
	got := Analyze(line, len(line))
	if got.WordStart != 7 {
		t.Errorf("WordStart = %d, want 7 (the opening quote)", got.WordStart)
	}
	if head := line[:got.WordStart]; head != "upload " {
		t.Errorf("head = %q, want %q", head, "upload ")
	}
}

func TestTokenizeOffsets(t *testing.T) {
	toks := Tokenize(`upload "a b" c`)
	if len(toks) != 3 {
		t.Fatalf("got %d tokens: %#v", len(toks), toks)
	}
	if toks[1].Text != "a b" || toks[1].Start != 7 {
		t.Errorf("token 1 = %#v, want text %q start 7", toks[1], "a b")
	}
	if toks[2].Text != "c" || toks[2].Start != 13 {
		t.Errorf("token 2 = %#v, want text %q start 13", toks[2], "c")
	}
}

func TestLocalPaths(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"alpha.txt", "alp2.txt", "beta.txt", ".hidden"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := LocalPaths(dir + "/alp")
	want := []string{dir + "/alp2.txt", dir + "/alpha.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prefix match = %#v, want %#v", got, want)
	}

	// Directories are suffixed so the next Tab descends.
	got = LocalPaths(dir + "/sub")
	if len(got) != 1 || got[0] != dir+"/subdir"+string(filepath.Separator) {
		t.Errorf("directory completion = %#v, want trailing separator", got)
	}

	// Hidden entries only when explicitly requested.
	for _, c := range LocalPaths(dir + "/") {
		if filepath.Base(c) == ".hidden" {
			t.Error("hidden file offered without a leading dot")
		}
	}
	if got := LocalPaths(dir + "/.h"); len(got) != 1 {
		t.Errorf("explicit dot prefix should offer .hidden, got %#v", got)
	}
}

type fakeLister struct {
	entries []Entry
	err     error
	gotDir  string
}

func (f *fakeLister) ListDir(_ context.Context, dir string) ([]Entry, error) {
	f.gotDir = dir
	return f.entries, f.err
}

func TestRemotePaths(t *testing.T) {
	l := &fakeLister{entries: []Entry{
		{Name: "Windows", IsDir: true},
		{Name: "winhlp32.exe"},
		{Name: "Users", IsDir: true},
	}}
	// Windows paths are case-insensitive, so a lowercase prefix must match.
	got := RemotePaths(context.Background(), l, `C:\win`)
	want := []string{`C:\Windows\`, `C:\winhlp32.exe`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if l.gotDir != `C:\` {
		t.Errorf("listed %q, want %q", l.gotDir, `C:\`)
	}

	// A bare word lists the current remote location.
	RemotePaths(context.Background(), l, "Doc")
	if l.gotDir != "" {
		t.Errorf("bare word listed %q, want the current location (empty)", l.gotDir)
	}

	// Tab must never surface an error or hang the prompt.
	bad := &fakeLister{err: errors.New("boom")}
	if got := RemotePaths(context.Background(), bad, "x"); got != nil {
		t.Errorf("failed listing should yield no candidates, got %#v", got)
	}
	if got := RemotePaths(context.Background(), nil, "x"); got != nil {
		t.Errorf("nil lister should yield no candidates, got %#v", got)
	}
}

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"plain.txt":         "plain.txt",
		"with space.txt":    `"with space.txt"`,
		`C:\Program Files\`: `"C:\Program Files\"`,
	}
	for in, want := range cases {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}

// A path Tab inserts must parse back to exactly one argument.
func TestQuotedCompletionRoundTrips(t *testing.T) {
	quoted := Quote("my file.txt")
	toks := Tokenize("upload " + quoted)
	if len(toks) != 2 || toks[1].Text != "my file.txt" {
		t.Errorf("round trip of %q gave %#v", quoted, toks)
	}
}

// The option site must actually carry the flag names, and they must narrow the
// way a prefix is expected to.
func TestDonutOptionCandidates(t *testing.T) {
	line := "donut-loader -pro"
	got := Analyze(line, len(line))
	if got.Target != TargetOptions {
		t.Fatalf("Target = %v, want TargetOptions", got.Target)
	}
	cands := Verbs(got.Word, got.Options)
	if len(cands) != 1 || cands[0] != "-process_id" {
		t.Errorf("Verbs(%q, %v) = %v, want [-process_id]", got.Word, got.Options, cands)
	}
	// An empty word offers both, sorted.
	empty := Analyze("donut-loader ", len("donut-loader "))
	if all := Verbs(empty.Word, empty.Options); len(all) != 2 || all[0] != "-donutfile" {
		t.Errorf("empty-word options = %v, want [-donutfile -process_id]", all)
	}
}

// A space inside an open quote belongs to the word, not to the separator. Before
// this was handled, `donut-loader -donutfile "/opt/my ` resolved to the flag-name
// site and Tab inserted a flag into the middle of the path.
func TestOpenQuoteKeepsTheWord(t *testing.T) {
	cases := []struct {
		line   string
		target Target
		word   string
	}{
		{`donut-loader -donutfile "/opt/my `, TargetLocal, "/opt/my "},
		{`upload "/opt/my `, TargetLocal, "/opt/my "},
		{`download "C:\Program Files\`, TargetRemote, `C:\Program Files\`},
	}
	for _, c := range cases {
		got := Analyze(c.line, len(c.line))
		if got.Target != c.target || got.Word != c.word {
			t.Errorf("Analyze(%q) = target %v word %q, want target %v word %q",
				c.line, got.Target, got.Word, c.target, c.word)
		}
		// The replacement span must start at the opening quote, so accepting a
		// candidate rewrites the path instead of appending to it.
		if c.line[got.WordStart] != '"' {
			t.Errorf("Analyze(%q) WordStart=%d points at %q, want the opening quote",
				c.line, got.WordStart, c.line[got.WordStart])
		}
	}
}
