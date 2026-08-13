// Package complete implements tab completion for the shell.
//
// Completion is context-sensitive: `upload` takes a local path then a remote
// one, `download` the reverse, so the same Tab press has to consult either the
// local filesystem or the target depending on which argument the cursor is in.
package complete

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RemoteLister lists names in a directory on the target. dir is empty for the
// shell's current location.
type RemoteLister interface {
	ListDir(ctx context.Context, dir string) ([]Entry, error)
}

type Entry struct {
	Name  string
	IsDir bool
}

// Token is one shell word with its position in the line.
type Token struct {
	Text  string
	Start int // byte offset of the token (of its opening quote, if quoted)
	End   int
	Quote rune // 0 if unquoted
}

// Tokenize splits a line the way the shell's argument parser does, but keeps
// offsets so a completer can replace just the word under the cursor.
func Tokenize(line string) []Token {
	toks, _ := tokenize(line)
	return toks
}

// tokenize also reports whether the line ends inside an unterminated quote. A
// space inside a quote is part of the word, not a separator, so a completer that
// judged "new word" from the trailing byte alone would abandon the path the
// operator is halfway through typing, `upload "/opt/my file` is exactly the
// whitespace-path case this shell supports.
func tokenize(line string) ([]Token, bool) {
	var toks []Token
	var cur strings.Builder
	var quote rune
	start := -1
	flush := func(end int) {
		if start >= 0 {
			toks = append(toks, Token{Text: cur.String(), Start: start, End: end, Quote: quote})
			cur.Reset()
			start = -1
			quote = 0
		}
	}
	for i, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0 // stays part of the same token
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			if start < 0 {
				start = i
			}
			quote = r
		case r == ' ' || r == '\t':
			flush(i)
		default:
			if start < 0 {
				start = i
			}
			cur.WriteRune(r)
		}
	}
	open := quote != 0
	flush(len(line))
	return toks, open
}

// Target says what the word under the cursor should be completed against.
type Target int

const (
	TargetNone Target = iota
	TargetVerb
	TargetLocal
	TargetRemote
	// TargetExecutable is the local .NET assembly argument of invoke-binary. The
	// shell resolves it against -e/--executables (or the local filesystem), which
	// this package has no knowledge of, so it is handled there rather than here.
	TargetExecutable
	// TargetOptions completes against a fixed set of literal words carried in
	// Context.Options, a command's own flag names, where a filesystem has
	// nothing to offer.
	TargetOptions
	// TargetPSNative defers to PowerShell's own completion engine on the target
	// (TabExpansion2). It is used only where a filesystem listing is the wrong
	// answer and PowerShell knows the right one: a parameter name (`-Na`) or a
	// parameter's value (`-Name con`). Paths deliberately stay on TargetRemote,
	// that path is proven, and its quoting is tuned to what the editor needs.
	TargetPSNative
)

// Context describes the completion site: which word is being completed, where it
// starts, and what it should be completed against.
type Context struct {
	Target    Target
	Word      string   // text of the word so far (quotes removed)
	WordStart int      // byte offset to replace from
	Options   []string // candidates for TargetOptions
}

// Analyze decides what to complete at pos.
func Analyze(line string, pos int) Context {
	if pos > len(line) {
		pos = len(line)
	}
	head := line[:pos]
	toks, openQuote := tokenize(head)

	// If the cursor sits right after whitespace, we are starting a new word,
	// unless that whitespace is inside a quote, where it belongs to the word.
	atNewWord := !openQuote && (pos == 0 || head[pos-1] == ' ' || head[pos-1] == '\t')

	word, wordStart, argIndex := "", pos, len(toks)
	if !atNewWord && len(toks) > 0 {
		last := toks[len(toks)-1]
		word, wordStart, argIndex = last.Text, last.Start, len(toks)-1
	}

	if argIndex == 0 {
		// The first word is normally a command name, so it completes against the
		// built-in verbs. But operators routinely launch something on the target
		// by path, `.\mimikatz.exe`, `C:\tools\x.exe`, and that path lives on
		// the remote box, so a path-shaped first word completes there instead.
		if looksLikeRemotePath(word) {
			return Context{Target: TargetRemote, Word: word, WordStart: wordStart}
		}
		return Context{Target: TargetVerb, Word: word, WordStart: wordStart}
	}
	verb := strings.ToLower(toks[0].Text)
	// Everything except the local side of upload/download is a command that runs
	// on the target, so its path arguments are completed against the remote
	// filesystem, `dir C:\`, `type .\notes.txt`, `.\bin -Path C:\...` all work.
	target := TargetRemote
	var options []string
	switch verb {
	case "upload":
		// upload <local> <remote>
		switch argIndex {
		case 1:
			target = TargetLocal
		case 2:
			target = TargetRemote
		default:
			target = TargetNone
		}
	case "download":
		// download <remote> <local>
		switch argIndex {
		case 1:
			target = TargetRemote
		case 2:
			target = TargetLocal
		default:
			target = TargetNone
		}
	case "invoke-binary":
		// invoke-binary <local exe> [args]: only arg 1 is a path (a local one);
		// the assembly's own arguments aren't completable.
		if argIndex == 1 {
			target = TargetExecutable
		} else {
			target = TargetNone
		}
	default:
		// An arbitrary PowerShell command. Its *path* arguments stay on
		// TargetRemote, but a parameter name or a parameter's value has nothing
		// to do with the filesystem, completing `-Na` against a directory
		// listing yields nothing at all, which is what it did before.
		target = psNativeOrRemote(word, toks, argIndex)
	case "donut-loader":
		// donut-loader -process_id <pid> -donutfile <local .bin>. The shellcode
		// is a *local* file, and which word holds it is decided by the preceding
		// flag rather than by position, except in the positional shorthand
		// `donut-loader <pid> <file>`, where it is the second argument. A pid has
		// nothing to complete against; the flag names complete themselves.
		prev := strings.ToLower(toks[argIndex-1].Text)
		// The first argument decides which form is being typed, so an empty word
		// can still be answered: nothing typed yet (or a flag first) means flags
		// are expected, a bare pid first means the positional form.
		flagForm := len(toks) < 2 || strings.HasPrefix(toks[1].Text, "-")
		switch {
		case !flagForm:
			if argIndex == 2 {
				target = TargetLocal
			} else {
				target = TargetNone
			}
		case prev == "-donutfile":
			target = TargetLocal
		case strings.HasPrefix(prev, "-"):
			target = TargetNone // the pid after -process_id
		case argIndex == 1 || argIndex == 3:
			// The only two flag positions. Past them the command is already
			// complete, and offering a third flag would build a line
			// parseDonutArgs rejects.
			// Copied: the shell's completion adapter rewrites candidate slices
			// in place when it requotes them.
			options = append([]string(nil), donutFlags...)
			target = TargetOptions
		default:
			target = TargetNone
		}
	}
	return Context{Target: target, Word: word, WordStart: wordStart, Options: options}
}

// psNativeOrRemote decides, for a command that runs on the target, whether the
// word under the cursor is something PowerShell should complete rather than the
// filesystem.
//
// A word starting with "-" is a parameter name. A word *following* a parameter
// is that parameter's value, process names, service names, enum members,
// unless it looks like a path, in which case the existing remote-path completion
// handles it, quoting and all.
func psNativeOrRemote(word string, toks []Token, argIndex int) Target {
	if looksLikeRemotePath(word) {
		return TargetRemote
	}
	if strings.HasPrefix(word, "-") {
		return TargetPSNative
	}
	if argIndex >= 1 && argIndex-1 < len(toks) && strings.HasPrefix(toks[argIndex-1].Text, "-") {
		return TargetPSNative
	}
	return TargetRemote
}

// donutFlags are donut-loader's parameter names, offered when the operator
// starts typing a flag. They match upstream evil-winrm's spelling so muscle
// memory carries over.
var donutFlags = []string{"-donutfile", "-process_id"}

// looksLikeRemotePath reports whether a first word is being typed as a path to
// something on the target (`.\x`, `..\x`, `\x`, `C:\x`, or a bare drive `C:`)
// rather than as a command name. A plain name with no separator or drive letter
// is treated as a command and offered the built-in verbs.
func looksLikeRemotePath(w string) bool {
	if strings.ContainsAny(w, `\/`) {
		return true
	}
	// Drive-qualified before the separator is typed, e.g. "C:".
	if len(w) >= 2 && w[1] == ':' &&
		((w[0] >= 'A' && w[0] <= 'Z') || (w[0] >= 'a' && w[0] <= 'z')) {
		return true
	}
	return false
}

// Verbs completes command names: the built-ins plus any dynamic candidates
// (loaded functions, script names). Matching is case-insensitive, PowerShell is,
// and a loaded function like Get-Foo must complete from "get-f", while the
// candidate's own casing is preserved. Duplicates are collapsed.
func Verbs(word string, verbs []string) []string {
	lw := strings.ToLower(word)
	seen := make(map[string]bool, len(verbs))
	var out []string
	for _, v := range verbs {
		if !strings.HasPrefix(strings.ToLower(v), lw) || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// LocalPaths completes against the local filesystem. Directories come back with
// a trailing separator so the next Tab descends into them.
func LocalPaths(word string) []string {
	dir, base := splitLocal(word)

	readDir := dir
	if readDir == "" {
		readDir = "."
	}
	expanded, err := expandHome(readDir)
	if err != nil {
		return nil
	}
	ents, err := os.ReadDir(expanded)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, base) {
			continue
		}
		// Hidden files only when explicitly asked for.
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".") {
			continue
		}
		full := dir + name
		if e.IsDir() {
			full += string(filepath.Separator)
		}
		out = append(out, full)
	}
	sort.Strings(out)
	return out
}

// RemotePaths completes against the target. Directories get a trailing
// backslash. A failure (or a slow box) yields no completions rather than an
// error, Tab must never break the prompt.
func RemotePaths(ctx context.Context, l RemoteLister, word string) []string {
	if l == nil {
		return nil
	}
	dir, base := splitRemote(word)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ents, err := l.ListDir(ctx, dir)
	if err != nil {
		return nil
	}
	lowerBase := strings.ToLower(base) // Windows paths are case-insensitive
	var out []string
	for _, e := range ents {
		if !strings.HasPrefix(strings.ToLower(e.Name), lowerBase) {
			continue
		}
		full := dir + e.Name
		if e.IsDir {
			full += `\`
		}
		out = append(out, full)
	}
	sort.Strings(out)
	return out
}

// splitLocal splits a local path into the part to keep and the prefix to match.
func splitLocal(word string) (dir, base string) {
	i := strings.LastIndexByte(word, filepath.Separator)
	if i < 0 {
		return "", word
	}
	return word[:i+1], word[i+1:]
}

// splitRemote splits a Windows path, accepting either separator since operators
// type both.
func splitRemote(word string) (dir, base string) {
	i := strings.LastIndexAny(word, `\/`)
	if i < 0 {
		return "", word
	}
	return word[:i+1], word[i+1:]
}

func expandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~"+string(filepath.Separator)) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
	}
	return p, nil
}

// Quote wraps a completion in double quotes if it contains whitespace, so the
// argument survives being re-parsed. An already-quoted word is left alone.
func Quote(s string) string {
	if !strings.ContainsAny(s, " \t") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
