package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sresarehumantoo/go-psrp/client"
)

// fakeTarget is an in-process stand-in for a WinRM target. It implements the
// transfer.Runner interface by recognising the fixed PowerShell templates that
// transfer.go emits and executing them against an in-memory Windows filesystem.
//
// It exists so the whole upload/download engine, chunking, base64 framing,
// Create-vs-Append semantics, the SHA-256 integrity check, glob expansion and
// the traversal guard, can be exercised without a live box. Everything the real
// target would compute (a file's hash, its length, a directory listing, a
// wildcard match) is computed here for real, so a byte-splicing or truncation
// bug shows up exactly as it would on the wire.
//
// The fake is deliberately case-sensitive on paths (real Windows is not); tests
// keep casing consistent, which keeps the fake simple and its failures legible.
type fakeTarget struct {
	cwd   string
	files map[string][]byte
	dirs  map[string]bool

	// Fault injection, all off by default.
	flipFirstWriteByte bool     // corrupt the first byte of the first chunk written
	truncateWriteTail  int      // drop this many bytes from every chunk written
	fail413            bool     // make every writeChunk fail with an HTTP-413-shaped error
	corruptReadB64     bool     // hand back a valid-but-wrong base64 blob on download
	listOverride       []string // if set, listFiles returns these relative names verbatim

	writes int // count of chunk writes actually applied (for chunk-count assertions)
	reads  int // count of download reads served
}

// putFile seeds a remote file (creating its parent directories) so download and
// glob paths have something to read.
func (f *fakeTarget) putFile(path string, data []byte) {
	path = f.winAbs(path)
	f.mkdirAll(parentDir(path))
	f.files[path] = append([]byte(nil), data...)
}

func newFakeTarget() *fakeTarget {
	f := &fakeTarget{
		cwd:   `C:\Users\test`,
		files: map[string][]byte{},
		dirs:  map[string]bool{},
	}
	f.dirs[`C:`] = true
	f.dirs[`C:\Users`] = true
	f.dirs[`C:\Users\test`] = true
	return f
}

var (
	reB64Arg   = regexp.MustCompile(`FromBase64String\('([^']*)'\)`)
	reOpenPath = regexp.MustCompile(`IO\.File\]::Open\('((?:[^']|'')*)'`)
	reMode     = regexp.MustCompile(`FileMode\]::(\w+)`)
	reResolve  = regexp.MustCompile(`GetUnresolvedProviderPathFromPSPath\('((?:[^']|'')*)'\)`)
	reTestPath = regexp.MustCompile(`Test-Path -LiteralPath '((?:[^']|'')*)'`)
	reVerifyP  = regexp.MustCompile(`\$p='((?:[^']|'')*)'`)
	reOpenRead = regexp.MustCompile(`OpenRead\('((?:[^']|'')*)'\)`)
	reSeek     = regexp.MustCompile(`Seek\((\d+),`)
	reByteLen  = regexp.MustCompile(`byte\[\] (\d+)`)
	reLiteral  = regexp.MustCompile(`Get-Item -LiteralPath '((?:[^']|'')*)'`)
	reGlobPath = regexp.MustCompile(`Get-Item -Path '((?:[^']|'')*)'`)
)

func psUnquote(s string) string { return strings.ReplaceAll(s, "''", "'") }

// RunRaw dispatches on the distinctive shape of each template. Order matters:
// the more specific patterns are tested before the general Get-Item ones.
func (f *fakeTarget) RunRaw(_ context.Context, script string) (*client.Result, error) {
	switch {
	case strings.Contains(script, "FromBase64String") && strings.Contains(script, "IO.File]::Open("):
		return f.writeChunk(script)
	case strings.Contains(script, "GetUnresolvedProviderPathFromPSPath"):
		return f.resolve(script)
	case strings.Contains(script, "Test-Path -LiteralPath") && strings.Contains(script, "New-Item -ItemType Directory"):
		return f.ensureDir(script)
	case strings.Contains(script, "Get-FileHash"):
		return f.verifyHash(script)
	case strings.Contains(script, "IO.File]::OpenRead"):
		return f.readChunk(script)
	case strings.Contains(script, "Get-ChildItem -LiteralPath") && strings.Contains(script, "-Recurse"):
		return f.listFiles(script)
	case strings.Contains(script, "Get-Item -Path") && strings.Contains(script, "PSIsContainer"):
		return f.globItems(script)
	case strings.Contains(script, "Get-Item -LiteralPath") && strings.Contains(script, "PSIsContainer"):
		return f.stat(script)
	}
	return nil, fmt.Errorf("fakeTarget: unrecognised script:\n%s", script)
}

func out(vals ...interface{}) *client.Result { return &client.Result{Output: vals} }

// winAbs resolves a possibly-relative PowerShell path to an absolute, normalized
// one, the way GetUnresolvedProviderPathFromPSPath would: `.` and `..` are
// collapsed and a relative path is rooted at the current location.
func (f *fakeTarget) winAbs(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	var rooted string
	if len(p) >= 2 && p[1] == ':' { // drive-absolute, e.g. C:\...
		rooted = p
	} else {
		rooted = f.cwd + `\` + p
	}
	segs := strings.Split(rooted, `\`)
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		switch s {
		case "", ".":
			// drop empty (collapses doubled separators) and current-dir
		case "..":
			if len(out) > 1 { // never pop past the drive
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
		}
	}
	return strings.Join(out, `\`)
}

func (f *fakeTarget) resolve(script string) (*client.Result, error) {
	m := reResolve.FindStringSubmatch(script)
	if m == nil {
		return nil, errors.New("resolve: no path")
	}
	return out(f.winAbs(psUnquote(m[1]))), nil
}

func (f *fakeTarget) ensureDir(script string) (*client.Result, error) {
	m := reTestPath.FindStringSubmatch(script)
	if m == nil {
		return nil, errors.New("ensureDir: no path")
	}
	f.mkdirAll(f.winAbs(psUnquote(m[1])))
	return out(), nil
}

func (f *fakeTarget) mkdirAll(dir string) {
	segs := strings.Split(dir, `\`)
	for i := 1; i <= len(segs); i++ {
		f.dirs[strings.Join(segs[:i], `\`)] = true
	}
}

func (f *fakeTarget) writeChunk(script string) (*client.Result, error) {
	if f.fail413 {
		return nil, errors.New("the request contained an invalid quota: HTTP 413 Request Entity Too Large")
	}
	pm := reOpenPath.FindStringSubmatch(script)
	bm := reB64Arg.FindStringSubmatch(script)
	mm := reMode.FindStringSubmatch(script)
	if pm == nil || bm == nil || mm == nil {
		return nil, fmt.Errorf("writeChunk: could not parse:\n%s", script)
	}
	path := f.winAbs(psUnquote(pm[1]))
	data, err := base64.StdEncoding.DecodeString(bm[1])
	if err != nil {
		return nil, fmt.Errorf("writeChunk: bad base64: %w", err)
	}
	if f.flipFirstWriteByte && len(data) > 0 {
		data = append([]byte(nil), data...)
		data[0] ^= 0xFF
		f.flipFirstWriteByte = false // corrupt exactly one chunk
	}
	if f.truncateWriteTail > 0 && len(data) > f.truncateWriteTail {
		data = data[:len(data)-f.truncateWriteTail]
	}
	f.mkdirAll(parentDir(path))
	switch mm[1] {
	case "Create":
		f.files[path] = append([]byte(nil), data...) // truncates any existing file
	case "Append":
		f.files[path] = append(f.files[path], data...)
	default:
		return nil, fmt.Errorf("writeChunk: unknown mode %q", mm[1])
	}
	f.writes++
	return out(), nil
}

func (f *fakeTarget) verifyHash(script string) (*client.Result, error) {
	m := reVerifyP.FindStringSubmatch(script)
	if m == nil {
		return nil, errors.New("verify: no path")
	}
	path := f.winAbs(psUnquote(m[1]))
	data, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("verify: no such file %q", path)
	}
	sum := sha256.Sum256(data)
	// Real Get-FileHash returns upper-case hex; the caller compares case-insensitively.
	return out(fmt.Sprintf("%X:%d", sum, len(data))), nil
}

func (f *fakeTarget) readChunk(script string) (*client.Result, error) {
	pm := reOpenRead.FindStringSubmatch(script)
	sm := reSeek.FindStringSubmatch(script)
	nm := reByteLen.FindStringSubmatch(script)
	if pm == nil || sm == nil || nm == nil {
		return nil, fmt.Errorf("readChunk: could not parse:\n%s", script)
	}
	path := f.winAbs(psUnquote(pm[1]))
	data, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("readChunk: no such file %q", path)
	}
	off, _ := strconv.Atoi(sm[1])
	n, _ := strconv.Atoi(nm[1])
	end := off + n
	if end > len(data) {
		end = len(data)
	}
	if off > len(data) {
		off = len(data)
	}
	chunk := data[off:end]
	if f.corruptReadB64 && len(chunk) > 0 {
		chunk = append([]byte(nil), chunk...)
		chunk[0] ^= 0xFF
		f.corruptReadB64 = false
	}
	f.reads++
	return out(base64.StdEncoding.EncodeToString(chunk)), nil
}

func (f *fakeTarget) stat(script string) (*client.Result, error) {
	m := reLiteral.FindStringSubmatch(script)
	if m == nil {
		return nil, errors.New("stat: no path")
	}
	path := f.winAbs(psUnquote(m[1]))
	if f.dirs[path] {
		return out("True:0"), nil
	}
	if data, ok := f.files[path]; ok {
		return out(fmt.Sprintf("False:%d", len(data))), nil
	}
	// Get-Item -ErrorAction Stop on a missing path is a terminating error.
	return nil, fmt.Errorf("Cannot find path '%s' because it does not exist.", path)
}

func (f *fakeTarget) listFiles(script string) (*client.Result, error) {
	m := reLiteral.FindStringSubmatch(script)
	if m == nil {
		return nil, errors.New("listFiles: no path")
	}
	if f.listOverride != nil {
		vals := make([]interface{}, len(f.listOverride))
		for i, r := range f.listOverride {
			vals[i] = r
		}
		return &client.Result{Output: vals}, nil
	}
	root := strings.TrimRight(f.winAbs(psUnquote(m[1])), `\`)
	prefix := root + `\`
	var rels []string
	for p := range f.files {
		if strings.HasPrefix(p, prefix) {
			rels = append(rels, p[len(prefix):])
		}
	}
	sort.Strings(rels)
	vals := make([]interface{}, len(rels))
	for i, r := range rels {
		vals[i] = r
	}
	return &client.Result{Output: vals}, nil
}

// globItems expands a wildcard in the final path segment (the shapes the tests
// and the tool actually use: C:\dir\*, C:\dir\*.txt). It matches both files and
// directories that are immediate children of the pattern's directory.
func (f *fakeTarget) globItems(script string) (*client.Result, error) {
	m := reGlobPath.FindStringSubmatch(script)
	if m == nil {
		return nil, errors.New("glob: no pattern")
	}
	pattern := f.winAbs(psUnquote(m[1]))
	dir := parentDir(pattern)
	last := pattern[len(dir)+1:]
	re := wildcardToRegexp(last)

	type item struct {
		path  string
		isDir bool
	}
	seen := map[string]bool{}
	var items []item
	consider := func(full string, isDir bool) {
		if parentDir(full) != dir {
			return
		}
		name := full[len(dir)+1:]
		if re.MatchString(name) && !seen[full] {
			seen[full] = true
			items = append(items, item{full, isDir})
		}
	}
	for p := range f.files {
		consider(p, false)
	}
	for d := range f.dirs {
		consider(d, true)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].path < items[j].path })
	var vals []interface{}
	for _, it := range items {
		flag := 0
		if it.isDir {
			flag = 1
		}
		vals = append(vals, fmt.Sprintf("%d|%s", flag, it.path))
	}
	return &client.Result{Output: vals}, nil
}

func wildcardToRegexp(pat string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pat {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}
