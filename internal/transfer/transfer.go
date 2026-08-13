// Package transfer implements file upload and download over PSRP.
//
// There is no file-transfer channel in WinRM, so bytes ride inside PowerShell
// commands as base64: upload decodes a chunk remotely and appends it to the
// target file, download reads a byte range remotely and returns it base64-encoded.
// Every transfer is verified with a SHA-256 comparison at the end, because a
// silently truncated payload is the failure mode that matters here.
//
// Security note: remote filenames are attacker-controlled if the target is
// hostile. Anything used to build a *local* path is reduced to its base name and
// then checked to be inside the destination directory (see safeLocalPath), the
// Ruby implementation had a path-traversal bug here (fixed in b3bf74b) where
// Get-ChildItem output was joined into local paths directly.
package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/smnsjas/go-psrp/client"

	"github.com/sresarehumantoo/wsmancer/internal/output"
)

// DefaultChunkSize is the raw bytes per round trip. Base64 inflates this by 4/3
// and it must stay well inside the WinRM envelope limit (MaxEnvelopeSizekb,
// 500KB by default), so 192KiB of payload -> ~256KB encoded leaves headroom for
// the script wrapper and PSRP framing.
const DefaultChunkSize = 192 * 1024

// Runner is the subset of a session this package needs.
type Runner interface {
	RunRaw(ctx context.Context, script string) (*client.Result, error)
}

// Progress reports transferred bytes. total is -1 when unknown.
type Progress func(done, total int64)

type Client struct {
	r         Runner
	ChunkSize int
}

func New(r Runner) *Client { return &Client{r: r, ChunkSize: DefaultChunkSize} }

// NewWithChunk allows the caller to tune bytes-per-round-trip. Larger is faster
// but a chunk whose base64 form exceeds the target's MaxEnvelopeSizekb is
// rejected with HTTP 413; 256KiB is about the ceiling for the 500KB default.
func NewWithChunk(r Runner, chunk int) *Client {
	if chunk <= 0 {
		chunk = DefaultChunkSize
	}
	return &Client{r: r, ChunkSize: chunk}
}

func (c *Client) chunk() int {
	if c.ChunkSize > 0 {
		return c.ChunkSize
	}
	return DefaultChunkSize
}

// ---------------------------------------------------------------- upload

// Upload copies a local file or directory to the target. remote may be relative
// to the shell's current location; an empty remote means the local base name in
// the current location. A local path containing * or ? is treated as a glob (see
// uploadGlob).
func (c *Client) Upload(ctx context.Context, local, remote string, prog Progress) error {
	if hasGlobMeta(local) {
		return c.uploadGlob(ctx, local, remote, prog)
	}
	st, err := os.Stat(local)
	if err != nil {
		return fmt.Errorf("local path: %w", err)
	}
	if remote == "" {
		remote = filepath.Base(local)
	}
	if st.IsDir() {
		return c.uploadDir(ctx, local, remote, prog)
	}
	return c.uploadFile(ctx, local, remote, st.Size(), prog)
}

// uploadGlob expands a local wildcard and uploads every match. A single match
// behaves exactly like naming it; multiple matches land under remote, which is
// treated as a directory (each by its base name, directories keeping their
// tree).
func (c *Client) uploadGlob(ctx context.Context, pattern, remote string, prog Progress) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("bad upload pattern %q: %w", pattern, err)
	}
	if len(matches) == 0 {
		return fmt.Errorf("no local files match %q", pattern)
	}
	if len(matches) == 1 {
		return c.Upload(ctx, matches[0], remote, prog)
	}
	if remote == "" {
		remote = "." // the shell's current remote location
	}
	var entries []uploadEntry
	for _, m := range matches {
		es, err := c.collectUploads(m, remote+`\`+filepath.Base(m))
		if err != nil {
			return err
		}
		entries = append(entries, es...)
	}
	return c.uploadEntries(ctx, entries, prog)
}

func (c *Client) uploadDir(ctx context.Context, localRoot, remoteRoot string, prog Progress) error {
	entries, err := c.collectUploads(localRoot, remoteRoot)
	if err != nil {
		return err
	}
	return c.uploadEntries(ctx, entries, prog)
}

// uploadEntry is one regular file resolved to its remote destination.
type uploadEntry struct {
	local, remote string
	size          int64
}

// collectUploads flattens a local path (file or directory) into the regular
// files to send and their remote destinations under remoteBase.
func (c *Client) collectUploads(root, remoteBase string) ([]uploadEntry, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("local path: %w", err)
	}
	if !st.IsDir() {
		return []uploadEntry{{local: root, remote: remoteBase, size: st.Size()}}, nil
	}
	var out []uploadEntry
	err = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil // skip symlinks, devices, sockets
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		dest := strings.ReplaceAll(remoteBase+`\`+filepath.ToSlash(rel), "/", `\`)
		out = append(out, uploadEntry{local: p, remote: dest, size: info.Size()})
		return nil
	})
	return out, err
}

// uploadEntries sends a set of files, reporting one progress bar across the whole
// set (total summed up front). It underlies directory and multi-match uploads.
func (c *Client) uploadEntries(ctx context.Context, entries []uploadEntry, prog Progress) error {
	var total int64
	for _, e := range entries {
		total += e.size
	}
	var done int64
	for _, e := range entries {
		base := done
		err := c.uploadFile(ctx, e.local, e.remote, e.size, func(d, _ int64) {
			if prog != nil {
				prog(base+d, total)
			}
		})
		if err != nil {
			return fmt.Errorf("%s: %w", e.local, err)
		}
		done += e.size
	}
	if prog != nil {
		prog(done, total)
	}
	return nil
}

func (c *Client) uploadFile(ctx context.Context, local, remote string, size int64, prog Progress) error {
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()

	abs, err := c.resolveRemote(ctx, remote)
	if err != nil {
		return err
	}
	if err := c.ensureRemoteDir(ctx, parentDir(abs)); err != nil {
		return err
	}

	sum := sha256.New()
	buf := make([]byte, c.chunk())
	var done int64
	first := true

	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			sum.Write(buf[:n])
			if err := c.writeChunk(ctx, abs, buf[:n], first); err != nil {
				return err
			}
			first = false
			done += int64(n)
			if prog != nil {
				prog(done, size)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	// An empty file still has to exist on the target.
	if first {
		if err := c.writeChunk(ctx, abs, nil, true); err != nil {
			return err
		}
	}
	return c.verify(ctx, abs, hex.EncodeToString(sum.Sum(nil)), done)
}

// writeChunk appends one chunk. Opening per chunk rather than holding a remote
// FileStream across pipelines keeps the target from being left with a locked,
// half-written file if a chunk fails midway.
func (c *Client) writeChunk(ctx context.Context, absRemote string, data []byte, first bool) error {
	mode := "Append"
	if first {
		mode = "Create" // truncates an existing file
	}
	script := fmt.Sprintf(
		`$b=[Convert]::FromBase64String('%s')
$f=[IO.File]::Open(%s,[IO.FileMode]::%s,[IO.FileAccess]::Write)
try{$f.Write($b,0,$b.Length)}finally{$f.Close()}`,
		base64.StdEncoding.EncodeToString(data), psQuote(absRemote), mode)
	if _, err := c.run(ctx, script); err != nil {
		// The target enforces MaxEnvelopeSizekb (500KB by default), and base64
		// inflates a chunk by 4/3. Say so, rather than leaving the operator with
		// a bare 413.
		if strings.Contains(err.Error(), "413") {
			return fmt.Errorf("chunk of %d KiB was rejected as too large (HTTP 413); "+
				"retry with a smaller --chunk-size: %w", len(data)/1024, err)
		}
		return err
	}
	return nil
}

// ---------------------------------------------------------------- download

// Download copies a remote file or directory to local. An empty local means the
// remote base name in the current working directory. A remote path containing *
// or ? is treated as a glob (see downloadGlob).
func (c *Client) Download(ctx context.Context, remote, local string, prog Progress) error {
	if hasGlobMeta(remote) {
		return c.downloadGlob(ctx, remote, local, prog)
	}
	abs, err := c.resolveRemote(ctx, remote)
	if err != nil {
		return err
	}
	isDir, size, err := c.stat(ctx, abs)
	if err != nil {
		return err
	}
	if local == "" {
		local = filepath.Base(strings.ReplaceAll(abs, `\`, "/"))
		if local == "" || local == "." || local == string(filepath.Separator) {
			return errors.New("could not derive a local filename; pass one explicitly")
		}
	}
	if isDir {
		_, err := c.downloadDir(ctx, abs, local, prog)
		return err
	}
	// Downloading onto an existing directory means "into" it.
	if st, err := os.Stat(local); err == nil && st.IsDir() {
		name, err := safeLocalPath(local, filepath.Base(strings.ReplaceAll(abs, `\`, "/")))
		if err != nil {
			return err
		}
		local = name
	}
	return c.downloadFile(ctx, abs, local, size, prog)
}

// downloadDir copies a remote directory tree and returns the total bytes moved,
// so a caller composing several downloads (a glob) can keep one running progress
// offset.
func (c *Client) downloadDir(ctx context.Context, absRemote, localRoot string, prog Progress) (int64, error) {
	rels, err := c.listFiles(ctx, absRemote)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(localRoot, 0o755); err != nil {
		return 0, err
	}
	var done int64
	for _, rel := range rels {
		// rel comes from the target and is untrusted.
		dest, err := safeLocalPath(localRoot, rel)
		if err != nil {
			return done, err
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return done, err
		}
		src := absRemote + `\` + rel
		_, size, err := c.stat(ctx, src)
		if err != nil {
			return done, fmt.Errorf("%s: %w", rel, err)
		}
		base := done
		err = c.downloadFile(ctx, src, dest, size, func(d, _ int64) {
			if prog != nil {
				prog(base+d, -1)
			}
		})
		if err != nil {
			return done, fmt.Errorf("%s: %w", rel, err)
		}
		done += size
	}
	return done, nil
}

// remoteMatch is one entry a remote wildcard expanded to.
type remoteMatch struct {
	path  string // absolute path on the target
	isDir bool
}

// downloadGlob expands a remote wildcard on the target and downloads every
// match. A single match behaves exactly like naming it; multiple matches land
// under local, which is treated as a directory.
func (c *Client) downloadGlob(ctx context.Context, pattern, local string, prog Progress) error {
	matches, err := c.resolveRemoteGlob(ctx, pattern)
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		return fmt.Errorf("no remote files match %q", pattern)
	}
	if len(matches) == 1 {
		return c.Download(ctx, matches[0].path, local, prog)
	}
	if local == "" {
		local = "."
	}
	if err := os.MkdirAll(local, 0o755); err != nil {
		return err
	}
	var done int64
	for _, m := range matches {
		base := done
		wrap := func(d, _ int64) {
			if prog != nil {
				prog(base+d, -1)
			}
		}
		// The base name comes from the target; keep it inside the local dir.
		name := filepath.Base(strings.ReplaceAll(m.path, `\`, "/"))
		dest, err := safeLocalPath(local, name)
		if err != nil {
			return err
		}
		if m.isDir {
			n, err := c.downloadDir(ctx, m.path, dest, wrap)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			done += n
			continue
		}
		_, size, err := c.stat(ctx, m.path)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := c.downloadFile(ctx, m.path, dest, size, wrap); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		done += size
	}
	return nil
}

// resolveRemoteGlob expands a wildcard on the target. Get-Item -Path does
// provider-level globbing even inside a single-quoted literal (the quoting only
// stops PowerShell from expanding variables/subexpressions), so a hostile path
// still can't break out. A path can contain neither '|' nor a newline on Windows,
// so they are safe field/line delimiters.
func (c *Client) resolveRemoteGlob(ctx context.Context, pattern string) ([]remoteMatch, error) {
	script := fmt.Sprintf(
		`Get-Item -Path %s -Force -ErrorAction SilentlyContinue | `+
			`ForEach-Object { "{0}|{1}" -f [int]$_.PSIsContainer,$_.FullName }`, psQuote(pattern))
	res, err := c.run(ctx, script)
	if err != nil {
		return nil, err
	}
	var out []remoteMatch
	for _, v := range res.Output {
		for _, ln := range strings.Split(output.Text(v), "\n") {
			flag, full, ok := strings.Cut(strings.TrimSpace(ln), "|")
			if !ok || full == "" {
				continue
			}
			out = append(out, remoteMatch{path: full, isDir: flag == "1"})
		}
	}
	return out, nil
}

func (c *Client) downloadFile(ctx context.Context, absRemote, local string, size int64, prog Progress) error {
	f, err := os.OpenFile(local, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	sum := sha256.New()
	var off int64
	for off < size {
		n := int64(c.chunk())
		if remaining := size - off; remaining < n {
			n = remaining
		}
		script := fmt.Sprintf(
			`$f=[IO.File]::OpenRead(%s)
try{
$null=$f.Seek(%d,[IO.SeekOrigin]::Begin)
$b=New-Object byte[] %d
$n=$f.Read($b,0,%d)
[Convert]::ToBase64String($b,0,$n)
}finally{$f.Close()}`, psQuote(absRemote), off, n, n)
		res, err := c.run(ctx, script)
		if err != nil {
			return err
		}
		b64, err := singleString(res)
		if err != nil {
			return err
		}
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return fmt.Errorf("decode chunk at offset %d: %w", off, err)
		}
		if len(data) == 0 {
			return fmt.Errorf("remote returned no data at offset %d of %d", off, size)
		}
		if _, err := f.Write(data); err != nil {
			return err
		}
		sum.Write(data)
		off += int64(len(data))
		if prog != nil {
			prog(off, size)
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return c.verify(ctx, absRemote, hex.EncodeToString(sum.Sum(nil)), off)
}

// ---------------------------------------------------------------- helpers

// verify compares the hash of the bytes we transferred against the file on the
// target, so truncation or corruption fails loudly instead of leaving a
// plausible-looking file behind.
func (c *Client) verify(ctx context.Context, absRemote, localHex string, localSize int64) error {
	script := fmt.Sprintf(
		`$p=%s
"{0}:{1}" -f (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash,(Get-Item -LiteralPath $p -Force).Length`,
		psQuote(absRemote))
	res, err := c.run(ctx, script)
	if err != nil {
		// Get-FileHash needs PowerShell 4+; don't fail an otherwise good
		// transfer because the target is ancient.
		return fmt.Errorf("integrity check could not run (transfer may still be fine): %w", err)
	}
	s, err := singleString(res)
	if err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}
	remoteHex, sizeStr, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return fmt.Errorf("integrity check: unexpected response %q", s)
	}
	if !strings.EqualFold(remoteHex, localHex) {
		return fmt.Errorf("integrity check FAILED: local sha256 %s, remote %s", localHex, remoteHex)
	}
	var remoteSize int64
	if _, err := fmt.Sscanf(sizeStr, "%d", &remoteSize); err == nil && remoteSize != localSize {
		return fmt.Errorf("integrity check FAILED: local %d bytes, remote %d", localSize, remoteSize)
	}
	return nil
}

// resolveRemote turns a possibly-relative PowerShell path into an absolute
// filesystem path. [IO.File] resolves relative paths against the process
// directory, not the shell's location, so this must happen before any IO.
func (c *Client) resolveRemote(ctx context.Context, p string) (string, error) {
	script := fmt.Sprintf(
		`$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(%s)`, psQuote(p))
	res, err := c.run(ctx, script)
	if err != nil {
		return "", err
	}
	s, err := singleString(res)
	if err != nil {
		return "", fmt.Errorf("resolve remote path %q: %w", p, err)
	}
	return strings.TrimSpace(s), nil
}

func (c *Client) ensureRemoteDir(ctx context.Context, dir string) error {
	if dir == "" {
		return nil
	}
	script := fmt.Sprintf(
		`if(-not (Test-Path -LiteralPath %s)){$null=New-Item -ItemType Directory -Force -Path %s}`,
		psQuote(dir), psQuote(dir))
	_, err := c.run(ctx, script)
	return err
}

// stat reports whether a remote path is a directory, and its size.
func (c *Client) stat(ctx context.Context, absRemote string) (isDir bool, size int64, err error) {
	script := fmt.Sprintf(
		`$i=Get-Item -LiteralPath %s -Force -ErrorAction Stop
"{0}:{1}" -f $i.PSIsContainer,$(if($i.PSIsContainer){0}else{$i.Length})`, psQuote(absRemote))
	res, err := c.run(ctx, script)
	if err != nil {
		return false, 0, err
	}
	s, err := singleString(res)
	if err != nil {
		return false, 0, err
	}
	dirStr, sizeStr, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return false, 0, fmt.Errorf("stat: unexpected response %q", s)
	}
	isDir = strings.EqualFold(dirStr, "True")
	if !isDir {
		if _, err := fmt.Sscanf(sizeStr, "%d", &size); err != nil {
			return false, 0, fmt.Errorf("stat: bad size %q", sizeStr)
		}
	}
	return isDir, size, nil
}

// listFiles returns file paths under a remote directory, relative to it.
func (c *Client) listFiles(ctx context.Context, absRemote string) ([]string, error) {
	script := fmt.Sprintf(
		`$root=(Get-Item -LiteralPath %s -Force).FullName.TrimEnd('\')
Get-ChildItem -LiteralPath $root -Recurse -Force -File | ForEach-Object { $_.FullName.Substring($root.Length+1) }`,
		psQuote(absRemote))
	res, err := c.run(ctx, script)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range res.Output {
		s := strings.TrimSpace(output.Text(v))
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// safeLocalPath joins an untrusted, target-supplied relative path under dir.
//
// Directory components are stripped from each element and the result is checked
// to be inside dir, so a target returning names like `..\..\.ssh\authorized_keys`
// cannot write outside the download directory.
func safeLocalPath(dir, untrusted string) (string, error) {
	// Windows and Unix separators both matter: the name comes from Windows.
	parts := strings.FieldsFunc(untrusted, func(r rune) bool { return r == '/' || r == '\\' })
	clean := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// filepath.Base defends against anything still embedding a separator,
		// and drive-relative names like `C:` are rejected outright.
		p = filepath.Base(p)
		if p == "" || p == "." || p == ".." || strings.Contains(p, ":") {
			continue
		}
		clean = append(clean, p)
	}
	if len(clean) == 0 {
		return "", fmt.Errorf("refusing unsafe remote filename %q", untrusted)
	}
	joined := filepath.Join(append([]string{dir}, clean...)...)

	// Belt and braces: confirm the result really is under dir.
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absDir, absJoined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing remote filename %q: escapes %s", untrusted, dir)
	}
	return joined, nil
}

// run executes a script and turns a PowerShell error stream into a Go error.
func (c *Client) run(ctx context.Context, script string) (*client.Result, error) {
	res, err := c.r.RunRaw(ctx, script)
	if err != nil {
		return nil, err
	}
	if res.HadErrors {
		return nil, errors.New(firstErrorMessage(res))
	}
	return res, nil
}

func firstErrorMessage(res *client.Result) string {
	for _, e := range res.Errors {
		if m, ok := output.Normalize(e).(map[string]interface{}); ok {
			if msg, ok := m["message"].(string); ok && msg != "" {
				return msg
			}
		}
		if s := strings.TrimSpace(output.Text(e)); s != "" {
			return s
		}
	}
	return "remote command reported an error"
}

// singleString pulls one string out of a pipeline result.
func singleString(res *client.Result) (string, error) {
	if len(res.Output) == 0 {
		return "", errors.New("remote command produced no output")
	}
	var b strings.Builder
	for _, v := range res.Output {
		b.WriteString(output.Text(v))
	}
	return b.String(), nil
}

// psQuote renders a Go string as a PowerShell single-quoted literal, where the
// only escape is a doubled quote. Single quotes prevent PowerShell from
// expanding $(...) or variables inside a path we do not control.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// hasGlobMeta reports whether p should be treated as a wildcard pattern. Only *
// and ? trigger it: both are illegal in Windows filenames, so a remote pattern is
// unambiguous, whereas [ and ] are legal filename characters, treating them as a
// character class would break a literal name like "file[1].txt". A [...] class
// still works when combined with * or ?.
func hasGlobMeta(p string) bool {
	return strings.ContainsAny(p, "*?")
}

func parentDir(winPath string) string {
	i := strings.LastIndexAny(winPath, `\/`)
	if i <= 0 {
		return ""
	}
	return winPath[:i]
}
