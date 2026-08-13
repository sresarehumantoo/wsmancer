package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// randBytes returns n deterministic-enough random bytes; content only has to be
// non-trivial so a truncation or byte-swap changes the hash.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// The core promise of this package: what lands on the target is byte-for-byte
// what left, even when the payload spans many envelope-sized chunks. A tiny
// ChunkSize forces the multi-chunk path (Create then repeated Append).
func TestUploadRoundTripMultiChunk(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.bin")
	data := randBytes(t, 1000)
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}

	tgt := newFakeTarget()
	c := NewWithChunk(tgt, 100) // 10 chunks
	if err := c.Upload(context.Background(), src, `C:\dst\payload.bin`, nil); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	got := tgt.files[`C:\dst\payload.bin`]
	if !bytes.Equal(got, data) {
		t.Fatalf("remote bytes differ: got %d, want %d", len(got), len(data))
	}
	if tgt.writes != 10 {
		t.Errorf("expected 10 chunk writes, got %d", tgt.writes)
	}
}

// An empty file still has to be created on the target, the loop never enters,
// so the first==true fallback is the only thing that writes it.
func TestUploadEmptyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(src, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tgt := newFakeTarget()
	c := New(tgt)
	if err := c.Upload(context.Background(), src, `C:\dst\empty.txt`, nil); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	got, ok := tgt.files[`C:\dst\empty.txt`]
	if !ok {
		t.Fatal("empty file was not created on the target")
	}
	if len(got) != 0 {
		t.Errorf("empty upload wrote %d bytes", len(got))
	}
}

// The first chunk opens in Create mode, which must truncate an existing longer
// file, otherwise a re-upload leaves stale tail bytes and the hash still
// matches nothing sane.
func TestUploadCreateTruncatesExisting(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new.bin")
	data := randBytes(t, 50)
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	tgt := newFakeTarget()
	tgt.putFile(`C:\dst\new.bin`, randBytes(t, 500)) // a longer pre-existing file
	c := NewWithChunk(tgt, 20)
	if err := c.Upload(context.Background(), src, `C:\dst\new.bin`, nil); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got := tgt.files[`C:\dst\new.bin`]; !bytes.Equal(got, data) {
		t.Fatalf("re-upload left %d bytes, want exactly the %d new ones", len(got), len(data))
	}
}

// The integrity check is the package's whole reason for hashing. A single
// corrupted byte on the target must surface as a loud failure, never a silent
// success.
func TestUploadIntegrityCatchesCorruption(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "p.bin")
	if err := os.WriteFile(src, randBytes(t, 400), 0o600); err != nil {
		t.Fatal(err)
	}
	tgt := newFakeTarget()
	tgt.flipFirstWriteByte = true
	c := NewWithChunk(tgt, 100)
	err := c.Upload(context.Background(), src, `C:\dst\p.bin`, nil)
	if err == nil {
		t.Fatal("Upload accepted a corrupted transfer")
	}
	if !strings.Contains(err.Error(), "integrity check FAILED") {
		t.Fatalf("wrong error for corruption: %v", err)
	}
}

// A dropped tail, the "silently truncated payload" the package docstring calls
// the failure mode that matters, must also be caught.
func TestUploadIntegrityCatchesTruncation(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "p.bin")
	if err := os.WriteFile(src, randBytes(t, 400), 0o600); err != nil {
		t.Fatal(err)
	}
	tgt := newFakeTarget()
	tgt.truncateWriteTail = 5 // every chunk loses 5 bytes on the target
	c := NewWithChunk(tgt, 100)
	err := c.Upload(context.Background(), src, `C:\dst\p.bin`, nil)
	if err == nil {
		t.Fatal("Upload accepted a truncated transfer")
	}
	if !strings.Contains(err.Error(), "integrity check FAILED") {
		t.Fatalf("wrong error for truncation: %v", err)
	}
}

// A 413 from the target must become actionable advice, not a bare status code.
func TestUpload413BecomesAdvice(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "p.bin")
	if err := os.WriteFile(src, randBytes(t, 400), 0o600); err != nil {
		t.Fatal(err)
	}
	tgt := newFakeTarget()
	tgt.fail413 = true
	c := NewWithChunk(tgt, 300)
	err := c.Upload(context.Background(), src, `C:\dst\p.bin`, nil)
	if err == nil {
		t.Fatal("Upload ignored a 413")
	}
	if !strings.Contains(err.Error(), "smaller --chunk-size") {
		t.Fatalf("413 not turned into advice: %v", err)
	}
}

// A directory upload must reproduce the tree under the remote root, every file
// intact.
func TestUploadDirTree(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]byte{
		"a.txt":                               randBytes(t, 130),
		filepath.Join("sub", "b.bin"):         randBytes(t, 250),
		filepath.Join("sub", "deep", "c.dat"): randBytes(t, 70),
	}
	for rel, data := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tgt := newFakeTarget()
	c := NewWithChunk(tgt, 64)
	if err := c.Upload(context.Background(), dir, `C:\dst\root`, nil); err != nil {
		t.Fatalf("Upload dir: %v", err)
	}
	for rel, data := range files {
		remote := `C:\dst\root\` + strings.ReplaceAll(rel, string(filepath.Separator), `\`)
		if got, ok := tgt.files[remote]; !ok {
			t.Errorf("missing on target: %s", remote)
		} else if !bytes.Equal(got, data) {
			t.Errorf("%s: %d bytes on target, want %d", remote, len(got), len(data))
		}
	}
}

// Download is the mirror image: the round-tripped local copy must equal the
// remote source, across many read chunks.
func TestDownloadRoundTripMultiChunk(t *testing.T) {
	data := randBytes(t, 1000)
	tgt := newFakeTarget()
	tgt.putFile(`C:\src\payload.bin`, data)

	dir := t.TempDir()
	dst := filepath.Join(dir, "payload.bin")
	c := NewWithChunk(tgt, 100)
	if err := c.Download(context.Background(), `C:\src\payload.bin`, dst, nil); err != nil {
		t.Fatalf("Download: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("downloaded bytes differ: got %d, want %d", len(got), len(data))
	}
	if tgt.reads != 10 {
		t.Errorf("expected 10 read chunks, got %d", tgt.reads)
	}
}

// The download integrity check compares our local hash against the target's own
// Get-FileHash; a corrupted chunk in flight must fail it.
func TestDownloadIntegrityCatchesCorruption(t *testing.T) {
	tgt := newFakeTarget()
	tgt.putFile(`C:\src\p.bin`, randBytes(t, 400))
	tgt.corruptReadB64 = true

	dir := t.TempDir()
	dst := filepath.Join(dir, "p.bin")
	c := NewWithChunk(tgt, 100)
	err := c.Download(context.Background(), `C:\src\p.bin`, dst, nil)
	if err == nil {
		t.Fatal("Download accepted a corrupted chunk")
	}
	if !strings.Contains(err.Error(), "integrity check FAILED") {
		t.Fatalf("wrong error for corruption: %v", err)
	}
}

// A hostile target controls the names listFiles returns. downloadDir must run
// each through safeLocalPath, which strips directory components so a traversal
// name lands as its base name *inside* the download dir and cannot escape. This
// is the end-to-end guard for the Ruby path-traversal bug.
func TestDownloadDirContainsTraversal(t *testing.T) {
	tgt := newFakeTarget()
	tgt.dirs[`C:\loot`] = true
	tgt.putFile(`C:\loot\anchor.txt`, []byte("x")) // so Get-Item reports a real dir
	// downloadDir builds src = C:\loot\ + rel, which winAbs collapses to C:\evil.txt.
	payload := []byte("pwned")
	tgt.putFile(`C:\evil.txt`, payload)
	tgt.listOverride = []string{`..\..\..\evil.txt`}

	dir := t.TempDir()
	local := filepath.Join(dir, "out")
	c := New(tgt)
	if err := c.Download(context.Background(), `C:\loot`, local, nil); err != nil {
		t.Fatalf("Download: %v", err)
	}
	// The traversal name was neutralised to its base name inside the download dir.
	got, err := os.ReadFile(filepath.Join(local, "evil.txt"))
	if err != nil {
		t.Fatalf("expected the file contained inside the download dir: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("content mismatch")
	}
	// And nothing escaped to a parent of the download dir.
	for _, p := range []string{filepath.Join(dir, "evil.txt"), filepath.Join(filepath.Dir(dir), "evil.txt")} {
		if _, statErr := os.Stat(p); statErr == nil {
			t.Fatalf("a file escaped the download directory: %s", p)
		}
	}
}

// A remote wildcard with several matches lands them all under the local dir.
func TestDownloadGlobMultiMatch(t *testing.T) {
	tgt := newFakeTarget()
	want := map[string][]byte{
		"one.txt":   randBytes(t, 120),
		"two.txt":   randBytes(t, 300),
		"three.txt": randBytes(t, 45),
	}
	for name, data := range want {
		tgt.putFile(`C:\loot\`+name, data)
	}
	tgt.putFile(`C:\loot\skip.bin`, randBytes(t, 10)) // must not match *.txt

	dir := t.TempDir()
	c := NewWithChunk(tgt, 64)
	if err := c.Download(context.Background(), `C:\loot\*.txt`, dir, nil); err != nil {
		t.Fatalf("Download glob: %v", err)
	}
	for name, data := range want {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s not downloaded: %v", name, err)
			continue
		}
		if !bytes.Equal(got, data) {
			t.Errorf("%s: content mismatch", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "skip.bin")); err == nil {
		t.Error("*.txt glob wrongly pulled skip.bin")
	}
}

// A local wildcard with several matches uploads each under the remote dir.
func TestUploadGlobMultiMatch(t *testing.T) {
	dir := t.TempDir()
	want := map[string][]byte{
		"one.txt": randBytes(t, 120),
		"two.txt": randBytes(t, 300),
	}
	for name, data := range want {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "skip.bin"), randBytes(t, 10), 0o600); err != nil {
		t.Fatal(err)
	}
	tgt := newFakeTarget()
	c := NewWithChunk(tgt, 64)
	if err := c.Upload(context.Background(), filepath.Join(dir, "*.txt"), `C:\dst`, nil); err != nil {
		t.Fatalf("Upload glob: %v", err)
	}
	for name, data := range want {
		if got, ok := tgt.files[`C:\dst\`+name]; !ok {
			t.Errorf("%s not uploaded", name)
		} else if !bytes.Equal(got, data) {
			t.Errorf("%s: content mismatch", name)
		}
	}
	if _, ok := tgt.files[`C:\dst\skip.bin`]; ok {
		t.Error("*.txt glob wrongly uploaded skip.bin")
	}
}

// Downloading a bare filename onto an existing local directory means "into it",
// and the name still passes through safeLocalPath.
func TestDownloadOntoExistingDir(t *testing.T) {
	tgt := newFakeTarget()
	data := randBytes(t, 200)
	tgt.putFile(`C:\src\report.txt`, data)

	dir := t.TempDir()
	c := NewWithChunk(tgt, 64)
	if err := c.Download(context.Background(), `C:\src\report.txt`, dir, nil); err != nil {
		t.Fatalf("Download: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "report.txt"))
	if err != nil {
		t.Fatalf("file not placed inside the dir: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("content mismatch")
	}
}

// resolveRemote must root a relative path at the shell's location before any IO,
// since [IO.File] would otherwise resolve it against the process directory.
func TestUploadRelativeRemoteResolves(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "note.txt")
	data := randBytes(t, 60)
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	tgt := newFakeTarget() // cwd = C:\Users\test
	c := New(tgt)
	if err := c.Upload(context.Background(), src, `.\note.txt`, nil); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got, ok := tgt.files[`C:\Users\test\note.txt`]; !ok {
		t.Fatal("relative remote path was not rooted at the shell location")
	} else if !bytes.Equal(got, data) {
		t.Error("content mismatch")
	}
}
