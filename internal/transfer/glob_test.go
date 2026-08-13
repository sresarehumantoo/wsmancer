package transfer

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestHasGlobMeta(t *testing.T) {
	glob := []string{"*.txt", "file?.log", `C:\loot\*`, "a[b]*"}
	for _, p := range glob {
		if !hasGlobMeta(p) {
			t.Errorf("hasGlobMeta(%q) = false, want true", p)
		}
	}
	// [ and ] alone must NOT trigger globbing, they are legal filename chars, so
	// "file[1].txt" is a literal name, not a pattern.
	literal := []string{"plain.txt", `C:\Users\svc\file[1].txt`, "a-b_c.bin", ""}
	for _, p := range literal {
		if hasGlobMeta(p) {
			t.Errorf("hasGlobMeta(%q) = true, want false", p)
		}
	}
}

// collectUploads flattens a local tree into (file -> remote dest) entries; the
// remote destinations must be Windows-separated and rooted at remoteBase.
func TestCollectUploads(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aa"), 0o600))
	must(os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("bbbb"), 0o600))

	c := &Client{}

	// A single file maps to remoteBase verbatim.
	got, err := c.collectUploads(filepath.Join(dir, "a.txt"), `C:\dst\a.txt`)
	must(err)
	if len(got) != 1 || got[0].remote != `C:\dst\a.txt` || got[0].size != 2 {
		t.Fatalf("file entry = %#v", got)
	}

	// A directory maps every regular file under remoteBase, Windows-separated.
	got, err = c.collectUploads(dir, `C:\dst\root`)
	must(err)
	var dests []string
	var total int64
	for _, e := range got {
		dests = append(dests, e.remote)
		total += e.size
		if strings.Contains(e.remote, "/") {
			t.Errorf("remote dest has a forward slash: %q", e.remote)
		}
	}
	sort.Strings(dests)
	want := []string{`C:\dst\root\a.txt`, `C:\dst\root\sub\b.txt`}
	if strings.Join(dests, ",") != strings.Join(want, ",") {
		t.Errorf("dests = %v, want %v", dests, want)
	}
	if total != 6 {
		t.Errorf("total size = %d, want 6", total)
	}
}
