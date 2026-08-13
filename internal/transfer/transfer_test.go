package transfer

import (
	"path/filepath"
	"strings"
	"testing"
)

// A hostile target controls the filenames Get-ChildItem returns, so anything
// used to build a local path must not be able to escape the download directory.
// This is the bug fixed in Ruby evil-winrm commit b3bf74b.
func TestSafeLocalPathBlocksTraversal(t *testing.T) {
	dir := t.TempDir()
	hostile := []string{
		`..\..\..\etc\passwd`,
		"../../../etc/passwd",
		`..\..\.ssh\authorized_keys`,
		"..",
		"../",
		`..\`,
		".",
		"",
		"   ",
		`C:\Windows\System32\drivers\etc\hosts`,
		"/etc/shadow",
		`....\\....\\evil`,
		`sub\..\..\..\out.txt`,
	}
	for _, name := range hostile {
		got, err := safeLocalPath(dir, name)
		if err != nil {
			continue // refused outright: fine
		}
		// If it was accepted, it must still be inside dir.
		rel, relErr := filepath.Rel(dir, got)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Errorf("safeLocalPath(%q, %q) = %q, escapes the destination directory", dir, name, got)
		}
	}
}

func TestSafeLocalPathKeepsLegitimateNames(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"notes.txt":            filepath.Join(dir, "notes.txt"),
		`sub\notes.txt`:        filepath.Join(dir, "sub", "notes.txt"),
		`a\b\c\deep.bin`:       filepath.Join(dir, "a", "b", "c", "deep.bin"),
		"sub/unix-style.txt":   filepath.Join(dir, "sub", "unix-style.txt"),
		"file with spaces.txt": filepath.Join(dir, "file with spaces.txt"),
		"weird-但-unicode.txt":  filepath.Join(dir, "weird-但-unicode.txt"),
	}
	for in, want := range cases {
		got, err := safeLocalPath(dir, in)
		if err != nil {
			t.Errorf("safeLocalPath(%q) unexpectedly refused: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("safeLocalPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// psQuote must neutralise quotes so a filename cannot break out of the literal
// and get evaluated as PowerShell.
func TestPSQuoteEscapes(t *testing.T) {
	cases := map[string]string{
		`C:\tmp\a.txt`:   `'C:\tmp\a.txt'`,
		`it's.txt`:       `'it''s.txt'`,
		`'; calc.exe; '`: `'''; calc.exe; '''`,
		`$(whoami).txt`:  `'$(whoami).txt'`, // single quotes don't expand
		`a'b'c`:          `'a''b''c'`,
	}
	for in, want := range cases {
		if got := psQuote(in); got != want {
			t.Errorf("psQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParentDir(t *testing.T) {
	cases := map[string]string{
		`C:\Users\x\file.txt`: `C:\Users\x`,
		`C:\file.txt`:         `C:`,
		`file.txt`:            "",
	}
	for in, want := range cases {
		if got := parentDir(in); got != want {
			t.Errorf("parentDir(%q) = %q, want %q", in, got, want)
		}
	}
}
