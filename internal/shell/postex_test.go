package shell

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
)

func TestIsScriptLoad(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"Recon.ps1", "Upper.PS1"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("function Get-Foo{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	sh := &Shell{o: &cli.Options{Scripts: dir}}
	cases := []struct {
		line string
		want bool
	}{
		{"Recon.ps1", true},           // bare name in the -s dir
		{"Upper.PS1", true},           // .PS1 extension accepted (EqualFold)
		{"Missing.ps1", false},        // not present in the dir
		{"Recon.ps1 -Verbose", false}, // extra args => a command, not a load
		{`.\Recon.ps1`, false},        // path-qualified => run on the target
		{`C:\tools\x.ps1`, false},     // remote path
		{"whoami", false},             // not a .ps1
	}
	for _, c := range cases {
		if _, ok := sh.isScriptLoad(c.line); ok != c.want {
			t.Errorf("isScriptLoad(%q) = %v, want %v", c.line, ok, c.want)
		}
	}

	// With no -s directory, nothing is ever a script load.
	none := &Shell{o: &cli.Options{}}
	if _, ok := none.isScriptLoad("Recon.ps1"); ok {
		t.Error("isScriptLoad should be false when -s is unset")
	}
}

func TestScriptNames(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"A.ps1", "b.PS1", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sh := &Shell{o: &cli.Options{Scripts: dir}}
	got := sh.scriptNames()
	if len(got) != 2 {
		t.Errorf("scriptNames() = %v, want the two .ps1 files", got)
	}
}
