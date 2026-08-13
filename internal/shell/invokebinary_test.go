package shell

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
)

func TestInvokeCommand(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no args", nil, "Invoke-Binary $global:__ewbin"},
		{"empty slice", []string{}, "Invoke-Binary $global:__ewbin"},
		{"one arg", []string{"klist"}, "Invoke-Binary ($global:__ewbin + ' ,klist')"},
		{"several args comma-joined", []string{"kerberoast", "/outfile:x"},
			"Invoke-Binary ($global:__ewbin + ' ,kerberoast,/outfile:x')"},
		// A pre-comma-joined single token is passed through unchanged.
		{"already comma-joined", []string{"a,b,c"}, "Invoke-Binary ($global:__ewbin + ' ,a,b,c')"},
		// Single quotes are doubled so an argument can't escape the PS literal.
		{"embedded quote", []string{"it's"}, "Invoke-Binary ($global:__ewbin + ' ,it''s')"},
	}
	for _, c := range cases {
		if got := invokeCommand(c.args); got != c.want {
			t.Errorf("%s: invokeCommand(%#v) = %q, want %q", c.name, c.args, got, c.want)
		}
	}
}

func TestResolveExecutable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "Rubeus.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}

	withExe := &Shell{o: &cli.Options{Executables: dir}}
	noExe := &Shell{o: &cli.Options{}}

	// A bare name resolves against -e/--executables.
	if got, err := withExe.resolveExecutable("Rubeus.exe"); err != nil || got != exe {
		t.Errorf("bare name with -e = (%q, %v), want (%q, nil)", got, err, exe)
	}
	// A name absent from -e is returned as given (os.ReadFile reports it later).
	if got, err := withExe.resolveExecutable("Missing.exe"); err != nil || got != "Missing.exe" {
		t.Errorf("absent name = (%q, %v), want (Missing.exe, nil)", got, err)
	}
	// A path-shaped word bypasses -e entirely.
	if got, err := withExe.resolveExecutable("./local/x.exe"); err != nil || got != "./local/x.exe" {
		t.Errorf("path-shaped name = (%q, %v), want it unchanged", got, err)
	}
	// Without -e, the argument is used verbatim.
	if got, err := noExe.resolveExecutable("Rubeus.exe"); err != nil || got != "Rubeus.exe" {
		t.Errorf("bare name without -e = (%q, %v), want (Rubeus.exe, nil)", got, err)
	}
}

func TestCompleteExecutable(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"Rubeus.exe", "Certify.exe", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sh := &Shell{o: &cli.Options{Executables: dir}}

	// Bare prefix matches only .exe files in -e, case-insensitively.
	if got := sh.completeExecutable("r"); !reflect.DeepEqual(got, []string{"Rubeus.exe"}) {
		t.Errorf(`completeExecutable("r") = %v, want [Rubeus.exe]`, got)
	}
	// Empty prefix lists every .exe (sorted), never the .txt.
	if got := sh.completeExecutable(""); !reflect.DeepEqual(got, []string{"Certify.exe", "Rubeus.exe"}) {
		t.Errorf(`completeExecutable("") = %v, want [Certify.exe Rubeus.exe]`, got)
	}
}
