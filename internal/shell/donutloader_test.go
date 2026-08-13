package shell

import (
	"strings"
	"testing"
)

func TestParseDonutArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		pid     string
		file    string
		wantErr bool
	}{
		{"upstream order", []string{"-process_id", "1234", "-donutfile", "/opt/d.bin"}, "1234", "/opt/d.bin", false},
		{"flags reversed", []string{"-donutfile", "/opt/d.bin", "-process_id", "1234"}, "1234", "/opt/d.bin", false},
		// PowerShell binds parameters case-insensitively, so we do too.
		{"mixed case flags", []string{"-Process_Id", "7", "-DonutFile", "d.bin"}, "7", "d.bin", false},
		{"positional shorthand", []string{"1234", "/opt/d.bin"}, "1234", "/opt/d.bin", false},
		{"no args", nil, "", "", true},
		{"flag without value", []string{"-process_id", "1234", "-donutfile"}, "", "", true},
		{"unknown flag", []string{"-pid", "1234", "-donutfile", "d.bin"}, "", "", true},
		{"same flag twice", []string{"-process_id", "1", "-process_id", "2"}, "", "", true},
		{"pid not a number", []string{"-process_id", "notapid", "-donutfile", "d.bin"}, "", "", true},
		{"pid zero", []string{"-process_id", "0", "-donutfile", "d.bin"}, "", "", true},
		{"pid negative", []string{"-process_id", "-5", "-donutfile", "d.bin"}, "", "", true},
		// A pid that isn't plain digits must never reach the remote command line.
		{"pid with injection", []string{"-process_id", "1;calc", "-donutfile", "d.bin"}, "", "", true},
		{"too many args", []string{"1", "2", "3"}, "", "", true},
	}
	for _, c := range cases {
		pid, file, err := parseDonutArgs(c.args)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: parseDonutArgs(%#v) err = %v, wantErr %v", c.name, c.args, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if pid != c.pid || file != c.file {
			t.Errorf("%s: parseDonutArgs(%#v) = (%q, %q), want (%q, %q)", c.name, c.args, pid, file, c.pid, c.file)
		}
	}
}

func TestDonutCommand(t *testing.T) {
	got := donutCommand("1234")
	want := "Donut-Loader -process_id 1234 -donutfile $global:__ewdonut"
	if got != want {
		t.Errorf("donutCommand(1234) = %q, want %q", got, want)
	}
}

// The embedded asset must actually define the function the command calls, and
// carry the x64 guard, a truncated or wrong asset would otherwise only show up
// against a live target.
func TestDonutLoaderAsset(t *testing.T) {
	for _, want := range []string{
		"function Donut-Loader {param($process_id,$donutfile)",
		"[System.Reflection.Assembly]::Load($bytes)",
		"[ShellcodeTest.Program]::Main($array)",
		"[IntPtr]::Size) -eq 4", // refuses to inject from an x86 process
	} {
		if !strings.Contains(donutLoaderFunc, want) {
			t.Errorf("embedded donut-loader.ps1 is missing %q", want)
		}
	}
}

// The positional shorthand must not swallow a flag as a filename: a
// half-converted line should say "usage", not "no such file".
func TestPositionalRejectsFlagShapedFile(t *testing.T) {
	if _, _, err := parseDonutArgs([]string{"3312", "-donutfile"}); err == nil {
		t.Error("`donut-loader 3312 -donutfile` should be a usage error, not a filename")
	}
}

// Atoi would accept a signed pid; the digits-only invariant the command claims
// has to actually hold, since the pid is interpolated into the remote command.
func TestPidMustBePlainDigits(t *testing.T) {
	for _, bad := range []string{"+3312", " 3312", "3312 ", "0x10", "3312.0", ""} {
		if _, _, err := parseDonutArgs([]string{"-process_id", bad, "-donutfile", "d.bin"}); err == nil {
			t.Errorf("pid %q was accepted, want rejected", bad)
		}
	}
	if pid, _, err := parseDonutArgs([]string{"-process_id", "3312", "-donutfile", "d.bin"}); err != nil || pid != "3312" {
		t.Errorf("plain digits = (%q, %v), want (3312, nil)", pid, err)
	}
}
