package complete

import "testing"

// A parameter name or a parameter's value has nothing to do with the filesystem;
// completing `-Na` against a directory listing yields nothing, which is exactly
// what it did before. Paths stay on TargetRemote, whose quoting is tuned to what
// the editor needs.
func TestAnalyzeRoutesParametersToPowerShell(t *testing.T) {
	cases := []struct {
		name string
		line string
		want Target
		word string
	}{
		{"parameter name", "Get-Process -Na", TargetPSNative, "-Na"},
		{"bare dash", "Get-Process -", TargetPSNative, "-"},
		{"value after a parameter", "Get-Process -Name con", TargetPSNative, "con"},
		{"empty value after a parameter", "Get-Process -Name ", TargetPSNative, ""},
		{"path value stays on the remote lister", `Get-Content -Path C:\Wind`, TargetRemote, `C:\Wind`},
		{"backslash-relative path too", `Get-Content -Path .\notes`, TargetRemote, `.\notes`},
		{"a plain argument is still a path", "Get-Content C:", TargetRemote, "C:"},
		{"first word is never PS-native", "Get-Pro", TargetVerb, "Get-Pro"},

		// The built-ins own their own argument semantics and must not be
		// rerouted: upload's first argument is the operator's filesystem, and
		// donut-loader's flags come from its own list.
		{"upload arg 1 stays local", "upload /etc/hostn", TargetLocal, "/etc/hostn"},
		{"download arg 2 stays local", "download C:\\f /tmp/x", TargetLocal, "/tmp/x"},
		{"donut-loader flags stay literal", "donut-loader -pro", TargetOptions, "-pro"},
		{"donut-loader file stays local", "donut-loader -donutfile /tmp/s", TargetLocal, "/tmp/s"},
		{"invoke-binary exe stays local", "invoke-binary Rub", TargetExecutable, "Rub"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Analyze(c.line, len(c.line))
			if got.Target != c.want {
				t.Errorf("Analyze(%q).Target = %v, want %v", c.line, got.Target, c.want)
			}
			if got.Word != c.word {
				t.Errorf("Analyze(%q).Word = %q, want %q", c.line, got.Word, c.word)
			}
		})
	}
}
