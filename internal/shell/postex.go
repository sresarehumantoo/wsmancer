package shell

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sresarehumantoo/wsmancer/internal/output"
)

// servicesScript is the canned `services` query: non-system services from the
// registry with their binary path and whether the current user can even query
// them, the raw material for service-based privesc (unquoted paths, weak perms).
// `-notmatch 'system'` drops the stock in-system32 services so the interesting
// third-party ones stand out. `$?` after the piped Get-Service reports whether
// the query was permitted. Select-Object fixes the column order (the original
// used an unordered hashtable).
const servicesScript = `Get-ItemProperty 'registry::HKLM\System\CurrentControlSet\Services\*' |
  Where-Object { $_.ImagePath -notmatch 'system' -and $null -ne $_.ImagePath } |
  ForEach-Object {
    Get-Service $_.PSChildName -ErrorAction SilentlyContinue | Out-Null
    $ok = $?
    [PSCustomObject]@{ Service = $_.PSChildName; Privileges = $ok; Path = $_.ImagePath }
  } | Select-Object Service, Privileges, Path`

// cleanupScriptVar removes the temporary global used to assemble a script.
const cleanupScriptVar = `Remove-Variable __wsm -Scope Global -ErrorAction SilentlyContinue`

// isScriptLoad reports whether line is a bare "<name>.ps1" naming a file in the
// -s scripts directory, a request to load it into the runspace rather than run
// it. A path-qualified name (`.\x.ps1`, `C:\x.ps1`) is left alone so invoking a
// script that lives on the target still works.
func (sh *Shell) isScriptLoad(line string) (string, bool) {
	if sh.o.Scripts == "" {
		return "", false
	}
	fields := strings.Fields(line)
	if len(fields) != 1 {
		return "", false
	}
	name := fields[0]
	if strings.ContainsAny(name, `\/`) || !strings.EqualFold(filepath.Ext(name), ".ps1") {
		return "", false
	}
	p := filepath.Join(sh.o.Scripts, name)
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		return "", false
	}
	return p, true
}

// loadScript reads a local PowerShell script and defines it in the remote
// runspace: base64 the bytes, assemble a global string in envelope-sized chunks,
// then Invoke-Expression it. Functions defined at top level persist in the single
// runspace, so later commands can call them.
func (sh *Shell) loadScript(ctx context.Context, sigs <-chan os.Signal, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := sh.ensureBaseline(ctx); err != nil {
		return err
	}

	b64 := base64.StdEncoding.EncodeToString(data)
	if err := sh.sendB64Var(ctx, sigs, "__wsm", b64); err != nil {
		_, _ = sh.s.RunRaw(ctx, cleanupScriptVar)
		return fmt.Errorf("sending %s: %w", filepath.Base(path), err)
	}

	load := `Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($global:__wsm)))`
	_, runErr := sh.s.RunRaw(ctx, load)
	_, _ = sh.s.RunRaw(ctx, cleanupScriptVar)
	if runErr != nil {
		return fmt.Errorf("loading %s: %w", filepath.Base(path), runErr)
	}

	sh.log.Event("[load] %s", path)
	added, err := sh.refreshLoadedFuncs(ctx)
	if err != nil {
		return err // the script loaded, but we could not enumerate it
	}
	if !sh.json {
		fmt.Fprintf(sh.out, "%s loaded %s (%d function%s available; `menu` to list)\n",
			sh.c.Blue("Info:"), filepath.Base(path), len(added), plural(len(added)))
	}
	return nil
}

// defineRemoteFunc sends a post-ex wrapper's definition to the runspace. RunRaw
// reports a *PowerShell* failure as an error record rather than a Go error, so
// checking only the Go error would latch a wrapper as "loaded" when the target
// rejected it, ConstrainedLanguage mode, or AMSI objecting to the embedded
// assembly, and every later call would then stream its payload to a function
// that does not exist, with no retry for the rest of the session.
func (sh *Shell) defineRemoteFunc(ctx context.Context, name, script string) error {
	res, err := sh.s.RunRaw(ctx, script)
	if err != nil {
		return fmt.Errorf("defining %s in the runspace: %w", name, err)
	}
	if len(res.Errors) > 0 {
		return fmt.Errorf("defining %s in the runspace: %s", name,
			sanitizeTerminal(output.Text(res.Errors[0])))
	}
	return nil
}

// menu lists the functions the operator has loaded and registers them for
// completion. Unlike evil-winrm's obfuscated menu, this is pure discoverability:
// which functions from your scripts are callable now.
func (sh *Shell) menu(ctx context.Context) error {
	loaded, err := sh.refreshLoadedFuncs(ctx)
	if err != nil {
		return err
	}
	// The operator asking what this session can run is also the point at which
	// the target's command surface is most likely to have changed under us (an
	// Import-Module, an Add-Type), so re-read it lazily on the next Tab.
	sh.invalidateRemoteCommands()
	if sh.json {
		return nil
	}
	if len(loaded) == 0 {
		fmt.Fprintf(sh.out, "%s no functions loaded yet%s\n", sh.c.Blue("Info:"), scriptsHint(sh.o.Scripts))
		return nil
	}
	fmt.Fprintf(sh.out, "%s %d function%s loaded:\n", sh.c.Blue("Info:"), len(loaded), plural(len(loaded)))
	for _, f := range loaded {
		fmt.Fprintf(sh.out, "  %s\n", f)
	}
	return nil
}

// ensureBaseline records the runspace's function names before any script load,
// so `menu` and completion show only what the operator brought in.
func (sh *Shell) ensureBaseline(ctx context.Context) error {
	if sh.baseline != nil {
		return nil
	}
	fns, err := sh.remoteFunctions(ctx)
	if err != nil {
		return err
	}
	sh.baseline = make(map[string]bool, len(fns))
	for _, f := range fns {
		sh.baseline[f] = true
	}
	return nil
}

// refreshLoadedFuncs recomputes the functions added since the baseline and
// registers them for Tab-completion, returning the current set.
func (sh *Shell) refreshLoadedFuncs(ctx context.Context) ([]string, error) {
	if err := sh.ensureBaseline(ctx); err != nil {
		return nil, err
	}
	fns, err := sh.remoteFunctions(ctx)
	if err != nil {
		return nil, err
	}
	var loaded []string
	for _, f := range fns {
		if sh.baseline[f] || builtinFunctions[strings.ToLower(f)] {
			continue
		}
		loaded = append(loaded, f)
	}
	sort.Strings(loaded)
	sh.loadedFuncs = loaded
	return loaded, nil
}

// builtinFunctions are PowerShell's default function-type commands. Many
// (Get-FileHash, New-Guid, …) are module-autoloaded and so appear only after the
// runspace warms up, after the baseline snapshot, so the baseline diff alone
// leaks them into the "loaded" list. This mirrors evil-winrm's menu exclusions.
var builtinFunctions = map[string]bool{
	"convertfrom-sddlstring": true, "get-verb": true, "importsystemmodules": true,
	"help": true, "cd": true, "oss": true, "clear-host": true, "format-hex": true,
	"get-filehash": true, "mkdir": true, "tabexpansion2": true, "more": true,
	"new-guid": true, "new-temporaryfile": true, "import-powershelldatafile": true,
	"main": true, "pause": true, "prompt": true,
	// This port's own post-ex wrappers, defined by ensureInvokeBinary /
	// ensureDonutLoader. `menu` promises to show only what the operator brought
	// in, so the shell's own scaffolding must not be reported as their script's.
	"invoke-binary": true, "donut-loader": true,
}

// remoteFunctions lists the function names defined in the runspace.
func (sh *Shell) remoteFunctions(ctx context.Context) ([]string, error) {
	res, err := sh.s.RunRaw(ctx, `Get-ChildItem Function: | ForEach-Object { $_.Name }`)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range res.Output {
		for _, ln := range strings.Split(output.Text(v), "\n") {
			if s := strings.TrimSpace(ln); s != "" {
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// verbCandidates is the first-word completion set: the built-ins plus the
// functions loaded this session plus the .ps1 names available under -s.
func (sh *Shell) verbCandidates() []string {
	v := make([]string, 0, len(completableVerbs)+len(sh.loadedFuncs)+8)
	v = append(v, completableVerbs...)
	v = append(v, sh.loadedFuncs...)
	v = append(v, sh.scriptNames()...)
	return v
}

// scriptNames lists the .ps1 files available to load from the -s directory, so
// their names Tab-complete as first words.
func (sh *Shell) scriptNames() []string {
	if sh.o.Scripts == "" {
		return nil
	}
	ents, err := os.ReadDir(sh.o.Scripts)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".ps1") {
			out = append(out, e.Name())
		}
	}
	return out
}

func scriptsHint(dir string) string {
	if dir == "" {
		return " (start with -s <dir>, then type a .ps1 name to load it)"
	}
	return " (type a .ps1 name from " + dir + " to load it)"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
