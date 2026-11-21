package shell

import (
	"math/rand"
	"strings"
	"testing"
)

func clmObf(seed int64) string {
	return obfuscateBypass(bypassCLMTemplate, bypassCLMFuncCount, bypassCLMVarCount, rand.New(rand.NewSource(seed)))
}

func TestCLMObfuscationLeavesNoTelltaleLiterals(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		got := clmObf(seed)
		for _, lit := range []string{
			"amsi.dll", "kernel32.dll", "System.dll",
			"System.Management.Automation.Security.SystemPolicy",
			"GetSystemLockdownPolicy",
		} {
			if strings.Contains(got, lit) {
				t.Errorf("seed %d: script still contains the literal %q", seed, lit)
			}
		}
	}
}

func TestCLMObfuscationConsumesEveryPlaceholder(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		got := clmObf(seed)
		for _, frag := range []string{">><", "<><", "FUNCTION1", "FUNCTION2", "VAR1", "VAR12"} {
			if strings.Contains(got, frag) {
				t.Errorf("seed %d: unconsumed %q remains", seed, frag)
			}
		}
	}
}

func TestCLMPatchBytesAreUnchanged(t *testing.T) {
	const patch = "0x29,0xc0,0xc3"
	if !strings.Contains(bypassCLMTemplate, patch) {
		t.Fatal("the template no longer carries the CLM patch bytes")
	}
	if !strings.Contains(clmObf(5), patch) {
		t.Error("obfuscation altered the CLM patch bytes")
	}
}

func TestCLMTemplateSplitsIntoSteps(t *testing.T) {
	steps := strings.Split(clmObf(9), jumpMarker)
	if len(steps) != 7 {
		t.Errorf("got %d steps, want 7", len(steps))
	}
	for i, s := range steps {
		if strings.TrimSpace(s) == "" {
			t.Errorf("step %d is empty", i+1)
		}
	}
}

func TestCLMObfuscationDiffersPerInvocation(t *testing.T) {
	if clmObf(1) == clmObf(2) {
		t.Error("two invocations produced identical scripts")
	}
}

func TestCLMObfuscatedScriptIsBalanced(t *testing.T) {
	got := clmObf(23)
	for _, pair := range []struct{ open, close string }{{"(", ")"}, {"{", "}"}, {"[", "]"}} {
		if o, c := strings.Count(got, pair.open), strings.Count(got, pair.close); o != c {
			t.Errorf("unbalanced %s%s: %d vs %d", pair.open, pair.close, o, c)
		}
	}
	if n := strings.Count(got, `"`); n%2 != 0 {
		t.Errorf("odd number of double quotes (%d)", n)
	}
}
