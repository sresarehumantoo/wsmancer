package complete

import (
	"reflect"
	"testing"
)

func TestVerbsCaseInsensitiveAndDedup(t *testing.T) {
	verbs := []string{"upload", "menu", "Get-Foo", "Get-Bar", "Recon.ps1", "menu"}

	// A lowercase prefix must match a mixed-case candidate (PowerShell is
	// case-insensitive, and a loaded Get-Foo has to complete from "get-f").
	got := Verbs("get-f", verbs)
	if !reflect.DeepEqual(got, []string{"Get-Foo"}) {
		t.Errorf(`Verbs("get-f") = %v, want [Get-Foo]`, got)
	}

	// Built-in lowercase verbs still work, and the duplicate "menu" collapses.
	got = Verbs("m", verbs)
	if !reflect.DeepEqual(got, []string{"menu"}) {
		t.Errorf(`Verbs("m") = %v, want [menu] (deduped)`, got)
	}

	// Empty prefix returns everything, once each.
	if got := Verbs("", verbs); len(got) != 5 {
		t.Errorf("Verbs(\"\") returned %d candidates, want 5 unique: %v", len(got), got)
	}
}
