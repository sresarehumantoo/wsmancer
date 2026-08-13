package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/smnsjas/go-psrpcore/serialization"
)

// A DateTime arrives as a PSObject whose Value holds the time.Time and which
// also carries a DisplayHint property. An earlier version of Normalize only
// unwrapped Value when there were no properties, so `Get-Date` serialized as
// {"DisplayHint":2} and the timestamp was lost outright.
func TestNormalizeUnwrapsValueDespiteDecorationProperties(t *testing.T) {
	want := time.Date(2026, time.July, 24, 18, 14, 35, 0, time.UTC)
	ps := &serialization.PSObject{
		Value:      want,
		Properties: map[string]interface{}{"DisplayHint": int32(2)},
	}
	got := Normalize(ps)
	ts, ok := got.(time.Time)
	if !ok {
		t.Fatalf("Normalize returned %T (%v), want time.Time, the wrapped value was dropped", got, got)
	}
	if !ts.Equal(want) {
		t.Errorf("got %v, want %v", ts, want)
	}
	// It must also survive as a real JSON timestamp, not an object.
	b, err := json.Marshal(Normalize(ps))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"2026-07-24T18:14:35Z"` {
		t.Errorf("marshalled as %s, want an RFC3339 string", b)
	}
}

func TestNormalizeErrorRecordSurfacesMessage(t *testing.T) {
	msg := `Cannot find path 'C:\nope' because it does not exist.`
	rec := &serialization.PSObject{
		TypeNames: []string{errorRecordType, "System.Object"},
		ToString:  msg,
		Properties: map[string]interface{}{
			"ErrorCategory_TargetName":        `C:\nope`,
			"ErrorCategory_TargetType":        "String",
			"ErrorCategory_Category":          int32(13),
			"InvocationInfo_InvocationName":   "Get-Item",
			"InvocationInfo_ScriptLineNumber": int32(1),
			"Exception": &serialization.PSObject{
				ToString: "System.Management.Automation.ItemNotFoundException: " + msg,
			},
			// Noise that must not be carried through.
			"InvocationInfo_PipelineLength": int32(0),
			"SerializeExtendedInfo":         true,
			"InvocationInfo_BoundParameters": &serialization.PSObject{
				ToString: "System.Collections.Generic.Dictionary`2[...]",
			},
		},
	}
	m, ok := Normalize(rec).(map[string]interface{})
	if !ok {
		t.Fatalf("Normalize returned %T, want map", Normalize(rec))
	}
	if m["message"] != msg {
		t.Errorf("message = %v, want %q", m["message"], msg)
	}
	if m["target_name"] != `C:\nope` {
		t.Errorf("target_name = %v", m["target_name"])
	}
	if m["invocation_name"] != "Get-Item" {
		t.Errorf("invocation_name = %v", m["invocation_name"])
	}
	if !strings.Contains(m["exception"].(string), "ItemNotFoundException") {
		t.Errorf("exception = %v", m["exception"])
	}
	for _, noise := range []string{"InvocationInfo_PipelineLength", "SerializeExtendedInfo", "InvocationInfo_BoundParameters"} {
		if _, present := m[noise]; present {
			t.Errorf("%s should have been dropped from the error record", noise)
		}
	}
}

func TestNormalizeNestedStructures(t *testing.T) {
	in := &serialization.PSObject{
		TypeNames: []string{"System.Management.Automation.PSCustomObject"},
		Properties: map[string]interface{}{
			"Arr": []interface{}{int32(1), int32(2)},
			"Nested": &serialization.PSObject{
				TypeNames:  []string{"System.Management.Automation.PSCustomObject"},
				Properties: map[string]interface{}{"A": int32(1), "B": "two"},
			},
			"List": &serialization.TypedList{Items: []interface{}{"x", "y"}},
		},
		Members: map[string]interface{}{"Extended": "yes"},
	}
	m := Normalize(in).(map[string]interface{})
	if m["__type"] != "System.Management.Automation.PSCustomObject" {
		t.Errorf("__type = %v", m["__type"])
	}
	if m["Extended"] != "yes" {
		t.Errorf("extended member missing: %v", m)
	}
	if got := m["Arr"].([]interface{}); len(got) != 2 || got[0] != int32(1) {
		t.Errorf("Arr = %v", got)
	}
	if got := m["Nested"].(map[string]interface{}); got["B"] != "two" {
		t.Errorf("Nested = %v", got)
	}
	if got := m["List"].([]interface{}); len(got) != 2 || got[1] != "y" {
		t.Errorf("List = %v", got)
	}
}

// Normalize must never hand encoding/json a *PSObject, or the output becomes
// the library's struct fields instead of the user's object.
func TestNormalizeLeavesNoPSObjects(t *testing.T) {
	in := []interface{}{
		&serialization.PSObject{Properties: map[string]interface{}{
			"Inner": &serialization.PSObject{Value: "deep"},
		}},
	}
	b, err := json.Marshal(normalizeSlice(in))
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"TypeNames", "OrderedMemberKeys", "Properties"} {
		if bytes.Contains(b, []byte(leaked)) {
			t.Errorf("PSObject struct field %q leaked into JSON: %s", leaked, b)
		}
	}
}

func TestTextPrefersToString(t *testing.T) {
	ps := &serialization.PSObject{
		TypeNames:  []string{"System.Diagnostics.Process"},
		ToString:   "System.Diagnostics.Process (lsass)",
		Properties: map[string]interface{}{"Id": int32(580)},
	}
	if got := Text(ps); got != "System.Diagnostics.Process (lsass)" {
		t.Errorf("Text = %q", got)
	}
}

func TestColorsDisabled(t *testing.T) {
	if got := NewColors(false).Red("x"); got != "x" {
		t.Errorf("colors should be suppressed, got %q", got)
	}
	if got := NewColors(true).Red("x"); !strings.Contains(got, "\x1b[31m") {
		t.Errorf("colors should be applied, got %q", got)
	}
}

// Out-String pads every line to its -Width, so rows arrive with hundreds of
// trailing spaces; a terminal wraps those, which reads as blank lines between
// entries. Interior blanks must survive, Get-ChildItem uses them around the
// "Directory:" heading.
func TestCleanBlockStripsOutStringPadding(t *testing.T) {
	in := "\r\n    Directory: C:\\Users\\svc-account" + strings.Repeat(" ", 60) + "\r\n" +
		"\r\n" +
		"Mode     Name" + strings.Repeat(" ", 200) + "\r\n" +
		"----     ----" + strings.Repeat(" ", 200) + "\r\n" +
		"d-r---   Desktop" + strings.Repeat(" ", 190) + "\r\n" +
		"d-r---   Documents" + strings.Repeat(" ", 188) + "\r\n\r\n\r\n"

	got := CleanBlock(in)
	for i, ln := range strings.Split(got, "\n") {
		if ln != strings.TrimRight(ln, " \t\r") {
			t.Errorf("line %d still padded: %q", i, ln)
		}
	}
	want := "    Directory: C:\\Users\\svc-account\n" +
		"\n" +
		"Mode     Name\n" +
		"----     ----\n" +
		"d-r---   Desktop\n" +
		"d-r---   Documents"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestCleanBlockEmptyAndBlankOnly(t *testing.T) {
	for _, in := range []string{"", "\r\n", "   \r\n  \r\n"} {
		if got := CleanBlock(in); got != "" {
			t.Errorf("CleanBlock(%q) = %q, want empty", in, got)
		}
	}
}

// Write-Host does not reach the output stream: PowerShell 5.1 wraps it in an
// InformationRecord. Rendering that record whole dumps Source/TimeGenerated/… in
// map order, so only MessageData should surface.
func TestInformationTextUnwrapsMessageData(t *testing.T) {
	rec := &serialization.PSObject{Properties: map[string]interface{}{
		"MessageData":   "HELLO-FROM-WRITE-HOST",
		"Source":        "Write-Host",
		"Computer":      "DC01.corp.local",
		"TimeGenerated": "2026-07-26T12:40:57Z",
	}}
	if got := InformationText(rec); got != "HELLO-FROM-WRITE-HOST" {
		t.Errorf("InformationText(record) = %q, want just the message", got)
	}
	// A record with a ToString, and anything not record-shaped, renders normally.
	if got := InformationText("plain"); got != "plain" {
		t.Errorf("InformationText(string) = %q, want %q", got, "plain")
	}
	withToString := &serialization.PSObject{
		ToString:   "rendered",
		Properties: map[string]interface{}{"MessageData": "ignored"},
	}
	if got := InformationText(withToString); got != "rendered" {
		t.Errorf("InformationText(ToString record) = %q, want %q", got, "rendered")
	}
}
