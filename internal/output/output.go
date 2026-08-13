// Package output renders pipeline results. Two modes share one session:
//
//	text, what a pentester expects from evil-winrm: PowerShell formats the
//	       output remotely (Out-String) and we print the text verbatim.
//	json, the reason this port exists: PSRP objects survive as objects, so an
//	       agent gets typed fields instead of scraping a console table.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/smnsjas/go-psrpcore/serialization"
	"github.com/sresarehumantoo/go-psrp/client"
)

// ANSI colors, suppressed when --no-colors is set or the environment asks for
// colourless output.
type Colors struct{ enabled bool }

func NewColors(enabled bool) Colors { return Colors{enabled} }

// EnvDisablesColor reports whether the environment asks for no color, so the
// caller can fold it into the --no-colors flag. Kept here because whether
// color happens at all is this package's decision alone.
//
//   - NO_COLOR set to any value, per the no-color.org convention. Presence is
//     what counts, not the value, so NO_COLOR=0 still disables, that is the
//     convention as written, and second-guessing it would surprise anyone who
//     exports it globally.
//   - TERM empty or "dumb", the terminal that has declared it cannot render
//     escapes. This is the same test internal/lineedit uses to pick the plain
//     reader, so a dumb terminal gets a plain prompt AND plain output rather
//     than one of each.
func EnvDisablesColor() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return true
	}
	switch os.Getenv("TERM") {
	case "", "dumb":
		return true
	}
	return false
}

func (c Colors) wrap(code, s string) string {
	if !c.enabled || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (c Colors) Red(s string) string    { return c.wrap("31", s) }
func (c Colors) Yellow(s string) string { return c.wrap("33", s) }
func (c Colors) Blue(s string) string   { return c.wrap("34", s) }
func (c Colors) Bold(s string) string   { return c.wrap("1", s) }

// Normalize converts a deserialized PSRP value into something encoding/json
// renders usefully. Without this, a *PSObject marshals as its Go struct guts
// (TypeNames/Properties/Members/...) instead of the object the user asked for.
func Normalize(v interface{}) interface{} {
	switch t := v.(type) {
	case nil:
		return nil
	case *serialization.PSObject:
		return normalizePSObject(t)
	case serialization.PSObject:
		return normalizePSObject(&t)
	case *serialization.PSObjectWithRef:
		return normalizePSObject(&t.PSObject)
	case *serialization.TypedList:
		return normalizeSlice(t.Items)
	case serialization.TypedList:
		return normalizeSlice(t.Items)
	case []interface{}:
		return normalizeSlice(t)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			out[k] = Normalize(val)
		}
		return out
	default:
		return v // primitives: string, int32/64, bool, float64, ...
	}
}

func normalizeSlice(in []interface{}) []interface{} {
	out := make([]interface{}, 0, len(in))
	for _, v := range in {
		out = append(out, Normalize(v))
	}
	return out
}

const errorRecordType = "System.Management.Automation.ErrorRecord"

// normalizePSObject flattens a PSObject to its properties. Adapted (extended)
// members are merged over base properties, which is what PowerShell itself
// surfaces. Type and string form are kept under reserved keys so a consumer can
// still tell a Process from a FileInfo.
func normalizePSObject(o *serialization.PSObject) interface{} {
	if len(o.TypeNames) > 0 && o.TypeNames[0] == errorRecordType {
		return normalizeErrorRecord(o)
	}
	// A PSObject wrapping a primitive (DateTime, enum, ...) is that primitive
	// semantically; the properties riding along are presentation metadata
	// (DisplayHint and friends). Returning the value keeps a timestamp a
	// timestamp, the map branch below would silently drop o.Value entirely.
	if o.Value != nil {
		return Normalize(o.Value)
	}
	m := make(map[string]interface{}, len(o.Properties)+len(o.Members)+2)
	for k, v := range o.Properties {
		m[k] = Normalize(v)
	}
	for k, v := range o.Members {
		m[k] = Normalize(v)
	}
	if len(o.TypeNames) > 0 {
		m["__type"] = o.TypeNames[0]
	}
	if o.ToString != "" {
		m["__string"] = o.ToString
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// normalizeErrorRecord picks the useful fields out of an ErrorRecord. Serialized
// verbatim it is ~25 properties of InvocationInfo_* bookkeeping with the actual
// message buried among them, which defeats the point of structured output.
func normalizeErrorRecord(o *serialization.PSObject) interface{} {
	m := map[string]interface{}{"__type": errorRecordType}
	if o.ToString != "" {
		m["message"] = o.ToString
	}
	// str reads a property that may be a bare string or a PSObject whose
	// ToString holds the text.
	str := func(key string) (string, bool) {
		v, ok := o.Properties[key]
		if !ok {
			return "", false
		}
		switch t := v.(type) {
		case string:
			return t, t != ""
		case *serialization.PSObject:
			return t.ToString, t.ToString != ""
		default:
			return "", false
		}
	}
	for jsonKey, prop := range map[string]string{
		"exception":                "Exception",
		"target_name":              "ErrorCategory_TargetName",
		"target_type":              "ErrorCategory_TargetType",
		"fully_qualified_error_id": "FullyQualifiedErrorId",
		"position":                 "InvocationInfo_PositionMessage",
		"category_message":         "ErrorCategory_Message",
		"invocation_name":          "InvocationInfo_InvocationName",
	} {
		if s, ok := str(prop); ok {
			m[jsonKey] = s
		}
	}
	if v, ok := o.Properties["ErrorCategory_Category"]; ok {
		m["category"] = Normalize(v)
	}
	if v, ok := o.Properties["InvocationInfo_ScriptLineNumber"]; ok {
		m["script_line"] = Normalize(v)
	}
	return m
}

// Text renders one pipeline value for human consumption.
func Text(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case *serialization.PSObject:
		return psObjectText(t)
	case serialization.PSObject:
		return psObjectText(&t)
	case *serialization.PSObjectWithRef:
		return psObjectText(&t.PSObject)
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, Text(e))
		}
		return strings.Join(parts, "\n")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// InformationText renders one record of the Information stream. PowerShell 5.1
// wraps Write-Host in an InformationRecord, whose interesting part is the single
// MessageData property, Text would otherwise dump the whole record (Source,
// TimeGenerated, Computer, …) in map order, which is both noise and unstable.
// Anything that isn't shaped like an InformationRecord renders normally.
func InformationText(v interface{}) string {
	var o *serialization.PSObject
	switch t := v.(type) {
	case *serialization.PSObject:
		o = t
	case serialization.PSObject:
		o = &t
	case *serialization.PSObjectWithRef:
		o = &t.PSObject
	}
	if o != nil && o.ToString == "" {
		if md, ok := o.Properties["MessageData"]; ok {
			return Text(md)
		}
	}
	return Text(v)
}

func psObjectText(o *serialization.PSObject) string {
	if o.ToString != "" {
		return o.ToString
	}
	if o.Value != nil {
		return Text(o.Value)
	}
	// No remote formatting to lean on: fall back to key = value lines rather
	// than dumping the struct.
	var b strings.Builder
	for k, v := range o.Properties {
		fmt.Fprintf(&b, "%s = %s\n", k, Text(v))
	}
	return strings.TrimRight(b.String(), "\n")
}

// CleanBlock tidies a block of remotely-formatted text for a terminal.
//
// Out-String pads every line out to its -Width, so a table comes back with each
// row trailing hundreds of spaces. The terminal wraps those padded lines, which
// looks like blank lines between rows. Stripping the padding fixes the display
// without having to narrow -Width, which would truncate wide tables instead.
//
// Interior blank lines are kept, PowerShell uses them meaningfully, e.g. around
// the "Directory:" heading of a Get-ChildItem listing.
func CleanBlock(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimRight(ln, " \t\r")
	}
	// Drop leading/trailing blank lines that Out-String adds around the block.
	start, end := 0, len(lines)
	for start < end && lines[start] == "" {
		start++
	}
	for end > start && lines[end-1] == "" {
		end--
	}
	return strings.Join(lines[start:end], "\n")
}

// RenderText writes a result the way a shell would: stdout stream first, then
// the diagnostic streams, which PowerShell keeps separate from output.
func RenderText(w io.Writer, res *client.Result, c Colors) {
	for _, o := range res.Output {
		if s := CleanBlock(Text(o)); s != "" {
			fmt.Fprintln(w, s)
		}
	}
	// Write-Host does not write to the output stream, PowerShell 5.1 files it
	// under Information. Skipping it loses the only thing many post-ex scripts
	// ever say (and the donut loader's own x64 refusal), so it is printed
	// unadorned, the way a console shows it.
	for _, i := range res.Information {
		if s := CleanBlock(InformationText(i)); s != "" {
			fmt.Fprintln(w, s)
		}
	}
	for _, e := range res.Errors {
		fmt.Fprintln(w, c.Red(CleanBlock(Text(e))))
	}
	for _, e := range res.Warnings {
		fmt.Fprintln(w, c.Yellow("WARNING: "+CleanBlock(Text(e))))
	}
	for _, e := range res.Verbose {
		fmt.Fprintln(w, c.Blue("VERBOSE: "+CleanBlock(Text(e))))
	}
}

// Record types for the -o json stream's "type" discriminator. Every line is a
// self-describing JSON object; a consumer switches on "type" to tell a command
// result from a transport error or a session-level event. The distinction only
// bites in batch mode (`-x -`), where results, an error, and a "shell recovered"
// notice can all arrive on the same stdout stream, but the field is emitted in
// every mode so a single line is always self-describing on its own.
const (
	TypeResult = "result" // one command's output/streams/verdict
	TypeError  = "error"  // a failure not tied to a rendered command (connect, transport)
	TypeEvent  = "event"  // a session-level notice (e.g. the shell was recovered)
)

// JSONResult is the envelope for -o json: one self-describing object per
// command, so a consumer can stream them without tracking state.
//
// ID is the request-protocol correlation token: when a batch command arrived as
// a JSON request object carrying an "id", the same value is echoed here so a
// consumer can match a response to the request it issued, even though the single
// runspace runs commands in order. It is omitted for a bare-line command, which
// carries no id.
type JSONResult struct {
	Type        string        `json:"type"`
	ID          interface{}   `json:"id,omitempty"`
	Command     string        `json:"command"`
	Output      []interface{} `json:"output"`
	Errors      []interface{} `json:"errors,omitempty"`
	Warnings    []interface{} `json:"warnings,omitempty"`
	Verbose     []interface{} `json:"verbose,omitempty"`
	Information []interface{} `json:"information,omitempty"`
	HadErrors   bool          `json:"had_errors"`
	DurationMS  int64         `json:"duration_ms"`
}

func NewJSONResult(cmd string, res *client.Result, dur time.Duration) JSONResult {
	return JSONResult{
		Type:        TypeResult,
		Command:     cmd,
		Output:      normalizeSlice(res.Output),
		Errors:      normalizeSlice(res.Errors),
		Warnings:    normalizeSlice(res.Warnings),
		Verbose:     normalizeSlice(res.Verbose),
		Information: normalizeSlice(res.Information),
		HadErrors:   res.HadErrors,
		DurationMS:  dur.Milliseconds(),
	}
}

// RenderJSON emits one object per line so `-o json` is pipe-friendly for an
// interactive session as well as a one-shot. An unset Type defaults to
// TypeResult, so the direct-literal callers (a transfer summary) stay untouched
// while every emitted line still carries the discriminator.
func RenderJSON(w io.Writer, r JSONResult) error {
	if r.Type == "" {
		r.Type = TypeResult
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// JSONError reports a failure in the same stream shape, so a consumer parsing
// -o json never has to fall back to reading stderr prose.
func JSONError(w io.Writer, cmd string, err error) error {
	return RenderJSON(w, JSONResult{
		Type:      TypeError,
		Command:   cmd,
		Output:    []interface{}{},
		Errors:    []interface{}{err.Error()},
		HadErrors: true,
	})
}

// JSONEvent is a session-level notice in the -o json stream: something happened
// to the session itself, not to a command. It carries type "event" so a
// consumer never mistakes it for command output.
type JSONEvent struct {
	Type      string `json:"type"`
	Event     string `json:"event"`
	Message   string `json:"message"`
	StateLost bool   `json:"state_lost,omitempty"`
}

// RenderEvent emits one session-level event object. stateLost says whether the
// runspace's accumulated state (cwd, variables, functions, -s scripts, any
// AMSI patch) was discarded, which a batch consumer must know, because it has
// to re-establish anything it was relying on before its next command.
func RenderEvent(w io.Writer, event, message string, stateLost bool) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(JSONEvent{Type: TypeEvent, Event: event, Message: message, StateLost: stateLost})
}
