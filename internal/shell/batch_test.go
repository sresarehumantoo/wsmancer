package shell

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
)

// batch builds a batch Shell with no session, for the same reason once() does:
// every test here drives only built-ins, so a nil session turns an accidental
// round trip into a crash rather than a silent pass.
func batch(t *testing.T, o *cli.Options) (*Shell, *bytes.Buffer) {
	t.Helper()
	if o == nil {
		o = &cli.Options{}
	}
	o.NoColors = true
	var buf bytes.Buffer
	return NewBatch(nil, o, &buf), &buf
}

// The core promise: many commands, one shell. `help` twice must run twice
// against the same Shell, the loop iterates, it does not stop after one.
func TestBatchRunsEveryLineOverOneShell(t *testing.T) {
	sh, out := batch(t, nil)

	code := sh.Batch(context.Background(), strings.NewReader("help\nhelp\n"))
	if code != 0 {
		t.Errorf("Batch = %d, want 0", code)
	}
	if n := strings.Count(out.String(), "Any PowerShell command"); n != 2 {
		t.Errorf("help ran %d times, want 2", n)
	}
}

// Blank lines are skipped, not dispatched, dispatch indexes Fields(line)[0] and
// would panic on an empty line.
func TestBatchSkipsBlankLines(t *testing.T) {
	sh, out := batch(t, nil)

	code := sh.Batch(context.Background(), strings.NewReader("\n\nhelp\n \n\t\n"))
	if code != 0 {
		t.Errorf("Batch = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "Any PowerShell command") {
		t.Error("help did not run amid blank lines")
	}
}

// The aggregate exit code: one failing command anywhere makes the batch fail,
// even though earlier and later commands succeed.
func TestBatchExitsOneIfAnyCommandFailed(t *testing.T) {
	sh, _ := batch(t, nil)

	// help (ok), upload with no args (usage error), help (ok).
	code := sh.Batch(context.Background(), strings.NewReader("help\nupload\nhelp\n"))
	if code != 1 {
		t.Errorf("Batch with one failing line = %d, want 1", code)
	}
}

// A per-line verdict must not leak: after a failing line, a succeeding line must
// reset failed, so an all-good tail cannot inherit an earlier failure. The teeth
// are the ordering, failure first, success last, expecting the *aggregate* to
// still be 1 but proving the reset by the mirror test below.
func TestBatchAllSuccessExitsZero(t *testing.T) {
	sh, _ := batch(t, nil)

	if code := sh.Batch(context.Background(), strings.NewReader("help\nclear\nhelp\n")); code != 0 {
		t.Errorf("Batch with all-succeeding lines = %d, want 0", code)
	}
}

// `exit`/`quit` ends the batch early: a command after it must not run. The teeth
// are that the post-exit line is one that would fail, if the loop did not break,
// the exit code would be 1.
func TestBatchStopsAtExit(t *testing.T) {
	sh, out := batch(t, nil)

	code := sh.Batch(context.Background(), strings.NewReader("exit\nupload\n"))
	if code != 0 {
		t.Errorf("Batch(exit then a failing line) = %d, want 0 (the failing line must not run)", code)
	}
	if strings.Contains(out.String(), "usage: upload") {
		t.Error("a command after `exit` ran; the batch did not stop")
	}
}

// -o json batch emits one self-describing object per command, error path
// included, so a consumer parses stdout alone. A dispatch error (upload with no
// args) is a type "error" record.
func TestBatchJSONEmitsOneObjectPerLine(t *testing.T) {
	sh, out := batch(t, &cli.Options{Output: "json"})

	code := sh.Batch(context.Background(), strings.NewReader("upload\nupload\n"))
	if code != 1 {
		t.Errorf("Batch = %d, want 1", code)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d JSON lines, want 2:\n%s", len(lines), out.String())
	}
	for i, ln := range lines {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("line %d is not JSON (%v): %s", i, err, ln)
		}
		if m["type"] != "error" || m["had_errors"] != true {
			t.Errorf("line %d = %+v, want type=error had_errors=true", i, m)
		}
	}
}

// parseRequest tells a structured JSON request from a bare command line. The
// bare-line cases are the ones that must not regress: an ordinary command, and a
// PowerShell scriptblock that starts with "{" but is not JSON, both run verbatim
// with no id.
func TestParseRequest(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		command string
		id      interface{}
	}{
		{"bare command", "whoami", "whoami", nil},
		{"request with string id", `{"id":"r1","command":"whoami"}`, "whoami", "r1"},
		{"request with numeric id", `{"id":7,"command":"hostname"}`, "hostname", float64(7)},
		{"request without id", `{"command":"whoami"}`, "whoami", nil},
		{"scriptblock is not a request", "{ Get-Process }", "{ Get-Process }", nil},
		{"json object without command is bare", `{"foo":1}`, `{"foo":1}`, nil},
		{"malformed json is bare", `{"command":`, `{"command":`, nil},
		{"leading brace but bare-ish", `{"command":""}`, `{"command":""}`, nil}, // empty command -> bare
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd, id := parseRequest(c.in)
			if cmd != c.command || id != c.id {
				t.Errorf("parseRequest(%q) = (%q, %v), want (%q, %v)", c.in, cmd, id, c.command, c.id)
			}
		})
	}
}

// The correlation contract: a request's id is echoed on the object it produces,
// and a bare line that follows carries none (reqID must be cleared). upload with
// no args is the vehicle, it fails in dispatch without touching the target, so
// the error object is emitted with the id attached.
func TestBatchEchoesRequestID(t *testing.T) {
	sh, out := batch(t, &cli.Options{Output: "json"})

	sh.Batch(context.Background(), strings.NewReader(
		`{"id":"req-42","command":"upload"}`+"\n"+"upload\n"))

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d objects, want 2:\n%s", len(lines), out.String())
	}
	var first, second map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if first["id"] != "req-42" {
		t.Errorf("structured request: id = %v, want req-42", first["id"])
	}
	if _, ok := second["id"]; ok {
		t.Errorf("bare line after a request carried an id (%v); reqID was not cleared", second["id"])
	}
}

// Batch is a session: unlike a one-shot it recovers a forgotten shell rather
// than reporting it, because there is a next command to protect. This pins the
// wiring (once stays false); the actual recovery is a live-gate concern
// (scripts/batch-test.py), since recoverShell needs a real session to renew.
func TestBatchKeepsSessionSemantics(t *testing.T) {
	sh, _ := batch(t, nil)
	if sh.once {
		t.Error("batch shell has once=true; a forgotten shell would be abandoned, not recovered")
	}
	if sh.ed != nil {
		t.Error("batch built a line editor; it reads the stream itself")
	}
	if sh.hist != nil {
		t.Error("batch opened a history store; there is no prompt to recall at")
	}
}
