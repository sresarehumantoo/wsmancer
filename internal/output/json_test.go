package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/sresarehumantoo/go-psrp/client"
)

// decode reads exactly one NDJSON object off the buffer into a generic map, and
// fails if there is not exactly one line, the stream's one-object-per-line
// contract is part of what these tests defend.
func decode(t *testing.T, b *bytes.Buffer) map[string]interface{} {
	t.Helper()
	raw := bytes.TrimRight(b.Bytes(), "\n")
	if bytes.Contains(raw, []byte("\n")) {
		t.Fatalf("expected exactly one JSON line, got:\n%s", raw)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not JSON (%v): %s", err, raw)
	}
	return m
}

// The discriminator is the whole point of adding it: every line self-identifies,
// so a batch consumer can switch on "type" without tracking position.
func TestResultCarriesTypeResult(t *testing.T) {
	var b bytes.Buffer
	r := NewJSONResult("whoami", &client.Result{}, 5*time.Millisecond)
	if err := RenderJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	if m := decode(t, &b); m["type"] != TypeResult {
		t.Errorf("type = %v, want %q", m["type"], TypeResult)
	}
}

// The direct-literal callers (the transfer summary) never set Type; RenderJSON
// must default it rather than emit a line with an empty discriminator. This is
// what lets those call sites stay untouched.
func TestRenderJSONDefaultsEmptyTypeToResult(t *testing.T) {
	var b bytes.Buffer
	if err := RenderJSON(&b, JSONResult{Command: "upload x y"}); err != nil {
		t.Fatal(err)
	}
	if m := decode(t, &b); m["type"] != TypeResult {
		t.Errorf("type = %v, want %q for an unset Type", m["type"], TypeResult)
	}
}

func TestJSONErrorCarriesTypeError(t *testing.T) {
	var b bytes.Buffer
	if err := JSONError(&b, "bad", errors.New("boom")); err != nil {
		t.Fatal(err)
	}
	m := decode(t, &b)
	if m["type"] != TypeError {
		t.Errorf("type = %v, want %q", m["type"], TypeError)
	}
	if m["had_errors"] != true {
		t.Errorf("had_errors = %v, want true", m["had_errors"])
	}
}

// A session-level event must be distinguishable from command output, and must
// carry state_lost so a batch consumer knows to re-establish what it relied on.
func TestRenderEventIsTypedAndCarriesStateLost(t *testing.T) {
	var b bytes.Buffer
	if err := RenderEvent(&b, "shell_recovered", "state gone", true); err != nil {
		t.Fatal(err)
	}
	m := decode(t, &b)
	if m["type"] != TypeEvent {
		t.Errorf("type = %v, want %q", m["type"], TypeEvent)
	}
	if m["event"] != "shell_recovered" || m["state_lost"] != true {
		t.Errorf("event object = %+v, want event=shell_recovered state_lost=true", m)
	}
}

// state_lost is omitempty: a false value should not appear, so a consumer reads
// its presence-and-true as the "re-establish" signal without ambiguity.
func TestRenderEventOmitsStateLostWhenFalse(t *testing.T) {
	var b bytes.Buffer
	if err := RenderEvent(&b, "input_error", "read failed", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := decode(t, &b)["state_lost"]; ok {
		t.Error("state_lost present for a false value; want it omitted")
	}
}
