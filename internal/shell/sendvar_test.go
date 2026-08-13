package shell

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// payload builds a base64-alphabet string of n characters. The content does not
// matter to the chunker, only the length.
func payload(n int) string {
	return strings.Repeat("QUJD", (n+3)/4)[:n]
}

// captured reassembles what the chunk commands would have built on the target,
// so a test asserts the *result* of streaming rather than the exact command text.
type captured struct {
	scripts []string
	value   string
}

func (c *captured) run(script string) error {
	c.scripts = append(c.scripts, script)
	body := script[strings.Index(script, "'")+1 : len(script)-1]
	if strings.Contains(script, " = '") {
		c.value = body
	} else {
		c.value += body
	}
	return nil
}

func TestStreamB64VarReassemblesExactly(t *testing.T) {
	// Deliberately not a chunk multiple, so the final short chunk is exercised.
	want := payload(scriptChunk*3 + 137)
	var c captured
	if err := streamB64Var("__ewbin", want, nil, c.run); err != nil {
		t.Fatalf("streamB64Var: %v", err)
	}
	if c.value != want {
		t.Errorf("reassembled %d bytes, want %d", len(c.value), len(want))
	}
	if len(c.scripts) != 4 {
		t.Errorf("sent %d chunks, want 4", len(c.scripts))
	}
	// Only the first command may assign; the rest must append, or the target ends
	// up holding just the last chunk.
	if !strings.HasPrefix(c.scripts[0], "$global:__ewbin = '") {
		t.Errorf("first chunk does not assign: %.40q", c.scripts[0])
	}
	for _, s := range c.scripts[1:] {
		if !strings.HasPrefix(s, "$global:__ewbin += '") {
			t.Errorf("later chunk does not append: %.40q", s)
		}
	}
}

func TestStreamB64VarCtrlCStopsSendingAndReportsCancelled(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	var c captured
	// Interrupt while the second of four chunks is in flight.
	run := func(script string) error {
		if len(c.scripts) == 1 {
			sigs <- os.Interrupt
		}
		return c.run(script)
	}

	err := streamB64Var("__ewdonut", payload(scriptChunk*4), sigs, run)
	if !errors.Is(err, errPayloadCancelled) {
		t.Fatalf("err = %v, want errPayloadCancelled", err)
	}
	// reportErr suppresses context.Canceled, which is how the "^C" line stays the
	// only thing the operator sees. Callers re-wrap with %w, so the chain must
	// survive that too.
	if !errors.Is(err, context.Canceled) {
		t.Error("cancellation does not unwrap to context.Canceled; reportErr would print it raw")
	}
	if len(c.scripts) != 2 {
		t.Errorf("sent %d chunks after Ctrl-C, want 2 (abort must stop the stream)", len(c.scripts))
	}
}

// The regression the fix exists for: a Ctrl-C arriving during the *final* chunk
// must be consumed here. Checking the signal only at the top of the loop would
// leave it buffered in the cap-1 channel for the next executeAs to drain, which
// then terminates a command the operator never meant to stop.
func TestStreamB64VarConsumesCtrlCOnFinalChunk(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	var c captured
	run := func(script string) error {
		sigs <- os.Interrupt // one chunk total, so this is the last one
		return c.run(script)
	}

	if err := streamB64Var("__wsm", payload(64), sigs, run); !errors.Is(err, errPayloadCancelled) {
		t.Fatalf("err = %v, want errPayloadCancelled", err)
	}
	select {
	case <-sigs:
		t.Error("Ctrl-C left buffered; it would cancel the next command instead")
	default:
	}
}

func TestStreamB64VarPropagatesRunError(t *testing.T) {
	boom := errors.New("envelope too large")
	sent := 0
	err := streamB64Var("__wsm", payload(scriptChunk*3), nil, func(string) error {
		sent++
		if sent == 2 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if sent != 2 {
		t.Errorf("sent %d chunks, want 2 (a failed chunk must stop the stream)", sent)
	}
}
