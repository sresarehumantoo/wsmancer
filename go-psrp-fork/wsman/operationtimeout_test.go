package wsman

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

func parsePT(t *testing.T, s string) int {
	t.Helper()
	if !strings.HasPrefix(s, "PT") || !strings.HasSuffix(s, "S") {
		t.Fatalf("not an ISO PTnS duration: %q", s)
	}
	n, err := strconv.Atoi(s[2 : len(s)-1])
	if err != nil {
		t.Fatalf("bad duration %q: %v", s, err)
	}
	return n
}

func TestOperationTimeout(t *testing.T) {
	// No deadline: the default is used verbatim.
	if got := operationTimeout(context.Background(), 20*time.Second); got != "PT20S" {
		t.Errorf("no deadline: got %q, want PT20S", got)
	}

	// Deadline well beyond the default: the default still caps it.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	if got := operationTimeout(ctx, 20*time.Second); got != "PT20S" {
		t.Errorf("far deadline: got %q, want PT20S (default cap)", got)
	}

	// Deadline shorter than the default (the drain-receive case: 10s ctx vs 20s
	// default): the poll must be capped well under the deadline so the server
	// replies before the socket deadline fires.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	got := parsePT(t, operationTimeout(ctx2, 20*time.Second))
	if got < 1 || got > 7 { // 10 - 3s margin, minus a little elapsed time
		t.Errorf("10s deadline: got PT%dS, want between 1 and 7 (< deadline - margin)", got)
	}

	// Deadline at/under the margin: floored to a positive value, never zero or
	// negative (which would make the server reject or return instantly).
	ctx3, cancel3 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel3()
	if got := parsePT(t, operationTimeout(ctx3, 20*time.Second)); got < 1 {
		t.Errorf("tight deadline: got PT%dS, want >= 1", got)
	}
}

// The Receive poll default is the dominant term in Ctrl-C latency (the terminate
// waits out the in-flight poll), so it is tunable — and must stay a sane, whole
// number of seconds however it is set.
func TestDefaultReceivePoll(t *testing.T) {
	t.Setenv("WSMANCER_POLL_SECONDS", "")
	if got := defaultReceivePoll(); got != time.Second {
		t.Errorf("unset: got %v, want 1s", got)
	}

	t.Setenv("WSMANCER_POLL_SECONDS", "4")
	if got := defaultReceivePoll(); got != 4*time.Second {
		t.Errorf("override: got %v, want 4s", got)
	}

	// Garbage and non-positive values fall back rather than producing a poll of
	// zero (which would spin the receive loop against the server).
	for _, bad := range []string{"nonsense", "0", "-3", "1.5"} {
		t.Setenv("WSMANCER_POLL_SECONDS", bad)
		if got := defaultReceivePoll(); got != time.Second {
			t.Errorf("%q: got %v, want the 1s default", bad, got)
		}
	}
}

// The property that actually prevents the connection teardown: for any deadline,
// the chosen operation timeout must leave the server time to reply before the
// caller's deadline (which the transport uses as the socket read deadline).
func TestOperationTimeoutStaysUnderDeadline(t *testing.T) {
	for _, remaining := range []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 60 * time.Second} {
		ctx, cancel := context.WithTimeout(context.Background(), remaining)
		secs := parsePT(t, operationTimeout(ctx, 60*time.Second))
		cancel()
		if time.Duration(secs)*time.Second >= remaining {
			t.Errorf("remaining=%v: operation timeout PT%dS is not under the deadline", remaining, secs)
		}
	}
}
