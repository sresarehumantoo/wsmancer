package ntlmseal

import (
	"context"
	"testing"
	"time"
)

// The socket deadline is load-bearing in two opposite directions, and both are
// easy to break silently:
//
//   - never zero, or a blackholed connection (dropped VPN, NAT timeout) leaves
//     the response read blocked in netpoll forever and wedges the shell;
//   - never shorter than a legitimate server-side hold, or a healthy long-poll
//     looks like a dead connection, tearing down the connection and re-dialling
//     a fresh WSMan session mid-work -- the churn bug fix (A) removed.
func TestWriteDeadlineNeverZero(t *testing.T) {
	got := writeDeadline(context.Background())
	if got.IsZero() {
		t.Fatal("writeDeadline() returned the zero time: a severed connection would hang forever")
	}
	if d := time.Until(got); d < 90*time.Second {
		t.Errorf("backstop is %v; too close to the PT60S server holds to be safe", d)
	}
}

func TestWriteDeadlineHonoursCallerDeadline(t *testing.T) {
	// A caller that set its own (shorter) deadline must win: that is how the
	// Ctrl-C stop budget and the drain receive bound themselves.
	want := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), want)
	defer cancel()
	if got := writeDeadline(ctx); !got.Equal(want) {
		t.Errorf("writeDeadline() = %v, want the caller's %v", got, want)
	}
}

func TestWriteDeadlineBackstopExceedsServerHolds(t *testing.T) {
	// WSMan advertises PT60S on Create/Command/Send/Signal/Delete. The backstop
	// has to clear that plus network RTT, or it fires during normal operation.
	const longestAdvertisedHold = 60 * time.Second
	if deadCommsBackstop <= longestAdvertisedHold {
		t.Fatalf("deadCommsBackstop %v <= longest advertised hold %v: healthy "+
			"long-polls would be torn down as dead connections",
			deadCommsBackstop, longestAdvertisedHold)
	}
}

// A cancel-only context (what a running command has) must still get the
// backstop -- that is precisely the case that used to hang.
func TestWriteDeadlineCancelOnlyContextGetsBackstop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if writeDeadline(ctx).IsZero() {
		t.Fatal("a cancel-only context got no deadline: this is the hang")
	}
}
