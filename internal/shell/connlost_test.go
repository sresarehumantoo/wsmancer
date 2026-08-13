package shell

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"syscall"
	"testing"
)

// The positive cases are the VERBATIM error strings observed by severing the TCP
// connection under a live session.
// Hand-invented approximations would not prove the classifier survives the
// four-layer wrapping the real transport produces.
func TestConnectionLostRecognisesRealTransportErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{
			"mid-command break, surfaced through the pipeline reader",
			errors.New(`read fragment header: wsman receive: receive: transport: request failed: ` +
				`Post "http://10.0.0.1:5985/wsman": dial 10.0.0.1:5985: dial tcp 10.0.0.1:5985: ` +
				`i/o timeout (Client.Timeout exceeded while awaiting headers)`),
		},
		{
			"peer reset while reading a sealed response",
			errors.New(`read response: read tcp 10.0.0.2:46572->10.0.0.1:5985: read: connection reset by peer`),
		},
		{
			"write to a severed connection",
			errors.New(`write: write tcp 10.0.0.2:50018->10.0.0.1:5985: i/o timeout`),
		},
		// Sentinel-reachable forms: the fork wraps some failures with %w, so these
		// must be caught without relying on the message text at all.
		{"wrapped ECONNRESET", fmt.Errorf("wsman receive: %w", syscall.ECONNRESET)},
		{"wrapped EPIPE", fmt.Errorf("send: %w", syscall.EPIPE)},
		{"wrapped unexpected EOF", fmt.Errorf("read fragment blob: %w", io.ErrUnexpectedEOF)},
		{
			"net.Error timeout behind url.Error",
			&url.Error{Op: "Post", URL: "http://h/wsman", Err: &net.OpError{
				Op: "read", Net: "tcp", Err: &timeoutErr{}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !connectionLost(tc.err) {
				t.Errorf("connectionLost() = false for a real connection loss:\n  %v", tc.err)
			}
		})
	}
}

// The classifier replaces the error text shown to the operator, so a false
// positive would hide a genuine command failure behind "run it again".
func TestConnectionLostIgnoresOrdinaryErrors(t *testing.T) {
	cases := []error{
		nil,
		errors.New("upload: local file not found: /tmp/nope"),
		errors.New(`The term 'foo' is not recognized as the name of a cmdlet`),
		errors.New("signal terminate 1C5D11D7: fault 2150858843"),
		errors.New("Access is denied"),
		// A WinRM operation timing out server-side is a normal, non-fatal poll
		// result -- not the connection dying.
		errors.New("w:TimedOut"),
	}
	for _, err := range cases {
		if connectionLost(err) {
			t.Errorf("connectionLost() = true for an ordinary error: %v", err)
		}
	}
}

type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "i/o deadline exceeded" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }
