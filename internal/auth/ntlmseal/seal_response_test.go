package ntlmseal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http"
	"testing"
)

func TestIsSealedResponse(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{`multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`, true},
		{"application/soap+xml;charset=UTF-8", false},
		{"text/html", false},
		{"", false},
	}
	for _, c := range cases {
		resp := &http.Response{Header: http.Header{}}
		if c.ct != "" {
			resp.Header.Set("Content-Type", c.ct)
		}
		if got := isSealedResponse(resp); got != c.want {
			t.Errorf("isSealedResponse(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}

// TestIntegrityFailuresAreTerminal pins the classification sealed() switches on.
// unwrap returning the right error is only half the job: the transport decides
// whether that error drops the connection or lets the body through, and the two
// halves were out of step. A reordered message returned a plain fmt.Errorf, so
// sealed() filed it under "not really ours", handed the caller raw ciphertext,
// and left the desynced connection open, live, that surfaced as an XML syntax
// error on binary bytes, not as a security failure. Every error here comes from
// a real unwrap call, so the test cannot pass by restating the sentinels.
func TestIntegrityFailuresAreTerminal(t *testing.T) {
	exported := bytes.Repeat([]byte{0x42}, 16)
	msg := []byte("a sealed server response")

	t.Run("tampered ciphertext is terminal", func(t *testing.T) {
		sig, sealed := newServerSide(exported).seal(msg)
		sealed[0] ^= 0x01
		_, err := newSessionKeys(exported).unwrap(sig, sealed)
		if err == nil || !terminalUnwrapError(err) {
			t.Fatalf("err = %v; want a terminal integrity failure", err)
		}
	})

	t.Run("out-of-sequence is terminal", func(t *testing.T) {
		// sig[12:16] is not covered by the checksum, so an attacker can rewrite
		// it alone. It must still drop the connection rather than reaching the
		// caller as an unparseable body.
		sig, sealed := newServerSide(exported).seal(msg)
		binary.LittleEndian.PutUint32(sig[12:16], 7)
		_, err := newSessionKeys(exported).unwrap(sig, sealed)
		if err == nil || !errors.Is(err, errOutOfSequence) {
			t.Fatalf("err = %v; want errOutOfSequence", err)
		}
		if !terminalUnwrapError(err) {
			t.Fatal("an out-of-sequence message was treated as a parse failure")
		}
	})

	t.Run("a body that was never sealed is not terminal", func(t *testing.T) {
		// The contrast case: this must stay non-terminal, or a proxy's plain
		// error page would start tearing down connections. It also stops the
		// two cases above from passing by making everything terminal.
		_, err := newSessionKeys(exported).unwrapHTTP([]byte("<html>502 Bad Gateway</html>"))
		if err == nil {
			t.Fatal("a non-sealed body parsed as sealed")
		}
		if terminalUnwrapError(err) {
			t.Errorf("a non-sealed body was treated as an integrity failure: %v", err)
		}
	})
}

// TestServerSealKeystreamSync is the reason sealed() now decrypts fault (non-200)
// responses instead of returning them untouched: the server-direction RC4
// keystream is stateful, so the client must unwrap every sealed server message
// or every later response on the connection decrypts to garbage. This models a
// server sealing two messages and shows that skipping the first (the old
// behavior on an HTTP 500) desyncs the second.
func TestServerSealKeystreamSync(t *testing.T) {
	exported := bytes.Repeat([]byte{0x42}, 16)

	msgA, msgB := []byte("first-response"), []byte("second-response")

	t.Run("in-sequence unwrap recovers both", func(t *testing.T) {
		srv := newServerSide(exported)
		k := newSessionKeys(exported)
		sigA, sealedA := srv.seal(msgA)
		sigB, sealedB := srv.seal(msgB)
		got, err := k.unwrap(sigA, sealedA)
		if err != nil || !bytes.Equal(got, msgA) {
			t.Fatalf("message A = %q, %v; want %q", got, err, msgA)
		}
		got, err = k.unwrap(sigB, sealedB)
		if err != nil || !bytes.Equal(got, msgB) {
			t.Fatalf("message B = %q, %v; want %q", got, err, msgB)
		}
	})

	t.Run("skipping a sealed message desyncs the next", func(t *testing.T) {
		srv := newServerSide(exported)
		k := newSessionKeys(exported)
		_, _ = srv.seal(msgA) // server sealed A...
		sigB, sealedB := srv.seal(msgB)
		// ...but the client never unwrapped A (old non-200 path). Now B is
		// decrypted against a keystream a full message behind. Since the
		// signature check went in this now surfaces as a hard error rather than
		// silent garbage, which is strictly better, but the property under
		// test is the desync itself, so accept either symptom.
		got, err := k.unwrap(sigB, sealedB)
		if err == nil && bytes.Equal(got, msgB) {
			t.Fatal("expected a desync, but B decrypted and verified cleanly")
		}
	})
}
