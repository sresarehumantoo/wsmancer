package transport

import (
	"strings"
	"testing"
)

// describeBody must never let a binary/encrypted body reach the error string
// verbatim (it would scramble a terminal that prints the error), while still
// inlining a readable text body for diagnosis. (Fork patch.)
func TestDescribeBody(t *testing.T) {
	// A parseable SOAP fault is summarized instead (see soapfault_test.go);
	// this is the fallback for everything else textual.
	t.Run("inlines a textual body", func(t *testing.T) {
		body := []byte(`{"error":"the endpoint rejected the request"}`)
		got := describeBody(body)
		if got != string(body) {
			t.Fatalf("describeBody(text) = %q, want it inlined verbatim", got)
		}
	})

	t.Run("summarizes an encrypted/binary body", func(t *testing.T) {
		body := []byte("--Encrypted Boundary\r\n\x1b[2J\x00\xff\xfe\x9b\x07 octet-stream")
		got := describeBody(body)
		if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\x00') {
			t.Fatalf("describeBody(binary) leaked control bytes: %q", got)
		}
		if !strings.Contains(got, "non-text body") {
			t.Fatalf("describeBody(binary) = %q, want a size summary", got)
		}
	})

	t.Run("bounds a very long text body", func(t *testing.T) {
		got := describeBody([]byte(strings.Repeat("A", 5000)))
		if !strings.HasSuffix(got, "...") {
			t.Fatalf("describeBody(long text) should be truncated with an ellipsis")
		}
		if len(got) > 2100 {
			t.Fatalf("describeBody(long text) = %d bytes, want it bounded", len(got))
		}
	})
}
