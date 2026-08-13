package cli

import (
	"strings"
	"testing"
)

func TestNormalizeFingerprint(t *testing.T) {
	// 32 bytes = 64 hex chars.
	base := strings.Repeat("ab", 32)

	ok := []string{
		base,
		strings.ToUpper(base),
		// colon-separated, the form openssl / browsers print
		strings.Join(splitPairs(base), ":"),
		"  " + strings.Join(splitPairs(base), ":") + "\n",
	}
	for _, in := range ok {
		got, err := NormalizeFingerprint(in)
		if err != nil {
			t.Errorf("NormalizeFingerprint(%q) errored: %v", in, err)
			continue
		}
		if len(got) != 32 {
			t.Errorf("NormalizeFingerprint(%q) = %d bytes, want 32", in, len(got))
		}
	}

	bad := map[string]string{
		"too short":   "aabb",
		"not hex":     strings.Repeat("zz", 32),
		"odd nibbles": base + "a",
	}
	for name, in := range bad {
		if _, err := NormalizeFingerprint(in); err == nil {
			t.Errorf("%s: NormalizeFingerprint(%q) should have errored", name, in)
		}
	}
}

// FormatFingerprint output must round-trip back through NormalizeFingerprint.
func TestFingerprintRoundTrip(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	s := FormatFingerprint(raw)
	if !strings.Contains(s, ":") {
		t.Errorf("FormatFingerprint should be colon-separated, got %q", s)
	}
	back, err := NormalizeFingerprint(s)
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if string(back) != string(raw) {
		t.Errorf("round trip changed the bytes: %x -> %q -> %x", raw, s, back)
	}
}

func splitPairs(s string) []string {
	var out []string
	for i := 0; i+2 <= len(s); i += 2 {
		out = append(out, s[i:i+2])
	}
	return out
}
