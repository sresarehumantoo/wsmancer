package krbseal

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

// TestRotateInverse proves the RRC rotation helpers are exact inverses.
func TestRotateInverse(t *testing.T) {
	for _, n := range []int{0, 1, 7, 16, 28, 40} {
		b := make([]byte, 64)
		rand.Read(b)
		if got := rotateLeft(rotateRight(b, n), n); !bytes.Equal(got, b) {
			t.Fatalf("rotate n=%d not inverse", n)
		}
	}
}

// TestSealPlumbing proves the wrap token structure + RC4/AES crypto + rotation
// are internally self-consistent: a token sealed as initiator, when rotated
// back and decrypted with the same key usage, recovers plaintext||header.
// (The only thing this does NOT prove is Windows's RRC/usage convention, which
// requires a live acceptor that issues an AES session key.)
func TestSealPlumbing(t *testing.T) {
	kv := make([]byte, 32)
	rand.Read(kv)
	key := types.EncryptionKey{KeyType: 18, KeyValue: kv} // aes256-cts-hmac-sha1-96

	s, err := newSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("<s:Envelope>whoami</s:Envelope>")

	sig, data, err := s.wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	token := append(append([]byte{}, sig...), data...)
	// Reverse: un-rotate by the RRC we wrote, decrypt with the SAME usage.
	hdr := token[:16]
	rrc := int(uint16(hdr[6])<<8 | uint16(hdr[7]))
	cipher := rotateLeft(token[16:], rrc)
	dec, err := crypto.DecryptMessage(cipher, key, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.HasPrefix(dec, plain) {
		t.Fatalf("plaintext not recovered: got %q", dec)
	}
	if len(dec) != len(plain)+16 {
		t.Fatalf("expected plaintext||16-byte-header, got %d bytes", len(dec))
	}
}

// rc4Sealer returns a sealer on a random arcfour-hmac session key.
func rc4Sealer(t *testing.T) *sealer {
	t.Helper()
	kv := make([]byte, 16)
	rand.Read(kv)
	s, err := newSealer(types.EncryptionKey{KeyType: 23, KeyValue: kv}) // rc4-hmac
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// aesSealer returns a sealer on a random aes256-cts-hmac-sha1-96 session key.
func aesSealer(t *testing.T) *sealer {
	t.Helper()
	kv := make([]byte, 32)
	rand.Read(kv)
	s, err := newSealer(types.EncryptionKey{KeyType: 18, KeyValue: kv})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// packContainer builds the WinRM multipart/encrypted body around an
// already-sealed (sig, data), the way a server would. wrapHTTP cannot be used
// for this because it seals as the initiator.
func packContainer(sig, data []byte, plainLen int) []byte {
	var b bytes.Buffer
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("\tContent-Type: " + protocol + "\r\n")
	fmt.Fprintf(&b, "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n", plainLen)
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("\tContent-Type: application/octet-stream\r\n")
	lb := make([]byte, 4)
	binary.LittleEndian.PutUint32(lb, uint32(len(sig)))
	b.Write(lb)
	b.Write(sig)
	b.Write(data)
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes()
}

// TestRC4RoundTrip proves the RFC 4757 RC4-HMAC wrap/unwrap are inverse.
// It seals as the *acceptor*, because that is what unwrap is for and what the
// direction tag makes it demand, see TestRC4RejectsReflectedOwnToken.
func TestRC4RoundTrip(t *testing.T) {
	s := rc4Sealer(t)
	for _, plain := range [][]byte{[]byte("x"), []byte("whoami\r\n"), bytes.Repeat([]byte("A"), 137)} {
		sig, data, err := s.wrapAs(plain, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.unwrapRC4(sig, data, len(plain))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("rc4 round-trip mismatch: got %q want %q", got, plain)
		}
	}
}

// TestRC4RejectsTamperedCiphertext is the test that matters most in this file.
// RC4 is a length-preserving stream cipher, so XORing a delta into the
// ciphertext XORs it into the plaintext: an in-path attacker on 5985 picks the
// operator's output byte for byte. Only SGN_CKSUM covers the payload, so an
// unwrap that skipped the check would return exactly the attacker's text, and
// this asserts on that text, not merely on "an error happened", so it cannot
// pass by coincidence.
func TestRC4RejectsTamperedCiphertext(t *testing.T) {
	s := rc4Sealer(t)
	plain := []byte("<Objs>Administrator</Objs>")
	chosen := []byte("<Objs>GUEST........</Objs>")

	sig, data, err := s.wrapAs(plain, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, data...)
	for i := range tampered {
		tampered[i] ^= plain[i] ^ chosen[i]
	}

	got, err := s.unwrapRC4(sig, tampered, len(plain))
	if err == nil {
		t.Fatalf("accepted tampered ciphertext, returned %q", got)
	}
	if !errors.Is(err, errBadSignature) {
		t.Fatalf("want errBadSignature, got %v", err)
	}
	if bytes.Equal(got, chosen) {
		t.Fatalf("returned the attacker's chosen plaintext alongside the error")
	}
}

// TestRC4RejectsTamperedChecksum covers the other half: flipping SGN_CKSUM
// itself. That garbles the derived keys rather than being caught directly, so
// this proves the recompute-and-compare still turns it into a rejection.
func TestRC4RejectsTamperedChecksum(t *testing.T) {
	s := rc4Sealer(t)
	plain := []byte("whoami")
	sig, data, err := s.wrapAs(plain, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(sig, rc4OID)
	sgn := sig[i+len(rc4OID)+16:][:8] // token[16:24]
	sgn[3] ^= 0x40

	if got, err := s.unwrapRC4(sig, data, len(plain)); err == nil {
		t.Fatalf("accepted a token with a flipped checksum, returned %q", got)
	}
}

// TestRC4RejectsReflectedOwnToken proves the direction tag is enforced, and is
// the one reflection test that pins a real check: RFC 4757 uses one key for
// both directions, so the client's own request bounced back at it recomputes a
// valid SGN_CKSUM. Deleting the tag check makes this test fail, nothing else
// catches it.
func TestRC4RejectsReflectedOwnToken(t *testing.T) {
	s := rc4Sealer(t)
	plain := []byte("whoami")
	sig, data, err := s.wrap(plain) // initiator direction, as production sends
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.unwrapRC4(sig, data, len(plain)); err == nil {
		t.Fatalf("accepted our own reflected request, returned %q", got)
	}
}

// TestAESRejectsTamperedCiphertext proves the AES path rejects altered
// ciphertext. Integrity here comes from the etype's own HMAC inside
// crypto.DecryptMessage; this pins that a failure there is surfaced as
// errBadSignature rather than being reported as a decode problem.
func TestAESRejectsTamperedCiphertext(t *testing.T) {
	s := aesSealer(t)
	plain := []byte("<Objs>Administrator</Objs>")
	sig, data, err := s.wrapAs(plain, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, data...)
	tampered[0] ^= 0x01

	got, err := s.unwrap(sig, tampered, len(plain))
	if err == nil {
		t.Fatalf("accepted tampered AES ciphertext, returned %q", got)
	}
	if !errors.Is(err, errBadSignature) {
		t.Fatalf("want errBadSignature, got %v", err)
	}
}

// TestAESRejectsTamperedHeader is the check the etype cannot make. The 16-byte
// token header travels in the clear next to the ciphertext, so the HMAC does
// not cover it; RFC 4121 §4.2.6.2 binds it by having the sender echo a copy
// inside the encrypted payload for the receiver to compare. Flipping a
// cleartext header byte the rotation does not depend on is undetectable without
// that comparison.
func TestAESRejectsTamperedHeader(t *testing.T) {
	s := aesSealer(t)
	plain := []byte("whoami")
	sig, data, err := s.wrapAs(plain, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	// Byte 9 is part of the 64-bit sequence number: in the clear, echoed
	// inside, and not an input to decryption.
	tampered := append([]byte{}, sig...)
	tampered[9] ^= 0x01

	got, err := s.unwrap(tampered, data, len(plain))
	if err == nil {
		t.Fatalf("accepted a token whose cleartext header was altered, returned %q", got)
	}
	if !errors.Is(err, errBadSignature) {
		t.Fatalf("want errBadSignature, got %v", err)
	}
}

// TestAESRejectsReflectedOwnToken proves a reflected client token is refused.
// Note what actually refuses it: AES keys the two directions separately, so the
// ACCEPTOR_SEAL usage fails to decrypt an INITIATOR_SEAL token. The header's
// SentByAcceptor flag is a nicer error, not the mechanism, deleting that check
// leaves this test passing. Contrast TestRC4RejectsReflectedOwnToken.
func TestAESRejectsReflectedOwnToken(t *testing.T) {
	s := aesSealer(t)
	plain := []byte("whoami")
	sig, data, err := s.wrap(plain) // initiator direction
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.unwrap(sig, data, len(plain)); err == nil {
		t.Fatalf("accepted our own reflected request, returned %q", got)
	}
}

// TestUnwrapHTTPVerifies proves the check is reached through the real container
// parser, not only when unwrap is called directly, the transport's entry point
// is unwrapHTTP.
func TestUnwrapHTTPVerifies(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    *sealer
	}{{"rc4", rc4Sealer(t)}, {"aes", aesSealer(t)}} {
		t.Run(tc.name, func(t *testing.T) {
			plain := bytes.Repeat([]byte("A"), 64)
			sig, data, err := tc.s.wrapAs(plain, 0, true)
			if err != nil {
				t.Fatal(err)
			}
			body := packContainer(sig, data, len(plain))

			if got, err := tc.s.unwrapHTTP(body); err != nil {
				t.Fatalf("clean body rejected: %v", err)
			} else if !bytes.Equal(got, plain) {
				t.Fatalf("clean body mismatch: %q", got)
			}

			// Flip a byte of the payload, which sits at the very end.
			bad := append([]byte{}, body...)
			bad[len(bad)-len("--"+boundary+"--\r\n")-1] ^= 0x01
			if got, err := tc.s.unwrapHTTP(bad); err == nil {
				t.Fatalf("unwrapHTTP accepted a tampered body, returned %q", got)
			} else if !errors.Is(err, errBadSignature) {
				t.Fatalf("want errBadSignature, got %v", err)
			}
		})
	}
}

// TestContainerRoundTrip proves the WinRM multipart pack/parse is exact.
func TestContainerRoundTrip(t *testing.T) {
	kv := make([]byte, 32)
	rand.Read(kv)
	key := types.EncryptionKey{KeyType: 18, KeyValue: kv}
	s, _ := newSealer(key)

	plain := bytes.Repeat([]byte("A"), 200)
	_, body, err := s.wrapHTTP(plain)
	if err != nil {
		t.Fatal(err)
	}
	// The parser must locate the token and split sig/payload at the right offset.
	pl, err := originalLength(body)
	if err != nil || pl != len(plain) {
		t.Fatalf("originalLength: %d err=%v want %d", pl, err, len(plain))
	}
}
