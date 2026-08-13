package ntlmseal

import (
	"bytes"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// Test vectors from MS-NLMP (NT LAN Manager Authentication Protocol),
// §4.2.1 "Common Values" and §4.2.4 "NTLMv2 Authentication".
//
// These are the point of this file. Everything in message_test.go recomputes
// expected values with the same primitives the production code uses, so it can
// only catch layout and slicing mistakes, a self-consistent implementation of
// the *wrong* algorithm passes it. Published vectors are independent ground
// truth, and a whole class of mutant is caught only here: ntowfv2 skipping the
// upper-case, wrap signing the ciphertext, sealKey/signKey swapping direction,
// ntlmv2Temp dropping the temp blob's trailing Z(4), and unwrap accepting a
// forged signature. Every one stays self-consistent across both ends of the
// session, so no amount of round-tripping against ourselves would notice.
// scripts/ntlmseal-mutants.sh re-proves that by deleting this file and
// reporting which mutants survive.
//
// Values cross-checked against MS-NLMP v20260330 and v20110610 (byte-identical
// where both print a value), jborean93/ntlm-auth's test suite, and Chromium's
// net/ntlm/ntlm_test_data.h.
const (
	specUser     = "User"
	specDomain   = "Domain"
	specPassword = "Password"

	specNTOWFv1                  = "a4f49c406510bdcab6824ee7c30fd852" // MD4(UTF16LE(Password))
	specNTOWFv2                  = "0c868a403bfd7a93a3001ef22ef02e3f" // §4.2.4.1.1
	specSessionBaseKey           = "8de40ccadbc14a82f15cb0ad0de95ca3" // §4.2.4.1.2; == KeyExchangeKey for NTLMv2
	specRandomSessionKey         = "55555555555555555555555555555555" // §4.2.1
	specEncryptedRandomSessionKe = "c5dad2544fc9799094ce1ce90bc9d03e" // §4.2.4.2.3
	specClientChallenge          = "aaaaaaaaaaaaaaaa"                 // §4.2.1
	specNTProofStr               = "68cd0ab851e51c96aabc927bebef6a1c" // §4.2.4.2.2

	// §4.2.4.1.3. RespType/HiRespType || Z(6) || Time(0) || ClientChallenge ||
	// Z(4) || the challenge's AV_PAIRs || Z(4).
	specTemp = "01010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c00" +
		"44006f006d00610069006e0001000c0053006500720076006500720000000000" +
		"00000000"

	// §4.2.4.3. Fed to parseType2 verbatim, so the parser is checked against a
	// real server message rather than one this package built for itself.
	specChallengeMessage = "4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef" +
		"00000000000000002400240044000000060070170000000f5300650072007600" +
		"6500720002000c0044006f006d00610069006e0001000c0053006500720076006" +
		"5007200" + "00000000"

	// §4.2.4.4 GSS_WrapEx, SeqNum 0.
	specSealPlaintext    = "50006c00610069006e007400650078007400" // UTF-16LE "Plaintext"
	specClientSealingKey = "59f600973cc4960a25480a7c196e4c58"
	specClientSigningKey = "4788dc861b4782f35d43fd98fe1a2d39"
	specSealedData       = "54e50165bf1936dc996020c1811b0f06fb5f"
	specSignature        = "010000007fb38ec5c55d497600000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test vector %q: %v", s, err)
	}
	return b
}

func TestNTOWFv2Vector(t *testing.T) {
	// MS-NLMP §3.3.2:
	//   NTOWFv2(Passwd, User, UserDom) =
	//     HMAC_MD5(MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf(Uppercase(User), UserDom)))
	// The username is upper-cased; the domain is NOT. This vector is what
	// distinguishes those two, and it is the only test in the package that can.
	ntHash := ntHashOf(specPassword)
	if want := mustHex(t, specNTOWFv1); !bytes.Equal(ntHash, want) {
		t.Fatalf("MD4(UTF16LE(%q)) = %x, want %x", specPassword, ntHash, want)
	}

	got := ntowfv2(specUser, specDomain, ntHash)
	if want := mustHex(t, specNTOWFv2); !bytes.Equal(got, want) {
		t.Errorf("NTOWFv2 = %x, want %x", got, want)
	}

	t.Run("username case does not matter", func(t *testing.T) {
		// A DC accepts the username in any case; upper-casing inside NTOWFv2 is
		// what makes that true.
		if lower := ntowfv2("user", specDomain, ntHash); !bytes.Equal(lower, got) {
			t.Errorf("lower-case user gave %x, want %x", lower, got)
		}
	})

	t.Run("domain case does matter", func(t *testing.T) {
		// The mirror of the above, and the reason ToUpper must not be applied to
		// the domain: doing so would silently break auth against a DC whose
		// domain the operator typed in lower case.
		if upper := ntowfv2(specUser, "DOMAIN", ntHash); bytes.Equal(upper, got) {
			t.Error("upper-casing the domain produced the same key; NTOWFv2 is upper-casing it")
		}
	})
}

func TestSealAndSignKeyVectors(t *testing.T) {
	exported := mustHex(t, specRandomSessionKey)

	if got, want := sealKey(exported, "client-to-server"), mustHex(t, specClientSealingKey); !bytes.Equal(got, want) {
		t.Errorf("client sealing key = %x, want %x", got, want)
	}
	if got, want := signKey(exported, "client-to-server"), mustHex(t, specClientSigningKey); !bytes.Equal(got, want) {
		t.Errorf("client signing key = %x, want %x", got, want)
	}

	t.Run("the magic constant is NUL-terminated", func(t *testing.T) {
		// MS-NLMP §3.4.5.2/3.4.5.3 call these "the null-terminated ASCII
		// constants shown", but the trailing NUL is not visible in the quoted
		// literal. Dropping it yields a plausible-looking 16-byte key that
		// simply does not match the server's, sealing then produces garbage
		// with no error anywhere. The vector above is the only thing that
		// catches it, so pin the negative case explicitly.
		noNUL := md5concat(exported, "session key to client-to-server sealing key magic constant")
		if bytes.Equal(noNUL, mustHex(t, specClientSealingKey)) {
			t.Fatal("the NUL byte made no difference; the vector cannot be discriminating")
		}
	})

	t.Run("the two directions differ", func(t *testing.T) {
		// MS-NLMP §4.2.4.4 publishes only the client-to-server pair, so the
		// server-direction keys cannot be vector-checked here. Assert the
		// property that actually matters, that they are derived from a
		// different constant, rather than inventing a vector for them.
		for _, k := range []struct {
			name       string
			cli, srv   []byte
			mustDiffer bool
		}{
			{"sealing", sealKey(exported, "client-to-server"), sealKey(exported, "server-to-client"), true},
			{"signing", signKey(exported, "client-to-server"), signKey(exported, "server-to-client"), true},
		} {
			if k.mustDiffer && bytes.Equal(k.cli, k.srv) {
				t.Errorf("%s: both directions derived the same key %x", k.name, k.cli)
			}
			if len(k.srv) != 16 {
				t.Errorf("%s: server key is %d bytes, want 16", k.name, len(k.srv))
			}
		}
	})
}

// TestWrapVector is the single highest-value test in the package: one call
// covers the RC4 keystream's continuity across data and checksum, the HMAC
// input (plaintext, not ciphertext), the encrypt-the-checksum rule that applies
// when key exchange is negotiated, and the 16-byte signature layout.
func TestWrapVector(t *testing.T) {
	k := newSessionKeys(mustHex(t, specRandomSessionKey))
	plain := mustHex(t, specSealPlaintext)

	sig, sealed := k.wrap(plain)

	if want := mustHex(t, specSealedData); !bytes.Equal(sealed, want) {
		t.Errorf("sealed data = %x, want %x", sealed, want)
	}
	if want := mustHex(t, specSignature); !bytes.Equal(sig, want) {
		t.Errorf("signature = %x, want %x", sig, want)
	}

	t.Run("the checksum consumes the keystream after the data", func(t *testing.T) {
		// MS-NLMP passes one RC4 Handle to both operations, so the checksum is
		// encrypted with the keystream bytes *following* those the message
		// consumed. Re-keying RC4 for the checksum yields a wrong-but-plausible
		// signature; this shows the spec's answer requires the continued stream.
		rekeyed := rc4crypt(mustHex(t, specClientSealingKey), []byte{0x70, 0x35, 0x28, 0x51, 0xf2, 0x56, 0x43, 0x09})
		if bytes.Equal(rekeyed, mustHex(t, specSignature)[4:12]) {
			t.Fatal("a re-keyed RC4 reproduced the spec's checksum; this test cannot discriminate")
		}
	})
}

// TestUnwrapAcceptsTheSpecSignature drives the receive path with MS-NLMP's own
// sealed message and signature. The spec publishes only the client-to-server
// direction, so the session's *server* slots are loaded with the client keys,
// that makes the spec's bytes an inbound message and lets the real unwrap,
// including its integrity check, be tested against published data rather than
// against whatever this package's wrap happened to produce.
func TestUnwrapAcceptsTheSpecSignature(t *testing.T) {
	newInbound := func() *sessionKeys {
		exported := mustHex(t, specRandomSessionKey)
		c, err := rc4.NewCipher(sealKey(exported, "client-to-server"))
		if err != nil {
			t.Fatal(err)
		}
		return &sessionKeys{serverSeal: c, serverSign: signKey(exported, "client-to-server")}
	}

	t.Run("accepts the spec's message", func(t *testing.T) {
		plain, err := newInbound().unwrap(mustHex(t, specSignature), mustHex(t, specSealedData))
		if err != nil {
			t.Fatalf("unwrap rejected MS-NLMP's own signed message: %v", err)
		}
		if want := mustHex(t, specSealPlaintext); !bytes.Equal(plain, want) {
			t.Errorf("plaintext = %x, want %x", plain, want)
		}
	})

	// Each of these is a message an in-path attacker could produce on plain
	// HTTP/5985. Before the check went in, every one of them was accepted and
	// its (attacker-chosen) plaintext handed to the caller.
	t.Run("rejects tampering", func(t *testing.T) {
		flip := func(s string, i int) []byte {
			b := mustHex(t, s)
			b[i] ^= 0x01
			return b
		}
		cases := []struct {
			name      string
			sig, data []byte
			wantErrIs bool
		}{
			{"flipped ciphertext bit", mustHex(t, specSignature), flip(specSealedData, 0), true},
			{"flipped ciphertext bit, late", mustHex(t, specSignature), flip(specSealedData, 17), true},
			{"flipped checksum bit", flip(specSignature, 4), mustHex(t, specSealedData), true},
			{"zeroed signature", make([]byte, 16), mustHex(t, specSealedData), true},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				_, err := newInbound().unwrap(c.sig, c.data)
				if err == nil {
					t.Fatal("tampered message was accepted")
				}
				if c.wantErrIs && !errors.Is(err, errBadSignature) {
					t.Errorf("error = %v, want errBadSignature", err)
				}
			})
		}
	})

	t.Run("rejects a replayed sequence number", func(t *testing.T) {
		// The spec's message is SeqNum 0. Present it to a session that has
		// already accepted message 0, and it must not be taken again.
		k := newInbound()
		if _, err := k.unwrap(mustHex(t, specSignature), mustHex(t, specSealedData)); err != nil {
			t.Fatal(err)
		}
		if _, err := k.unwrap(mustHex(t, specSignature), mustHex(t, specSealedData)); err == nil {
			t.Fatal("a replayed message was accepted")
		}
	})

	t.Run("rejects an altered sequence number", func(t *testing.T) {
		// The declared sequence in sig[12:16] is NOT covered by the checksum,
		// the HMAC is computed over the receiver's own counter, so an attacker
		// can rewrite it without disturbing anything else. Only the explicit
		// comparison against our counter catches this, and the replay case
		// above does not: there the counter had advanced, so the checksum
		// failed first and the sequence check never got a say. Removing the
		// sequence check was a MISSED mutant until this test existed.
		sig := mustHex(t, specSignature)
		binary.LittleEndian.PutUint32(sig[12:16], 7)
		_, err := newInbound().unwrap(sig, mustHex(t, specSealedData))
		if err == nil {
			t.Fatal("a message with an altered sequence number was accepted")
		}
		if errors.Is(err, errBadSignature) {
			t.Errorf("rejected by the checksum, not the sequence check: %v", err)
		}
		if !errors.Is(err, errOutOfSequence) {
			t.Errorf("error = %v, want errOutOfSequence", err)
		}
	})

	t.Run("rejects a malformed signature length", func(t *testing.T) {
		for _, n := range []int{0, 8, 12, 15, 17} {
			if _, err := newInbound().unwrap(make([]byte, n), mustHex(t, specSealedData)); err == nil {
				t.Errorf("accepted a %d-byte signature", n)
			}
		}
	})
}

func TestKeyExchangeVector(t *testing.T) {
	// For NTLMv2 the KeyExchangeKey is the SessionBaseKey verbatim (§3.4.5.1),
	// and the exported key is RC4-wrapped under it.
	got := rc4crypt(mustHex(t, specSessionBaseKey), mustHex(t, specRandomSessionKey))
	if want := mustHex(t, specEncryptedRandomSessionKe); !bytes.Equal(got, want) {
		t.Errorf("EncryptedRandomSessionKey = %x, want %x", got, want)
	}
}

// TestNTLMv2ResponseAgainstSpecVector checks the credential proof this client
// sends a DC against MS-NLMP's published values, end to end: the temp blob's
// field order and Z(4) padding, the NTProofStr HMAC over it, the full
// NtChallengeResponse, the SessionBaseKey/KeyExchangeKey identity, and the
// key-exchange wrap.
//
// It drives the extracted helpers rather than type3 itself, because type3
// necessarily supplies a random client challenge and a real clock, the vector
// needs a fixed 0xaa… challenge and a zero FILETIME. TestType3UsesTheVerified
// Helpers below closes the remaining gap by proving type3 wires these same
// functions up correctly, so the two together cover the whole path without any
// test-only indirection in the production code.
func TestNTLMv2ResponseAgainstSpecVector(t *testing.T) {
	// Guard the transcription itself: the spec renders these as offset-labeled
	// hex dumps, and a dropped byte would silently shift every field.
	if n := len(mustHex(t, specChallengeMessage)); n != 104 {
		t.Fatalf("CHALLENGE_MESSAGE vector is %d bytes, want 104", n)
	}
	if n := len(mustHex(t, specTemp)); n != 68 {
		t.Fatalf("temp vector is %d bytes, want 68", n)
	}

	ch, err := parseType2(mustHex(t, specChallengeMessage))
	if err != nil {
		t.Fatalf("parseType2 rejected the spec's CHALLENGE_MESSAGE: %v", err)
	}

	t.Run("parses the spec's challenge message", func(t *testing.T) {
		if want := mustHex(t, "0123456789abcdef"); !bytes.Equal(ch.serverChallenge, want) {
			t.Errorf("serverChallenge = %x, want %x", ch.serverChallenge, want)
		}
		if len(ch.targetInfo) != 36 {
			t.Errorf("targetInfo = %d bytes, want 36", len(ch.targetInfo))
		}
	})

	// §4.2.1: Time is a zero FILETIME and ClientChallenge is 0xaa repeated.
	temp := ntlmv2Temp(make([]byte, 8), mustHex(t, specClientChallenge), ch.targetInfo)
	respKeyNT := ntowfv2(specUser, specDomain, ntHashOf(specPassword))
	ntProof, ntResponse := ntlmv2Response(respKeyNT, ch.serverChallenge, temp)
	kek := keyExchangeKey(respKeyNT, ntProof)

	t.Run("temp blob matches the spec byte for byte", func(t *testing.T) {
		if want := mustHex(t, specTemp); !bytes.Equal(temp, want) {
			t.Errorf("temp = %x\nwant = %x", temp, want)
		}
	})

	t.Run("NTProofStr matches the spec", func(t *testing.T) {
		if want := mustHex(t, specNTProofStr); !bytes.Equal(ntProof, want) {
			t.Errorf("NTProofStr = %x, want %x", ntProof, want)
		}
	})

	t.Run("full NtChallengeResponse matches the spec", func(t *testing.T) {
		want := append(mustHex(t, specNTProofStr), mustHex(t, specTemp)...)
		if len(want) != 84 {
			t.Fatalf("vector assembly is wrong: %d bytes, want 84", len(want))
		}
		if !bytes.Equal(ntResponse, want) {
			t.Errorf("NtChallengeResponse = %x\nwant                = %x", ntResponse, want)
		}
	})

	t.Run("KeyExchangeKey is the SessionBaseKey", func(t *testing.T) {
		if want := mustHex(t, specSessionBaseKey); !bytes.Equal(kek, want) {
			t.Errorf("KeyExchangeKey = %x, want %x", kek, want)
		}
	})

	t.Run("the exported key wraps to the spec's blob", func(t *testing.T) {
		got := rc4crypt(kek, mustHex(t, specRandomSessionKey))
		if want := mustHex(t, specEncryptedRandomSessionKe); !bytes.Equal(got, want) {
			t.Errorf("EncryptedRandomSessionKey = %x, want %x", got, want)
		}
	})
}

// TestType3UsesTheVerifiedHelpers is the other half of the vector check above:
// it proves the AUTHENTICATE_MESSAGE type3 actually emits was built by those
// same, spec-verified functions, with the server's target info and timestamp,
// and the client challenge it generated. Without this, the helpers could be
// perfect and type3 could still call them with the wrong arguments.
func TestType3UsesTheVerifiedHelpers(t *testing.T) {
	ts := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	ti := bytes.Join([][]byte{
		avPair(2, utf16le("HTB")),
		avPair(7, ts),
		avPair(0, nil),
	}, nil)
	sc := mustHex(t, "0123456789abcdef")

	p, err := New(Config{User: "testuser", Domain: "example.local", Password: "testpass"})
	if err != nil {
		t.Fatal(err)
	}
	t1, t2 := p.type1(), buildType2(sc, ti)
	ch, err := parseType2(t2)
	if err != nil {
		t.Fatal(err)
	}
	msg, exported, err := p.type3(ch, t1, t2)
	if err != nil {
		t.Fatal(err)
	}
	got := parseType3(t, msg)

	// Recover the one input only type3 knows, the client challenge it drew,
	// then rebuild the whole response through the vector-verified helpers and
	// require the message to match it exactly.
	clientChallenge := got.nt[16:][16:24]
	respKeyNT := ntowfv2("testuser", "example.local", ntHashOf("testpass"))
	wantTemp := ntlmv2Temp(ts, clientChallenge, ti)
	wantProof, wantResponse := ntlmv2Response(respKeyNT, sc, wantTemp)

	if !bytes.Equal(got.nt, wantResponse) {
		t.Errorf("NtChallengeResponse = %x\nwant                = %x", got.nt, wantResponse)
	}
	if !bytes.Equal(got.esk, rc4crypt(keyExchangeKey(respKeyNT, wantProof), exported)) {
		t.Error("EncryptedRandomSessionKey is not the exported key wrapped under the verified KeyExchangeKey")
	}

	t.Run("LM response is zeroed, diverging from the spec example", func(t *testing.T) {
		// MS-NLMP §4.2.4.2.1 computes a real LMv2 response, because its example
		// CHALLENGE_MESSAGE carries no MsvAvTimestamp; §3.3.2's ComputeResponse
		// likewise computes one unconditionally. This code always sends Z(24).
		//
		// §3.1.5.1.2 makes that a SHOULD (not a MUST) when a timestamp is
		// present, but the reason it is safe in general is server-side:
		// §3.2.5.1.2 only compares LmChallengeResponse inside the branch taken
		// when the NT response mismatches, so a valid NTLMv2 response means the
		// field is never read at all. See the note on lmResponse in ntlmseal.go
		// for why sending a real LMv2 would be actively worse.
		if !bytes.Equal(got.lm, make([]byte, 24)) {
			t.Errorf("LmChallengeResponse = %x, want 24 zero bytes", got.lm)
		}
	})

	t.Run("LM response is zeroed even without an MsvAvTimestamp", func(t *testing.T) {
		// The behavior is unconditional, so pin it against a challenge that
		// carries no timestamp, the case §3.1.5.1.2's SHOULD does not cover,
		// and the one a non-Windows acceptor (Responder, pre-4.2.11 Samba)
		// actually produces. A conditional implementation would emit a real
		// LMv2 here and this would fail.
		noTS := append(avPair(2, utf16le("HTB")), avPair(0, nil)...)
		t2 := buildType2(sc, noTS)
		ch, err := parseType2(t2)
		if err != nil {
			t.Fatal(err)
		}
		msg, _, err := p.type3(ch, t1, t2)
		if err != nil {
			t.Fatal(err)
		}
		if lm := parseType3(t, msg).lm; !bytes.Equal(lm, make([]byte, 24)) {
			t.Errorf("LmChallengeResponse = %x, want 24 zero bytes", lm)
		}
	})
}
