package ntlmseal

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// The tests in this file cover NTLM message *structure*: field offsets, lengths,
// payload placement and the self-consistency of the values the server will check
// (NTProofStr, the MIC, the key-exchange blob). They deliberately recompute those
// values with the same primitives the production code uses, so they prove the
// message is assembled and sliced correctly, not that the cryptography matches
// the spec. That second, independent claim is what vectors_test.go is for, and
// neither file is sufficient alone: a wrong-but-consistent layout passes here,
// and a correct primitive wired to the wrong offset passes there.

func utf16leDecode(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func ntHashOf(password string) []byte {
	h := md4.New()
	h.Write(utf16le(password))
	return h.Sum(nil)
}

// avPair builds a single AV_PAIR (id, length, value) as it appears in TargetInfo.
func avPair(id uint16, val []byte) []byte {
	b := make([]byte, 4+len(val))
	binary.LittleEndian.PutUint16(b[0:2], id)
	binary.LittleEndian.PutUint16(b[2:4], uint16(len(val)))
	copy(b[4:], val)
	return b
}

// buildType2 assembles a CHALLENGE_MESSAGE with TargetInfo at the given offset,
// which is what a real server sends and what parseType2 has to walk.
func buildType2(serverChallenge, targetInfo []byte) []byte {
	const hdr = 48
	b := make([]byte, hdr)
	copy(b[0:8], ntlmSig)
	binary.LittleEndian.PutUint32(b[8:12], 2)
	copy(b[24:32], serverChallenge)
	binary.LittleEndian.PutUint16(b[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(b[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(b[44:48], hdr)
	return append(b, targetInfo...)
}

func TestType1(t *testing.T) {
	p, err := New(Config{User: "u", Domain: "d", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	m := p.type1()

	// 8 signature + 4 type + 4 flags + 8 domain + 8 workstation + 8 version.
	if len(m) != 40 {
		t.Fatalf("type1 length = %d, want 40", len(m))
	}
	if !bytes.Equal(m[:8], ntlmSig) {
		t.Errorf("signature = %q, want %q", m[:8], ntlmSig)
	}
	if got := binary.LittleEndian.Uint32(m[8:12]); got != 1 {
		t.Errorf("message type = %d, want 1", got)
	}

	flags := binary.LittleEndian.Uint32(m[12:16])
	// A negotiate message that fails to ask for seal/sign/key-exchange up front
	// gets a server that never offers session security, and the sealing layer
	// silently has nothing to do.
	for _, f := range []struct {
		name string
		bit  uint32
	}{
		{"negUnicode", negUnicode},
		{"negSign", negSign},
		{"negSeal", negSeal},
		{"negNTLM", negNTLM},
		{"negExtendedSec", negExtendedSec},
		{"negKeyExch", negKeyExch},
		{"neg128", neg128},
		{"neg56", neg56},
	} {
		if flags&f.bit == 0 {
			t.Errorf("type1 flags missing %s (0x%08x); got 0x%08x", f.name, f.bit, flags)
		}
	}
	// TargetInfo is a type-2 concern; asking for it in type 1 is not.
	if flags&negTargetInfo != 0 {
		t.Errorf("type1 flags unexpectedly set negTargetInfo; got 0x%08x", flags)
	}

	if !bytes.Equal(m[16:24], make([]byte, 8)) {
		t.Errorf("DomainNameFields = % x, want all zero", m[16:24])
	}
	if !bytes.Equal(m[24:32], make([]byte, 8)) {
		t.Errorf("WorkstationFields = % x, want all zero", m[24:32])
	}
	if !bytes.Equal(m[32:40], osVersion()) {
		t.Errorf("Version = % x, want % x", m[32:40], osVersion())
	}
}

func TestParseType2(t *testing.T) {
	sc := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ti := append(avPair(2, utf16le("DOMAIN")), avPair(0, nil)...)

	t.Run("extracts challenge and target info", func(t *testing.T) {
		ch, err := parseType2(buildType2(sc, ti))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ch.serverChallenge, sc) {
			t.Errorf("serverChallenge = % x, want % x", ch.serverChallenge, sc)
		}
		if !bytes.Equal(ch.targetInfo, ti) {
			t.Errorf("targetInfo = % x, want % x", ch.targetInfo, ti)
		}
	})

	t.Run("rejects malformed messages", func(t *testing.T) {
		cases := []struct {
			name string
			b    []byte
		}{
			{"empty", nil},
			{"too short", make([]byte, 47)},
			{"bad signature", append([]byte("NOTNTLM\x00"), make([]byte, 40)...)},
		}
		for _, c := range cases {
			if _, err := parseType2(c.b); err == nil {
				t.Errorf("%s: expected an error, got nil", c.name)
			}
		}
	})

	t.Run("target info running off the end is dropped, not sliced", func(t *testing.T) {
		// A hostile or truncated type 2 that claims more TargetInfo than it
		// carries must not panic the client with an out-of-range slice.
		b := buildType2(sc, ti)
		binary.LittleEndian.PutUint16(b[40:42], uint16(len(ti)+64))
		ch, err := parseType2(b)
		if err != nil {
			t.Fatal(err)
		}
		if ch.targetInfo != nil {
			t.Errorf("targetInfo = % x, want nil for an out-of-range length", ch.targetInfo)
		}
	})
}

// parsedType3 is the AUTHENTICATE_MESSAGE decomposed by reading its security
// buffers the way a server does.
type parsedType3 struct {
	raw       []byte
	flags     uint32
	mic       []byte
	lm, nt    []byte
	dom, user []byte
	ws, esk   []byte
}

func parseType3(t *testing.T, m []byte) parsedType3 {
	t.Helper()
	if len(m) < 88 {
		t.Fatalf("type3 too short: %d bytes", len(m))
	}
	if !bytes.Equal(m[:8], ntlmSig) {
		t.Fatalf("signature = %q, want %q", m[:8], ntlmSig)
	}
	if got := binary.LittleEndian.Uint32(m[8:12]); got != 3 {
		t.Fatalf("message type = %d, want 3", got)
	}
	field := func(name string, at int) []byte {
		l := binary.LittleEndian.Uint16(m[at : at+2])
		maxLen := binary.LittleEndian.Uint16(m[at+2 : at+4])
		off := binary.LittleEndian.Uint32(m[at+4 : at+8])
		if l != maxLen {
			t.Errorf("%s: Len=%d MaxLen=%d, want equal", name, l, maxLen)
		}
		if int(off)+int(l) > len(m) {
			t.Fatalf("%s: offset %d + len %d runs past the %d-byte message", name, off, l, len(m))
		}
		if l > 0 && off < 88 {
			t.Errorf("%s: payload offset %d lands inside the 88-byte header", name, off)
		}
		return m[off : off+uint32(l)]
	}
	return parsedType3{
		raw:   m,
		lm:    field("LmChallengeResponse", 12),
		nt:    field("NtChallengeResponse", 20),
		dom:   field("DomainName", 28),
		user:  field("UserName", 36),
		ws:    field("Workstation", 44),
		esk:   field("EncryptedRandomSessionKey", 52),
		flags: binary.LittleEndian.Uint32(m[60:64]),
		mic:   m[72:88],
	}
}

func TestType3Structure(t *testing.T) {
	const (
		user     = "testuser"
		domain   = "example.local"
		password = "testpass"
		ws       = "KALI"
	)
	sc := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	ts := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	ti := bytes.Join([][]byte{
		avPair(2, utf16le("HTB")),
		avPair(1, utf16le("FOREST")),
		avPair(7, ts), // MsvAvTimestamp
		avPair(0, nil),
	}, nil)

	p, err := New(Config{User: user, Domain: domain, Password: password, Workstation: ws})
	if err != nil {
		t.Fatal(err)
	}
	t1 := p.type1()
	t2 := buildType2(sc, ti)
	ch, err := parseType2(t2)
	if err != nil {
		t.Fatal(err)
	}
	msg, exported, err := p.type3(ch, t1, t2)
	if err != nil {
		t.Fatal(err)
	}
	got := parseType3(t, msg)

	t.Run("identity fields round-trip as UTF-16LE", func(t *testing.T) {
		if s := utf16leDecode(got.dom); s != domain {
			t.Errorf("DomainName = %q, want %q", s, domain)
		}
		if s := utf16leDecode(got.user); s != user {
			t.Errorf("UserName = %q, want %q", s, user)
		}
		if s := utf16leDecode(got.ws); s != ws {
			t.Errorf("Workstation = %q, want %q", s, ws)
		}
	})

	t.Run("LM response is 24 zero bytes", func(t *testing.T) {
		// MS-NLMP: when the client sends a timestamp in the NTLMv2 blob the LM
		// response must be zeroed. Sending a real LMv2 response here is the
		// classic downgrade foot-gun.
		if len(got.lm) != 24 || !bytes.Equal(got.lm, make([]byte, 24)) {
			t.Errorf("LmChallengeResponse = % x, want 24 zero bytes", got.lm)
		}
	})

	t.Run("flags advertise session security", func(t *testing.T) {
		for _, f := range []struct {
			name string
			bit  uint32
		}{
			{"negUnicode", negUnicode},
			{"negSign", negSign},
			{"negSeal", negSeal},
			{"negExtendedSec", negExtendedSec},
			{"negTargetInfo", negTargetInfo},
			{"negKeyExch", negKeyExch},
		} {
			if got.flags&f.bit == 0 {
				t.Errorf("type3 flags missing %s (0x%08x); got 0x%08x", f.name, f.bit, got.flags)
			}
		}
	})

	respKeyNT := ntowfv2(user, domain, ntHashOf(password))

	t.Run("NTProofStr covers the temp blob the message carries", func(t *testing.T) {
		if len(got.nt) <= 16 {
			t.Fatalf("NtChallengeResponse = %d bytes, want NTProofStr plus a temp blob", len(got.nt))
		}
		proof, temp := got.nt[:16], got.nt[16:]
		mac := hmac.New(md5.New, respKeyNT)
		mac.Write(sc)
		mac.Write(temp)
		if want := mac.Sum(nil); !bytes.Equal(proof, want) {
			t.Errorf("NTProofStr = % x, want % x", proof, want)
		}
	})

	t.Run("temp blob carries the server's target info and timestamp", func(t *testing.T) {
		temp := got.nt[16:]
		if len(temp) < 28 {
			t.Fatalf("temp blob = %d bytes, too short", len(temp))
		}
		if want := []byte{1, 1, 0, 0, 0, 0, 0, 0}; !bytes.Equal(temp[:8], want) {
			t.Errorf("temp header = % x, want % x", temp[:8], want)
		}
		// The server's own MsvAvTimestamp must be echoed back; substituting a
		// local clock here is what gets an NTLMv2 response rejected on a box
		// whose time has drifted from the attacker's.
		if !bytes.Equal(temp[8:16], ts) {
			t.Errorf("temp timestamp = % x, want the server's % x", temp[8:16], ts)
		}
		if !bytes.Contains(temp, ti) {
			t.Errorf("temp blob does not carry the server's target info")
		}
	})

	t.Run("encrypted session key unwraps to the exported key", func(t *testing.T) {
		// The server derives its seal/sign keys from whatever this blob decrypts
		// to. If it disagrees with `exported` by even a byte, sealing works
		// locally and every message is garbage on the wire.
		mac := hmac.New(md5.New, respKeyNT)
		mac.Write(got.nt[:16])
		keyExchKey := mac.Sum(nil)
		if dec := rc4crypt(keyExchKey, got.esk); !bytes.Equal(dec, exported) {
			t.Errorf("decrypted session key = % x, want % x", dec, exported)
		}
	})

	t.Run("MIC covers all three messages with a zeroed MIC field", func(t *testing.T) {
		zeroed := append([]byte{}, msg...)
		copy(zeroed[72:88], make([]byte, 16))
		mac := hmac.New(md5.New, exported)
		mac.Write(t1)
		mac.Write(t2)
		mac.Write(zeroed)
		if want := mac.Sum(nil); !bytes.Equal(got.mic, want) {
			t.Errorf("MIC = % x, want % x", got.mic, want)
		}
		if bytes.Equal(got.mic, make([]byte, 16)) {
			t.Error("MIC is all zeros, the placeholder was never overwritten")
		}
	})

	t.Run("each call uses a fresh client challenge", func(t *testing.T) {
		// Assert on the challenge bytes themselves, not on the messages
		// differing: the exported session key is random too, so whole-message
		// inequality holds even with a hardcoded challenge. (A mutant that
		// replaced the challenge with zeros passed the weaker check.)
		clientChallenge := func(p parsedType3) []byte {
			temp := p.nt[16:]
			return temp[16:24] // 8-byte header, 8-byte timestamp, then the challenge
		}
		other, otherExported, err := p.type3(ch, t1, t2)
		if err != nil {
			t.Fatal(err)
		}
		a, b := clientChallenge(got), clientChallenge(parseType3(t, other))
		if bytes.Equal(a, b) {
			t.Errorf("two type3 calls reused client challenge % x", a)
		}
		if bytes.Equal(a, make([]byte, 8)) {
			t.Error("client challenge is all zeros")
		}
		if bytes.Equal(exported, otherExported) {
			t.Error("two type3 calls exported the same session key")
		}
	})
}

// TestPassTheHashMatchesPassword is the property the -H flag rests on: deriving
// the NT hash from a password and supplying it directly must produce the same
// credential, or pass-the-hash authenticates as nobody.
func TestPassTheHashMatchesPassword(t *testing.T) {
	const password = "testpass"

	fromPassword, err := New(Config{User: "u", Domain: "d", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	fromHash, err := New(Config{User: "u", Domain: "d", NTHash: ntHashOf(password)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromPassword.ntHash, fromHash.ntHash) {
		t.Fatalf("NT hash from password = % x, from -H = % x", fromPassword.ntHash, fromHash.ntHash)
	}

	t.Run("rejects a wrong-length hash", func(t *testing.T) {
		for _, n := range []int{1, 15, 17, 32} {
			if _, err := New(Config{User: "u", NTHash: make([]byte, n)}); err == nil {
				t.Errorf("New accepted a %d-byte NT hash", n)
			}
		}
	})
}
