package ntlmseal

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// serverSide mirrors the target's half of the session: the same derived keys,
// the opposite direction. Building the expected bytes from the *other* end is
// what keeps these tests from merely re-running wrapHTTP's own arithmetic.
type serverSide struct {
	rc4c *rc4.Cipher
	sign []byte
	seq  uint32
}

func newServerSide(exported []byte) *serverSide {
	c, _ := rc4.NewCipher(sealKey(exported, "server-to-client"))
	return &serverSide{rc4c: c, sign: signKey(exported, "server-to-client")}
}

// seal mirrors wrap for the server direction: seal the body, then sign the
// *plaintext* and encrypt that checksum with the keystream bytes immediately
// following the message's. Both halves are built from primitives the vectors
// pin (sealKey, signKey, and wrap's own published signature), so this mock is
// not merely a restatement of unwrap's arithmetic.
func (s *serverSide) seal(plain []byte) (sig, sealed []byte) {
	sealed = make([]byte, len(plain))
	s.rc4c.XORKeyStream(sealed, plain)

	mac := hmac.New(md5.New, s.sign)
	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, s.seq)
	mac.Write(seq)
	mac.Write(plain)
	enc := make([]byte, 8)
	s.rc4c.XORKeyStream(enc, mac.Sum(nil)[:8])

	sig = make([]byte, 16)
	binary.LittleEndian.PutUint32(sig[0:4], 1)
	copy(sig[4:12], enc)
	binary.LittleEndian.PutUint32(sig[12:16], s.seq)
	s.seq++
	return sig, sealed
}

// sealTo produces a multipart/encrypted body the way the server would, so
// unwrapHTTP has something it did not itself construct to parse.
func (s *serverSide) sealTo(plain []byte) []byte {
	sig, sealed := s.seal(plain)

	var b bytes.Buffer
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("\tContent-Type: " + protocol + "\r\n")
	fmt.Fprintf(&b, "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n", len(plain))
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("\tContent-Type: application/octet-stream\r\n")
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(sig)))
	b.Write(lenBuf)
	b.Write(sig)
	b.Write(sealed)
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes()
}

func TestWrapHTTPEnvelope(t *testing.T) {
	exported := bytes.Repeat([]byte{0x42}, 16)
	k := newSessionKeys(exported)
	plain := []byte(`<s:Envelope><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action></s:Envelope>`)

	ct, body := k.wrapHTTP(plain)

	t.Run("content type names the protocol and boundary", func(t *testing.T) {
		for _, want := range []string{"multipart/encrypted", protocol, boundary} {
			if !strings.Contains(ct, want) {
				t.Errorf("Content-Type %q missing %q", ct, want)
			}
		}
	})

	t.Run("declares the plaintext length, not the sealed length", func(t *testing.T) {
		// The server slices the ciphertext using this number. Declaring the
		// sealed length (16 bytes longer, with the signature) truncates every
		// request by exactly the signature size.
		n, err := originalLength(body)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(plain) {
			t.Errorf("OriginalContent Length = %d, want %d", n, len(plain))
		}
	})

	t.Run("body is a well-formed two-part envelope", func(t *testing.T) {
		if !bytes.HasPrefix(body, []byte("--"+boundary+"\r\n")) {
			t.Error("body does not open with the boundary")
		}
		if !bytes.HasSuffix(body, []byte("--"+boundary+"--\r\n")) {
			t.Error("body does not close with the terminating boundary")
		}
		if n := bytes.Count(body, []byte("--"+boundary)); n != 3 {
			t.Errorf("found %d boundary markers, want 3", n)
		}
	})

	t.Run("plaintext never appears on the wire", func(t *testing.T) {
		// The whole point of the package: this body goes out over plain
		// HTTP/5985.
		if bytes.Contains(body, plain) {
			t.Fatal("the sealed body contains the plaintext verbatim")
		}
		if bytes.Contains(body, []byte("a:Action")) {
			t.Fatal("the sealed body leaks SOAP markup")
		}
	})

	t.Run("the server can recover the plaintext", func(t *testing.T) {
		marker := []byte("application/octet-stream\r\n")
		i := bytes.Index(body, marker)
		if i < 0 {
			t.Fatal("octet-stream section not found")
		}
		bin := body[i+len(marker):]
		sigLen := int(binary.LittleEndian.Uint32(bin[0:4]))
		sealed := bin[4+sigLen : 4+sigLen+len(plain)]

		srv, _ := rc4.NewCipher(sealKey(exported, "client-to-server"))
		out := make([]byte, len(sealed))
		srv.XORKeyStream(out, sealed)
		if !bytes.Equal(out, plain) {
			t.Errorf("server decrypted %q, want %q", out, plain)
		}
	})
}

func TestUnwrapHTTP(t *testing.T) {
	exported := bytes.Repeat([]byte{0x42}, 16)

	t.Run("recovers successive server messages", func(t *testing.T) {
		k := newSessionKeys(exported)
		srv := newServerSide(exported)
		for i, want := range [][]byte{
			[]byte("<s:Envelope>first</s:Envelope>"),
			[]byte("<s:Envelope>second</s:Envelope>"),
			[]byte(""),
			[]byte(strings.Repeat("x", 9000)),
		} {
			got, err := k.unwrapHTTP(srv.sealTo(want))
			if err != nil {
				t.Fatalf("message %d: %v", i, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("message %d = %q, want %q", i, got, want)
			}
		}
	})

	t.Run("rejects malformed bodies without panicking", func(t *testing.T) {
		// These arrive from the network. A slice out of range here is a crash
		// mid-session, so every one of them must come back as an error.
		good := newServerSide(exported).sealTo([]byte("payload"))
		cases := []struct {
			name string
			body []byte
		}{
			{"empty", nil},
			{"no length header", []byte("--" + boundary + "\r\ngarbage\r\n")},
			{"no octet-stream section", []byte("OriginalContent: Length=10\r\n")},
			{"truncated before the sig length", good[:bytes.Index(good, []byte("application/octet-stream\r\n"))+len("application/octet-stream\r\n")+2]},
			// Past the 24-byte closing boundary, so the sealed payload itself
			// is short of the declared 7 bytes.
			{"body shorter than the declared length", good[:len(good)-27]},
			{"non-numeric length", bytes.Replace(good, []byte("Length=7"), []byte("Length=x"), 1)},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				k := newSessionKeys(exported)
				if _, err := k.unwrapHTTP(c.body); err == nil {
					t.Error("expected an error, got nil")
				}
			})
		}
	})

	t.Run("an absurd declared length is refused, not allocated", func(t *testing.T) {
		k := newSessionKeys(exported)
		good := newServerSide(exported).sealTo([]byte("payload"))
		body := bytes.Replace(good, []byte("Length=7"), []byte("Length=4294967000"), 1)
		if _, err := k.unwrapHTTP(body); err == nil {
			t.Error("expected an error for a length far past the body")
		}
	})
}

func TestWrapHTTPUnwrapHTTPRoundTrip(t *testing.T) {
	// Client and server sides of one session, driven in lockstep: this is the
	// property the whole transport rests on, and it fails loudly if either
	// direction's keystream advances by the wrong number of bytes.
	exported := bytes.Repeat([]byte{0x7e}, 16)
	client := newSessionKeys(exported)
	peer := newSessionKeys(exported)

	// The peer's "client" handles decrypt what our client seals.
	for i := 0; i < 5; i++ {
		plain := []byte(fmt.Sprintf("<s:Envelope>request %d</s:Envelope>", i))
		_, body := client.wrapHTTP(plain)

		marker := []byte("application/octet-stream\r\n")
		bin := body[bytes.Index(body, marker)+len(marker):]
		sigLen := int(binary.LittleEndian.Uint32(bin[0:4]))
		sig := bin[4 : 4+sigLen]
		sealed := bin[4+sigLen:]
		sealed = sealed[:len(sealed)-len("--"+boundary+"--\r\n")]

		got := make([]byte, len(sealed))
		peer.clientSeal.XORKeyStream(got, sealed)
		peer.clientSeal.XORKeyStream(make([]byte, 8), sig[4:12])
		if !bytes.Equal(got, plain) {
			t.Fatalf("round %d: peer decrypted %q, want %q", i, got, plain)
		}
	}
}

// TestWrapSequenceNumbers pins the per-message sequence number. WinRM rejects a
// message whose sequence has repeated or skipped, and because the number is
// carried in the clear at a fixed offset it is cheap to assert exactly.
func TestWrapSequenceNumbers(t *testing.T) {
	k := newSessionKeys(bytes.Repeat([]byte{0x42}, 16))
	for i := uint32(0); i < 4; i++ {
		sig, _ := k.wrap([]byte("message"))
		if len(sig) != 16 {
			t.Fatalf("signature = %d bytes, want 16", len(sig))
		}
		if v := binary.LittleEndian.Uint32(sig[0:4]); v != 1 {
			t.Errorf("signature version = %d, want 1", v)
		}
		if seq := binary.LittleEndian.Uint32(sig[12:16]); seq != i {
			t.Errorf("message %d carries sequence %d", i, seq)
		}
	}
}

// TestWrapIdenticalPlaintextsDiffer catches an RC4 handle that is reset per
// message instead of running continuously: two identical requests would then
// seal to identical ciphertext, which leaks structure and desyncs the server.
func TestWrapIdenticalPlaintextsDiffer(t *testing.T) {
	k := newSessionKeys(bytes.Repeat([]byte{0x42}, 16))
	plain := []byte("<s:Envelope>identical</s:Envelope>")
	_, a := k.wrap(plain)
	_, b := k.wrap(plain)
	if bytes.Equal(a, b) {
		t.Fatal("identical plaintexts sealed to identical ciphertext; the RC4 handle is being reset")
	}
}

func TestOriginalLength(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    int
		wantErr bool
	}{
		{"typical header", "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=1234\r\n", 1234, false},
		{"zero", "Length=0\r\n", 0, false},
		{"missing", "no length here\r\n", 0, true},
		{"non-numeric", "Length=abc\r\n", 0, true},
		{"empty value", "Length=\r\n", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := originalLength([]byte(c.body))
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("originalLength = %d, want %d", got, c.want)
			}
		})
	}
}

func TestSoapAction(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"namespaced action",
			`<s:Header><a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action></s:Header>`,
			"Create",
		},
		{
			"bare action element",
			`<a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>`,
			"Command",
		},
		{"no slash in the uri", `<a:Action>Receive</a:Action>`, "Receive"},
		{"no action element", `<s:Envelope/>`, "?"},
		{"unterminated", `<a:Action>http://x/Create`, "?"},
		{"empty body", "", "?"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := soapAction([]byte(c.body)); got != c.want {
				t.Errorf("soapAction = %q, want %q", got, c.want)
			}
		})
	}
}

func TestNTLMToken(t *testing.T) {
	t.Run("extracts a Negotiate token", func(t *testing.T) {
		h := http.Header{}
		h.Add("Www-Authenticate", "Negotiate TlRMTVNTUAAC")
		if got := ntlmToken(h); got != "TlRMTVNTUAAC" {
			t.Errorf("ntlmToken = %q, want the token", got)
		}
	})

	t.Run("picks Negotiate out of a multi-scheme challenge", func(t *testing.T) {
		// A DC commonly offers Negotiate alongside Kerberos and Basic; taking
		// the first header blindly picks the wrong scheme.
		h := http.Header{}
		h.Add("Www-Authenticate", "Basic realm=\"x\"")
		h.Add("Www-Authenticate", "Negotiate TlRMTVNTUAAC")
		if got := ntlmToken(h); got != "TlRMTVNTUAAC" {
			t.Errorf("ntlmToken = %q, want the Negotiate token", got)
		}
	})

	t.Run("no Negotiate header yields empty", func(t *testing.T) {
		h := http.Header{}
		h.Add("Www-Authenticate", "Basic realm=\"x\"")
		if got := ntlmToken(h); got != "" {
			t.Errorf("ntlmToken = %q, want empty", got)
		}
	})
}

func TestTimestamp(t *testing.T) {
	ts := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	t.Run("prefers the server's MsvAvTimestamp", func(t *testing.T) {
		ti := bytes.Join([][]byte{
			avPair(2, utf16le("HTB")),
			avPair(7, ts),
			avPair(0, nil),
		}, nil)
		if got := timestamp(ti); !bytes.Equal(got, ts) {
			t.Errorf("timestamp = % x, want the server's % x", got, ts)
		}
	})

	t.Run("falls back to the local clock", func(t *testing.T) {
		ti := append(avPair(2, utf16le("HTB")), avPair(0, nil)...)
		got := timestamp(ti)
		if len(got) != 8 {
			t.Fatalf("timestamp = %d bytes, want 8", len(got))
		}
		if bytes.Equal(got, make([]byte, 8)) {
			t.Error("fallback timestamp is all zeros")
		}
	})

	t.Run("stops at MsvAvEOL", func(t *testing.T) {
		// A timestamp after the end-of-list marker is not part of the list;
		// walking past EOL reads attacker-controlled trailing bytes.
		ti := bytes.Join([][]byte{avPair(0, nil), avPair(7, ts)}, nil)
		if got := timestamp(ti); bytes.Equal(got, ts) {
			t.Error("timestamp walked past MsvAvEOL")
		}
	})

	t.Run("survives malformed target info", func(t *testing.T) {
		cases := map[string][]byte{
			"empty":            nil,
			"truncated header": {7, 0},
			"length past end":  {7, 0, 0xff, 0xff, 1, 2, 3},
			"wrong size":       append(avPair(7, []byte{1, 2, 3}), avPair(0, nil)...),
		}
		for name, ti := range cases {
			t.Run(name, func(t *testing.T) {
				if got := timestamp(ti); len(got) != 8 {
					t.Errorf("timestamp = %d bytes, want 8", len(got))
				}
			})
		}
	})
}
