package krbseal

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"

	kasn1 "github.com/go-krb5/x/encoding/asn1"
)

// The fixtures are built here rather than committed as files: a kirbi is a
// credential, and a real one has no place in the repo. Everything below is
// assembled with the same ASN.1 the parser reads back.

// der wraps content in a DER tag/length header.
func der(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch n := len(content); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func principal(parts ...string) types.PrincipalName {
	return types.PrincipalName{NameType: 2, NameString: parts}
}

// krbCredInfo and encKrbCredPart mirror messages.KrbCredInfo / EncKrbCredPart
// with identical tags. They exist only because those types are declared for
// unmarshalling: the fields omitted here are optional in the ASN.1 and unused
// by the loader, and a fixture that omits them is a fixture that proves they
// are optional.
type krbCredInfo struct {
	Key    types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm string              `asn1:"general,explicit,tag:1"`
	PName  types.PrincipalName `asn1:"explicit,tag:2"`
	SRealm string              `asn1:"explicit,ia5,tag:8"`
	SName  types.PrincipalName `asn1:"explicit,tag:9"`
}

type encKrbCredPart struct {
	TicketInfo []krbCredInfo `asn1:"explicit,tag:0"`
}

// kirbiFor builds a KRB-CRED carrying one ticket for spn. etype selects the
// encryption of the credential part: 0 is what a tool-written kirbi uses (the
// file is the secret), anything else means it came off the wire.
func kirbiFor(t *testing.T, spn []string, key []byte, etype int32) []byte {
	t.Helper()

	tkt := messages.Ticket{
		TktVNO:  5,
		Realm:   "CORP.LOCAL",
		SName:   principal(spn...),
		EncPart: types.EncryptedData{EType: 18, KVNO: 3, Cipher: []byte("opaque-to-us")},
	}
	tktDER, err := tkt.Marshal()
	if err != nil {
		t.Fatalf("marshal ticket: %v", err)
	}

	part := encKrbCredPart{TicketInfo: []krbCredInfo{{
		Key:    types.EncryptionKey{KeyType: 18, KeyValue: key},
		PRealm: "CORP.LOCAL",
		PName:  principal("svc-account"),
		SRealm: "CORP.LOCAL",
		SName:  principal(spn...),
	}}}
	// EncKrbCredPart.Unmarshal expects the APPLICATION 29 wrapper.
	partDER, err := kasn1.MarshalWithParams(part, "application,explicit,tag:29",
		// The principal names inside are []string with a GeneralString tag; the
		// fork's marshaller needs these to encode a string slice at all, and
		// Ticket.Marshal passes exactly the same pair.
		kasn1.WithMarshalSlicePreserveTypes(true), kasn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		t.Fatalf("marshal cred part: %v", err)
	}

	encData, err := kasn1.Marshal(types.EncryptedData{EType: etype, Cipher: partDER})
	if err != nil {
		t.Fatalf("marshal encrypted data: %v", err)
	}

	body := append([]byte{}, der(0xA0, []byte{0x02, 0x01, 0x05})...) // pvno 5
	body = append(body, der(0xA1, []byte{0x02, 0x01, 0x16})...)      // msg-type 22 (KRB_CRED)
	body = append(body, der(0xA2, der(0x30, tktDER))...)             // tickets: SEQUENCE OF Ticket
	body = append(body, der(0xA3, encData)...)                       // enc-part
	return der(0x76, der(0x30, body))                                // [APPLICATION 22] SEQUENCE
}

func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

const spn = "HTTP/dc01.corp.local"

// A kirbi is what Rubeus and Mimikatz hand an operator; it must work as a -K
// argument without any conversion step.
func TestLoadTicketReadsAKirbi(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	path := writeTemp(t, "svc.kirbi", kirbiFor(t, []string{"HTTP", "dc01.corp.local"}, key, 0))

	got, err := loadTicket(path, spn)
	if err != nil {
		t.Fatalf("loadTicket: %v", err)
	}
	if string(got.sessKey.KeyValue) != string(key) {
		t.Errorf("session key = %q, want the one in the kirbi", got.sessKey.KeyValue)
	}
	if got.realm != "CORP.LOCAL" {
		t.Errorf("realm = %q, want CORP.LOCAL", got.realm)
	}
	if n := got.cname.PrincipalNameString(); n != "svc-account" {
		t.Errorf("client principal = %q, want svc-account", n)
	}
	// The ticket must be the one carried alongside that key, not an empty value
	// that would sail through and fail much later inside the AP-REQ.
	if got.tkt.SName.PrincipalNameString() != spn || got.tkt.Realm != "CORP.LOCAL" {
		t.Errorf("ticket = %+v, want the %s ticket", got.tkt.SName, spn)
	}
}

// Rubeus prints a kirbi as base64, and pasting that into a file is the obvious
// thing to do with it.
func TestLoadTicketReadsABase64Kirbi(t *testing.T) {
	raw := kirbiFor(t, []string{"HTTP", "dc01.corp.local"}, []byte("k"), 0)
	// Wrapped, as a terminal or an editor would leave it.
	b64 := base64.StdEncoding.EncodeToString(raw)
	var wrapped strings.Builder
	for i := 0; i < len(b64); i += 64 {
		wrapped.WriteString(b64[i:min(i+64, len(b64))] + "\n")
	}
	path := writeTemp(t, "rubeus.txt", []byte(wrapped.String()))

	got, err := loadTicket(path, spn)
	if err != nil {
		t.Fatalf("loadTicket on base64 kirbi: %v", err)
	}
	if string(got.sessKey.KeyValue) != "k" {
		t.Errorf("session key = %q, want the one in the kirbi", got.sessKey.KeyValue)
	}
}

// The format is decided by the bytes, not the extension: a converter's output
// renamed by hand is common, and a wrong extension must not decide the parse.
func TestLoadTicketIgnoresTheExtension(t *testing.T) {
	path := writeTemp(t, "misnamed.ccache", kirbiFor(t, []string{"HTTP", "dc01.corp.local"}, []byte("k"), 0))
	if _, err := loadTicket(path, spn); err != nil {
		t.Fatalf("a kirbi named .ccache should still load: %v", err)
	}
}

// A ticket for the wrong host is the common mistake (the SPN follows the target
// FQDN), so the error has to say what the file actually holds.
func TestLoadTicketNamesWhatTheFileHolds(t *testing.T) {
	path := writeTemp(t, "other.kirbi", kirbiFor(t, []string{"cifs", "dc02.corp.local"}, []byte("k"), 0))

	_, err := loadTicket(path, spn)
	if err == nil {
		t.Fatal("a kirbi with no matching SPN should be an error")
	}
	if !strings.Contains(err.Error(), "cifs/dc02.corp.local") {
		t.Errorf("error should name the SPN the file does hold, got: %v", err)
	}
}

// A KRB-CRED taken off the wire cannot be opened without the session key of the
// exchange that carried it. That is not a parse failure, and saying so inside
// the ASN.1 parser's words would send the operator hunting the wrong thing.
func TestLoadTicketRejectsAnEncryptedCredPart(t *testing.T) {
	path := writeTemp(t, "wire.kirbi", kirbiFor(t, []string{"HTTP", "dc01.corp.local"}, []byte("k"), 18))

	_, err := loadTicket(path, spn)
	if err == nil {
		t.Fatal("an encrypted KRB-CRED should be refused")
	}
	if !strings.Contains(err.Error(), "etype 18") {
		t.Errorf("error should name the etype it found, got: %v", err)
	}
}

// Anything that is not a KRB-CRED belongs to the ccache parser, including
// rubbish, its message is the more useful one for a file that is neither.
func TestLoadTicketLeavesNonKirbiToTheCCacheParser(t *testing.T) {
	path := writeTemp(t, "garbage.bin", []byte{0x05, 0x04, 0xff, 0x00, 0x41, 0x42})

	_, err := loadTicket(path, spn)
	if err == nil {
		t.Fatal("garbage should not load")
	}
	if !strings.Contains(err.Error(), "ccache") {
		t.Errorf("error should come from the ccache parser, got: %v", err)
	}
}

func TestLoadTicketRejectsAnEmptyFile(t *testing.T) {
	path := writeTemp(t, "empty.ccache", nil)

	_, err := loadTicket(path, spn)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty ticket file should say so, got: %v", err)
	}
}
