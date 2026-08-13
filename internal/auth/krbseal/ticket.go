package krbseal

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// ticketCreds is everything the provider needs from a ticket file: the service
// ticket for the SPN, its session key, and the client identity to name in the
// AP-REQ authenticator.
type ticketCreds struct {
	realm   string
	cname   types.PrincipalName
	tkt     messages.Ticket
	sessKey types.EncryptionKey
}

// loadTicket reads a Kerberos ticket file and pulls out the service ticket for
// spn. Both formats operators actually have are accepted, an MIT ccache
// (impacket, getST.py, KRB5CCNAME) and a kirbi (Rubeus, Mimikatz), which is a
// raw KRB-CRED, because which one you hold is an accident of the tool that
// minted it, not a decision.
//
// Upstream evil-winrm accepts both too, but converts a kirbi by shelling out to
// impacket's ticketConverter.py and writing a .ccache next to the input. Nothing
// here needs a file in ccache shape: a KRB-CRED already carries the ticket, the
// session key and the client principal, which is the whole of what the provider
// reads out of a ccache. So it is parsed in memory, no external tool, no file
// written into the operator's directory.
func loadTicket(path, spn string) (*ticketCreds, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ticket file: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("ticket file %s is empty", path)
	}

	if kirbi, ok := asKirbi(raw); ok {
		return fromKirbi(kirbi, spn)
	}
	// Not a KRB-CRED, so treat it as a ccache. LoadCCache re-reads the file,
	// which is a wasted read but keeps the library's own parser in charge of the
	// format it owns.
	cc, err := credentials.LoadCCache(path)
	if err != nil {
		return nil, fmt.Errorf("load ccache: %w", err)
	}
	return fromCCache(cc, spn)
}

// asKirbi reports whether raw is a KRB-CRED, returning the DER to parse.
//
// The type is decided by the bytes, not the extension: `.ccache` files holding
// a kirbi (and vice versa) are common enough, a converter's output renamed by
// hand, and the extension is only ever a hint. A KRB-CRED is
// `[APPLICATION 22]`, so its DER starts with 0x76; anything else is left to the
// ccache parser, which is the stricter of the two and gives the better message
// when the file is neither.
//
// Base64 is accepted as well: Rubeus prints a kirbi as base64 and the natural
// thing to do with that output is paste it into a file. Decoding it here costs
// one branch and turns a baffling parse error into a working connection.
func asKirbi(raw []byte) ([]byte, bool) {
	if len(raw) > 0 && raw[0] == 0x76 {
		return raw, true
	}
	if !looksTextual(raw) {
		return nil, false
	}
	var b strings.Builder
	for _, r := range string(raw) {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	der, err := base64.StdEncoding.DecodeString(b.String())
	if err != nil || len(der) == 0 || der[0] != 0x76 {
		return nil, false
	}
	return der, true
}

// looksTextual reports whether raw could be base64 text rather than a binary
// ticket. It stays deliberately narrow, base64 alphabet plus whitespace, so a
// binary ccache can never be mistaken for text and lose the ccache parser's
// error message.
func looksTextual(raw []byte) bool {
	for _, c := range raw {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=', c == '\n', c == '\r', c == ' ', c == '\t':
		default:
			return false
		}
	}
	return true
}

// fromKirbi extracts the ticket for spn from a KRB-CRED.
func fromKirbi(der []byte, spn string) (*ticketCreds, error) {
	var kc messages.KRBCred
	if err := kc.Unmarshal(der); err != nil {
		return nil, fmt.Errorf("parse kirbi: %w", err)
	}
	// A kirbi from Rubeus, Mimikatz or impacket carries its EncKrbCredPart
	// unencrypted (etype 0): the file itself is the secret, so there is no key
	// to encrypt it with. Anything else came off the wire inside a real KRB_CRED
	// and cannot be opened without the session key of the exchange that carried
	// it, say so plainly rather than failing inside the ASN.1 parser.
	if kc.EncPart.EType != 0 {
		return nil, fmt.Errorf("kirbi's encrypted part uses etype %d; only an unencrypted "+
			"KRB-CRED (what Rubeus/Mimikatz/impacket write) can be read without the "+
			"session key that encrypted it", kc.EncPart.EType)
	}
	var enc messages.EncKrbCredPart
	if err := enc.Unmarshal(kc.EncPart.Cipher); err != nil {
		return nil, fmt.Errorf("parse kirbi credential part: %w", err)
	}
	// Tickets and TicketInfo are parallel lists (RFC 4120 §5.8.1): the key and
	// principal names in TicketInfo[i] belong to Tickets[i].
	var have []string
	for i, info := range enc.TicketInfo {
		name := info.SName.PrincipalNameString()
		have = append(have, name)
		if !strings.EqualFold(name, spn) || i >= len(kc.Tickets) {
			continue
		}
		return &ticketCreds{
			realm:   info.PRealm,
			cname:   info.PName,
			tkt:     kc.Tickets[i],
			sessKey: info.Key,
		}, nil
	}
	return nil, noTicketErr("kirbi", spn, have)
}

// fromCCache extracts the ticket for spn from a parsed ccache.
func fromCCache(cc *credentials.CCache, spn string) (*ticketCreds, error) {
	var have []string
	for _, cred := range cc.GetEntries() {
		name := cred.Server.PrincipalName.PrincipalNameString()
		have = append(have, name)
		if !strings.EqualFold(name, spn) {
			continue
		}
		t := &ticketCreds{
			realm:   cc.GetClientRealm(),
			cname:   cc.GetClientPrincipalName(),
			sessKey: cred.Key,
		}
		if err := t.tkt.Unmarshal(cred.Ticket); err != nil {
			return nil, fmt.Errorf("unmarshal ticket for %s: %w", name, err)
		}
		return t, nil
	}
	return nil, noTicketErr("ccache", spn, have)
}

// noTicketErr names what the file does hold. The usual cause is a TGT-only
// ccache (no service ticket was ever requested) or an SPN spelled for a
// different host, and both are invisible from "no service ticket for X".
func noTicketErr(kind, spn string, have []string) error {
	if len(have) == 0 {
		return fmt.Errorf("no service ticket for %s: the %s holds no credentials at all", spn, kind)
	}
	return fmt.Errorf("no service ticket for %s in the %s, which holds: %s",
		spn, kind, strings.Join(have, ", "))
}
