package wsman

import (
	"errors"
	"strings"
	"testing"
)

// envelopeWith builds a minimal response envelope carrying the given RelatesTo,
// in the namespace-prefixed form a real server sends.
func envelopeWith(relatesTo string) []byte {
	return []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">` +
		`<s:Header><a:RelatesTo>` + relatesTo + `</a:RelatesTo></s:Header>` +
		`<s:Body><rsp:ReceiveResponse xmlns:rsp="x"/></s:Body></s:Envelope>`)
}

func TestRelatesToAcceptsTheMatchingResponse(t *testing.T) {
	id := "uuid:3349E2EE-C2DA-44DA-A5C4-6BD9BF69B93F"
	if err := checkRelatesTo(id, envelopeWith(id)); err != nil {
		t.Fatalf("rejected a correlated response: %v", err)
	}
}

// TestRelatesToIsCaseInsensitive is the regression test for the trap described
// on checkRelatesTo: Delete builds its MessageID lowercase while every other
// call site upper-cases it, and the server echoes back the case it was given.
//
// This test is the *only* thing guarding that, and deliberately so: Delete is
// reached only from RemoveDisconnectedSession, which this tool never calls, so
// a case-sensitive compare survives every live harness. Verified by building
// that mutant and running it against a real target — nothing failed. Do not
// "simplify" this to ==.
func TestRelatesToIsCaseInsensitive(t *testing.T) {
	sent := "uuid:fec7072a-f05e-4f46-9bc7-2d9b0e46a5a6"
	echoed := strings.ToUpper(sent)
	if err := checkRelatesTo(sent, envelopeWith(echoed)); err != nil {
		t.Fatalf("rejected a response differing only in case: %v", err)
	}
	if err := checkRelatesTo(echoed, envelopeWith(sent)); err != nil {
		t.Fatalf("rejected a response differing only in case (reverse): %v", err)
	}
}

// TestRelatesToRejectsAReplay is the point of the whole check: a *valid*
// response to some earlier request, replayed by an in-path attacker, is
// perfectly signed and sealed and must still be refused.
func TestRelatesToRejectsAReplay(t *testing.T) {
	sent := "uuid:A1432EDF-3250-4213-9527-D66CF2911F3B"
	captured := "uuid:86D2E966-23B5-4CEE-87E3-2FDB3FC0A3AD" // an earlier exchange

	err := checkRelatesTo(sent, envelopeWith(captured))
	if err == nil {
		t.Fatal("accepted a response correlated to a different request")
	}
	if !errors.Is(err, ErrUncorrelatedResponse) {
		t.Fatalf("want ErrUncorrelatedResponse, got %v", err)
	}
}

// TestRelatesToRejectsAStrippedHeader pins that absence is a failure. Treating
// a missing RelatesTo as "nothing to check" would let an attacker disable the
// check by deleting one header.
func TestRelatesToRejectsAStrippedHeader(t *testing.T) {
	body := []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
		`<s:Header></s:Header><s:Body/></s:Envelope>`)

	err := checkRelatesTo("uuid:A1432EDF-3250-4213-9527-D66CF2911F3B", body)
	if err == nil {
		t.Fatal("accepted a response with no RelatesTo header")
	}
	if !errors.Is(err, ErrUncorrelatedResponse) {
		t.Fatalf("want ErrUncorrelatedResponse, got %v", err)
	}
}

// TestRelatesToCorrelatesFaultsToo — the server sends RelatesTo on faults as
// well, and the check runs before CheckFault, so a fault must correlate before
// its text is believed. (An uncorrelated fault could otherwise be injected to
// steer the shell's fault-text-keyed forgotten-shell detection.)
func TestRelatesToCorrelatesFaultsToo(t *testing.T) {
	id := "uuid:DC61E4FB-E537-4D5F-80D0-508FE358B3B1"
	fault := func(rel string) []byte {
		return []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
			`xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">` +
			`<s:Header><a:RelatesTo>` + rel + `</a:RelatesTo></s:Header>` +
			`<s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>` +
			`</s:Fault></s:Body></s:Envelope>`)
	}
	if err := checkRelatesTo(id, fault(id)); err != nil {
		t.Fatalf("rejected a correlated fault: %v", err)
	}
	if err := checkRelatesTo(id, fault("uuid:0000-wrong")); !errors.Is(err, ErrUncorrelatedResponse) {
		t.Fatalf("accepted an uncorrelated fault: %v", err)
	}
}

// TestRelatesToLeavesNonEnvelopesToTheCaller — a body that is not a SOAP
// envelope must not be masked by this check; the per-method unmarshal gives the
// better diagnostic.
func TestRelatesToLeavesNonEnvelopesToTheCaller(t *testing.T) {
	if err := checkRelatesTo("uuid:X", []byte("not xml at all")); err != nil {
		t.Fatalf("masked a non-envelope body: %v", err)
	}
}
