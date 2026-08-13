package transport

import (
	"strings"
	"testing"
)

// A real shell-not-found fault, as WinRM sends it: HTTP 500, several KB of
// namespaced XML, with the useful part in the middle.
const shellNotFoundFault = `<s:Envelope xml:lang="en-US" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <a:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/fault</a:Action>
    <a:MessageID>uuid:8B5C5B45-6E1F-4A9C-9E14-2D3E4F5A6B7C</a:MessageID>
    <a:RelatesTo>uuid:1A2B3C4D-5E6F-7A8B-9C0D-1E2F3A4B5C6D</a:RelatesTo>
  </s:Header>
  <s:Body>
    <s:Fault>
      <s:Code>
        <s:Value>s:Sender</s:Value>
        <s:Subcode>
          <s:Value>w:InvalidSelectors</s:Value>
        </s:Subcode>
      </s:Code>
      <s:Reason>
        <s:Text xml:lang="en-US">The WS-Management service cannot process the request. The request contained invalid selectors for the resource. </s:Text>
      </s:Reason>
      <s:Detail>
        <w:FaultDetail>http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/InvalidSelectors</w:FaultDetail>
        <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858843" Machine="dc.htb.local">
          <f:Message>The request for the Windows Remote Shell with ShellId 4F8A2C11-0000-0000-0000-000000000001 failed because the shell was not found on the server. Possible causes are: the specified ShellId is incorrect or the shell no longer exists on the server. Provide the correct ShellId or create a new shell and retry the operation. </f:Message>
        </f:WSManFault>
      </s:Detail>
    </s:Fault>
  </s:Body>
</s:Envelope>`

// The operator sees this error; it must be one readable line, not the envelope.
// (Fork patch.)
func TestSoapFaultSummary(t *testing.T) {
	got := describeBody([]byte(shellNotFoundFault))

	if strings.ContainsAny(got, "<>") || strings.ContainsAny(got, "\n\r") {
		t.Fatalf("fault summary still carries XML/newlines: %q", got)
	}
	if len(got) >= len(shellNotFoundFault) {
		t.Fatalf("fault summary is not a summary: %d bytes of a %d-byte body", len(got), len(shellNotFoundFault))
	}
	// What went wrong, and where in the stack it was refused.
	for _, want := range []string{
		"wsman fault:",
		"s:Sender",
		"w:InvalidSelectors",
		"shell was not found on the server",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("fault summary lost %q: %q", want, got)
		}
	}
	// client.isCommandGone and the reconnect path both match on the numeric
	// code; dropping it would silently turn a recognised condition into an
	// error the operator sees.
	if !strings.Contains(got, "2150858843") {
		t.Fatalf("fault summary dropped the WSMan code: %q", got)
	}
	// The reason is boilerplate for the subcode already printed, and the
	// message says the same thing with the specifics; carrying both would make
	// the line twice as long for nothing.
	if strings.Contains(got, "The request contained invalid selectors") {
		t.Fatalf("fault summary carries the boilerplate reason as well: %q", got)
	}
}

// The detail that names the cause can sit one WSManFault deeper, inside a
// provider fault. That nesting is the whole reason the message is read as
// "every descendant's text" rather than as a plain string field.
func TestSoapFaultSummaryReadsANestedProviderFault(t *testing.T) {
	body := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>
	  <s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:InternalError</s:Value></s:Subcode></s:Code>
	  <s:Reason><s:Text xml:lang="en-US">The WSMan provider host process did not return a proper response.</s:Text></s:Reason>
	  <s:Detail><f:WSManFault xmlns:f="f" Code="2150859046" Machine="dc"><f:Message>
	    <f:ProviderFault provider="microsoft.powershell" path="pwrshplugin.dll">
	      <f:Message>The user has exceeded the maximum allowed number of concurrent shells.</f:Message>
	    </f:ProviderFault>
	  </f:Message></f:WSManFault></s:Detail>
	</s:Fault></s:Body></s:Envelope>`

	got := describeBody([]byte(body))
	for _, want := range []string{
		"exceeded the maximum allowed number of concurrent shells", // the nested provider fault
		"code=2150859046",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("fault summary lost %q: %q", want, got)
		}
	}
}

// With no message at all, the reason is all there is — it must not be dropped
// along with the boilerplate.
func TestSoapFaultSummaryFallsBackToTheReason(t *testing.T) {
	body := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>
	  <s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>w:AccessDenied</s:Value></s:Subcode></s:Code>
	  <s:Reason><s:Text xml:lang="en-US">Access is denied.</s:Text></s:Reason>
	</s:Fault></s:Body></s:Envelope>`

	got := describeBody([]byte(body))
	if !strings.Contains(got, "Access is denied.") {
		t.Fatalf("fault summary dropped the only text it had: %q", got)
	}
	// The raw envelope contains that string too — say so only if it really was
	// summarized.
	if strings.ContainsRune(got, '<') {
		t.Fatalf("fault was not summarized at all: %q", got)
	}
}

// The summary path bypasses describeBody's isMostlyText guard, so it owes the
// same promise: nothing that can move a terminal's cursor gets through. XML 1.0
// forbids a literal C0 escape but permits the C1 controls by reference, so a
// fault message really can carry CSI (U+009B) — and the message text comes from
// whatever the target says.
func TestSoapFaultSummarySanitizesFieldText(t *testing.T) {
	body := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>` +
		`<s:Code><s:Value>s:Sender</s:Value></s:Code>` +
		"<s:Reason><s:Text>bad &#x9b;2J\tthing</s:Text></s:Reason>" +
		`</s:Fault></s:Body></s:Envelope>`

	got := describeBody([]byte(body))
	if strings.ContainsAny(got, "\u009b\t") {
		t.Fatalf("fault summary leaked a control character: %q", got)
	}
	if !strings.Contains(got, "bad") || !strings.Contains(got, "thing") {
		t.Fatalf("fault summary dropped the message text: %q", got)
	}
}

// Only an actual fault envelope takes the summary path; anything else keeps the
// old behaviour so a body we cannot parse is never swallowed.
func TestSoapFaultSummaryDeclinesNonFaults(t *testing.T) {
	for name, body := range map[string]string{
		"plain text":        "Service Unavailable",
		"truncated fault":   `<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Sen`,
		"mentions no fault": `<s:Envelope><s:Body><rsp:Shell/></s:Body></s:Envelope>`,
	} {
		if _, ok := soapFaultSummary([]byte(body)); ok {
			t.Fatalf("%s: summarized as a fault", name)
		}
		if got := describeBody([]byte(body)); got != body {
			t.Fatalf("%s: describeBody = %q, want it inlined verbatim", name, got)
		}
	}
}
