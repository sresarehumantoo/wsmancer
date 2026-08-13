package transport

// Fork patch: summarize a WSMan SOAP fault instead of dumping its envelope.
//
// WinRM reports every refused request as a SOAP fault, and on a fault the HTTP
// status is 500 — so the fault body never reaches wsman.ParseFault, which only
// runs on a successful response. It came back through describeBody as "mostly
// text" and was inlined whole: several KB of namespaced XML across the
// operator's terminal, with the two fields that actually say what went wrong
// (the reason, and the WSManFault message) buried in the middle of it.
//
// The parsing lives here rather than reusing wsman.ParseFault because package
// wsman imports this package; the dependency cannot go the other way.

import (
	"encoding/xml"
	"strings"
	"unicode"
)

// soapFaultSummary renders a WSMan SOAP fault body as one readable line, in the
// same shape as wsman.Fault.Error(). It reports false for anything that is not
// a fault envelope, leaving the caller to describe the body itself.
//
// The WSManFault code is carried through verbatim, and the message text is
// preserved rather than paraphrased: callers match on both (see
// client.isCommandGone, which recognises an already-finished command by fault
// code 2150858843 and by the message it comes with).
func soapFaultSummary(body []byte) (string, bool) {
	// Cheap reject first: unmarshalling every error body would be wasteful, and
	// most of them (an IIS error page, an encrypted blob) are not envelopes.
	if !strings.Contains(string(body), ":Fault") {
		return "", false
	}

	var env soapFaultEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return "", false
	}
	f := env.Body.Fault
	if f.Code.Value == "" && f.Reason.Text == "" {
		return "", false
	}

	// WinRM's Reason is boilerplate keyed to the subcode ("The request
	// contained invalid selectors for the resource."), which the subcode
	// already says; the WSManFault message is the one that names the shell,
	// the command or the provider that refused. So the message wins when there
	// is one, and the reason stands in when there is not.
	text := clean(string(f.Detail.WSManFault.Message))
	if text == "" {
		text = clean(f.Reason.Text)
	}

	var parts []string
	for _, p := range []string{
		clean(f.Code.Value),
		clean(f.Code.Subcode.Value),
		text,
	} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if code := clean(f.Detail.WSManFault.Code); code != "" {
		parts = append(parts, "code="+code)
	}
	return "wsman fault: " + strings.Join(parts, ": "), true
}

// clean makes one fault field safe and readable in a single-line error: the XML
// is indented, so its text arrives full of newlines and runs of spaces, and a
// field is still attacker-influenced text on its way to a terminal (the same
// reason describeBody refuses a non-text body). Runs of whitespace collapse to
// one space and anything non-graphic is dropped.
func clean(s string) string {
	const maxField = 600
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
		case unicode.IsGraphic(r):
			if space {
				b.WriteRune(' ')
				space = false
			}
			b.WriteRune(r)
		}
		if b.Len() >= maxField {
			return b.String() + "..."
		}
	}
	return b.String()
}

// allText is a string that collects the character data of its element and of
// every descendant. A plain string field takes only the element's own text,
// which for a provider fault is nothing but indentation: the message that
// matters ("the user has exceeded the maximum allowed number of concurrent
// shells") sits inside a nested ProviderFault/WSManFault/Message.
type allText string

func (t *allText) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var b strings.Builder
	depth := 0
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch v := tok.(type) {
		case xml.CharData:
			b.Write(v)
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				*t = allText(b.String())
				return nil
			}
			depth--
		}
	}
}

// soapFaultEnvelope is the subset of a SOAP fault this package reads. The
// WSManFault code is a string, not an int: it is only ever passed through, and
// codes such as 2150858843 do not fit an int on a 32-bit build.
type soapFaultEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		Fault struct {
			Code struct {
				Value   string `xml:"Value"`
				Subcode struct {
					Value string `xml:"Value"`
				} `xml:"Subcode"`
			} `xml:"Code"`
			Reason struct {
				Text string `xml:"Text"`
			} `xml:"Reason"`
			Detail struct {
				WSManFault struct {
					Code    string  `xml:"Code,attr"`
					Message allText `xml:"Message"`
				} `xml:"WSManFault"`
			} `xml:"Detail"`
		} `xml:"Fault"`
	} `xml:"Body"`
}
