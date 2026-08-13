package wsman

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/smnsjas/go-psrp/wsman/transport"
)

// operationTimeout picks a WS-Management OperationTimeout (the ISO-8601 duration
// the server may hold a long-poll before replying w:TimedOut) that is guaranteed
// to elapse — and let the server send that reply — *before* the caller's context
// deadline. (Fork patch.)
//
// This matters because the sealing transport sets the socket read deadline to
// the request context's deadline. A Receive advertises an OperationTimeout so
// the server holds the poll waiting for output; if that server-side hold is >=
// the client deadline, the socket read fires before the server replies, the
// transport treats the timeout as a dead connection, tears it down and re-dials
// a fresh WSMan session — which corrupts stateful PSRP and cascades into faults.
// Capping the operation timeout under the deadline (minus a margin for the reply
// plus network RTT) keeps a legitimately-held poll from killing the connection.
// With no deadline, the default is used unchanged.
func operationTimeout(ctx context.Context, def time.Duration) string {
	d := def
	if dl, ok := ctx.Deadline(); ok {
		const margin = 3 * time.Second
		if budget := time.Until(dl) - margin; budget < d {
			d = budget
		}
	}
	if d < time.Second {
		d = time.Second
	}
	return fmt.Sprintf("PT%dS", int(d/time.Second))
}

// defaultReceivePoll is how long the server may hold a Receive long-poll when
// the caller sets no deadline. (Fork patch.)
//
// It is the dominant term in Ctrl-C latency: the terminate Signal must run on
// the same single connection the running command's Receive holds (WinRM locks a
// shell to its owning client), so cancelling waits out whatever is left of the
// in-flight poll — uniformly distributed over [0, this]. Lowering it cuts cancel
// latency proportionally and costs one extra sealed round-trip per interval.
//
// Measured against a live box (HTB Forest, NTLM+seal), Ctrl-C to usable prompt:
//
//	5s ⇒ 2.49s median / 4.53s max, 0.23 Receive/s (10 KiB per 30s command)
//	2s ⇒ 1.64s median / 4.31s max, ~0.5 Receive/s
//	1s ⇒ 0.66s median / 1.36s max, 1.00 Receive/s (44 KiB per 30s command)
//
// 1s is the default: the polls only run *while a command is running* (an idle
// shell makes no requests at all), so the extra ~1.5 KiB/s is paid precisely on
// the long commands where a fast cancel matters. Operators who would rather be
// quieter on the wire than responsive can raise it.
//
// WSMANCER_POLL_SECONDS overrides it (whole seconds; the WSMan duration format
// used here has 1s granularity, which is also the floor in operationTimeout).
func defaultReceivePoll() time.Duration {
	if s := os.Getenv("WSMANCER_POLL_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Second
}

// Client is a WSMan client for communicating with WinRM endpoints.
type Client struct {
	endpoint  string
	transport *transport.HTTPTransport
	sessionID string
}

// NewClient creates a new WSMan client.
func NewClient(endpoint string, tr *transport.HTTPTransport) *Client {
	return &Client{
		endpoint:  endpoint,
		transport: tr,
		sessionID: "uuid:" + strings.ToUpper(uuid.New().String()),
	}
}

// SetSessionID sets the WS-Management SessionId for the client.
func (c *Client) SetSessionID(sessionID string) {
	c.sessionID = sessionID
}

// ReceiveResult contains the result of a Receive operation.
type ReceiveResult struct {
	Stdout       []byte
	Stderr       []byte
	CommandState string
	ExitCode     int
	Done         bool
}

// Create creates a new shell (RunspacePool) and returns the shell ID.
// For PowerShell remoting, creationXml should contain base64-encoded PSRP fragments
// (SessionCapability + InitRunspacePool messages).
// Create creates a new shell (RunspacePool) and returns the EndpointReference.
// For PowerShell remoting, creationXml should contain base64-encoded PSRP fragments
// (SessionCapability + InitRunspacePool messages).
func (c *Client) Create(ctx context.Context, options map[string]string, creationXML string) (*EndpointReference, error) {
	env := NewEnvelope().
		WithAction(ActionCreate).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S").
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithShellNamespace()

	// Add shell options
	idleTimeout := "PT30M" // default
	for name, value := range options {
		if name == "protocolversion" {
			env.WithOptionMustComply(name, value)
		} else if name == "IdleTimeout" {
			idleTimeout = value
			// Do not add as a header option, handled in body
		} else {
			env.WithOption(name, value)
		}
	}

	// Build shell body with optional creationXml for PSRP
	// Generate client-side ShellId as base suggestion
	shellID := strings.ToUpper(uuid.New().String())
	var shellBody string
	if creationXML != "" {
		shellBody = `<rsp:Shell ShellId="` + shellID + `" xmlns:rsp="` + NsShell + `">
  <rsp:InputStreams>stdin pr</rsp:InputStreams>
  <rsp:OutputStreams>stdout</rsp:OutputStreams>
  <rsp:IdleTimeOut>` + idleTimeout + `</rsp:IdleTimeOut>
  <creationXml xmlns="http://schemas.microsoft.com/powershell">` + creationXML + `</creationXml>
</rsp:Shell>`
	} else {
		// Basic WinRS shell
		shellBody = `<rsp:Shell ShellId="` + shellID + `" xmlns:rsp="` + NsShell + `">
  <rsp:InputStreams>stdin pr</rsp:InputStreams>
  <rsp:OutputStreams>stdout</rsp:OutputStreams>
  <rsp:IdleTimeOut>` + idleTimeout + `</rsp:IdleTimeOut>
</rsp:Shell>`
	}
	env.WithBody([]byte(shellBody))

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("create shell: %w", err)
	}

	// Parse CreateResponse to get the authoritative Endpoint Reference
	var resp createResponse
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("parse create response: %w", err)
	}

	epr := &EndpointReference{
		Address:     resp.Body.ResourceCreated.Address,
		ResourceURI: resp.Body.ResourceCreated.ReferenceParameters.ResourceURI,
		Selectors:   resp.Body.ResourceCreated.ReferenceParameters.SelectorSet.Selectors,
	}

	// If ResourceURI is empty in response, use the default
	if epr.ResourceURI == "" {
		epr.ResourceURI = ResourceURIPowerShell
	}
	// If Address is empty, use current endpoint (sanity check)
	// (Address in response is often just the path or full URL)

	return epr, nil
}

// Command creates a new command (Pipeline) in the shell and returns the command ID.
func (c *Client) Command(ctx context.Context, epr *EndpointReference, commandID, arguments string) (string, error) {
	env := NewEnvelope().
		WithAction(ActionCommand).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S").
		WithShellNamespace()

	// Add all selectors
	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

	// Build CommandLine with optional CommandId attribute
	var commandLine []byte
	if commandID != "" {
		commandLine = []byte(`<rsp:CommandLine CommandId="` + commandID + `" xmlns:rsp="` + NsShell + `">
  <rsp:Command></rsp:Command>
`)
	} else {
		commandLine = []byte(`<rsp:CommandLine xmlns:rsp="` + NsShell + `">
  <rsp:Command></rsp:Command>
`)
	}

	if arguments != "" {
		commandLine = append(commandLine, []byte(`  <rsp:Arguments>`+arguments+`</rsp:Arguments>
`)...)
	}

	commandLine = append(commandLine, []byte(`</rsp:CommandLine>
`)...)

	env.WithBody(commandLine)

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return "", fmt.Errorf("create command: %w", err)
	}

	var resp commandResponse
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("parse command response: %w", err)
	}

	return resp.Body.CommandResponse.CommandID, nil
}

// Send sends data to a command's input stream.
func (c *Client) Send(ctx context.Context, epr *EndpointReference, commandID, stream string, data []byte) error {
	encoded := base64.StdEncoding.EncodeToString(data)

	env := NewEnvelope().
		WithAction(ActionSend).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S").
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithShellNamespace()

	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

	var streamNode string
	if commandID != "" {
		streamNode = `<rsp:Stream Name="` + stream + `" CommandId="` + commandID + `">` + encoded + `</rsp:Stream>`
	} else {
		streamNode = `<rsp:Stream Name="` + stream + `">` + encoded + `</rsp:Stream>`
	}

	env.WithBody([]byte(`<rsp:Send xmlns:rsp="` + NsShell + `">
  ` + streamNode + `
</rsp:Send>`))

	_, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}

	return nil
}

// Receive retrieves output from a command's output streams.
func (c *Client) Receive(ctx context.Context, epr *EndpointReference, commandID string) (*ReceiveResult, error) {
	env := NewEnvelope().
		WithAction(ActionReceive).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:"+strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithMaxEnvelopeSize(153600).
		// Fork patch: adapt the poll length to the caller's deadline so the server
		// replies before our socket deadline fires (see operationTimeout). The
		// default (defaultReceivePoll) also bounds how long the single connection
		// is held per poll, so StopPipelines' terminate — which must run on this
		// same connection, since WinRM locks the shell to its owning client — wins
		// the connection mutex quickly instead of being starved by a long-held
		// Receive. That bounds Ctrl-C latency (~one poll) and keeps it well inside
		// the shell's stop timeout.
		WithOperationTimeout(operationTimeout(ctx, defaultReceivePoll())).
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithOption("WSMAN_CMDSHELL_OPTION_KEEPALIVE", "True").
		WithShellNamespace()

	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

	// Match pypsrp format: CommandId IS required on DesiredStream IF it's a command receive
	var streamNode string
	if commandID != "" {
		streamNode = `<rsp:DesiredStream CommandId="` + commandID + `">stdout</rsp:DesiredStream>`
	} else {
		streamNode = `<rsp:DesiredStream>stdout</rsp:DesiredStream>`
	}

	body := []byte(`<rsp:Receive xmlns:rsp="` + NsShell + `">
  ` + streamNode + `
</rsp:Receive>`)

	respBody, err := c.sendEnvelope(ctx, env.WithBody(body))
	if err != nil {
		// If the operation timed out, it just means no data was available.
		// We should return an empty result so the caller can poll again.
		if strings.Contains(err.Error(), "w:TimedOut") || strings.Contains(err.Error(), "OperationTimeout") {
			return &ReceiveResult{}, nil
		}
		return nil, fmt.Errorf("receive: %w", err)
	}

	var resp receiveResponse
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("parse receive response: %w", err)
	}

	result := &ReceiveResult{}

	// Decode streams
	for _, stream := range resp.Body.ReceiveResponse.Streams {
		decoded, err := base64.StdEncoding.DecodeString(stream.Content)
		if err != nil {
			continue // Skip invalid base64
		}

		switch stream.Name {
		case "stdout":
			result.Stdout = append(result.Stdout, decoded...)
		case "stderr":
			result.Stderr = append(result.Stderr, decoded...)
		}
	}

	// Check command state
	result.CommandState = resp.Body.ReceiveResponse.CommandState.State
	if resp.Body.ReceiveResponse.CommandState.ExitCode != nil {
		result.ExitCode = *resp.Body.ReceiveResponse.CommandState.ExitCode
		result.Done = true
	}

	return result, nil
}

// Signal sends a signal to a command.
func (c *Client) Signal(ctx context.Context, epr *EndpointReference, commandID, code string) error {
	env := NewEnvelope().
		WithAction(ActionSignal).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithShellNamespace()

	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

	env.WithBody([]byte(`<rsp:Signal xmlns:rsp="` + NsShell + `" CommandId="` + commandID + `">
  <rsp:Code>` + code + `</rsp:Code>
</rsp:Signal>`))

	_, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("signal: %w", err)
	}

	return nil
}

// Delete deletes a shell.
func (c *Client) Delete(ctx context.Context, epr *EndpointReference) error {
	env := NewEnvelope().
		WithAction(ActionDelete).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + uuid.New().String()).
		WithSessionID(c.sessionID).
		WithReplyTo(AddressAnonymous)

	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

	_, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("delete shell: %w", err)
	}

	return nil
}

// sendEnvelope marshals and sends a SOAP envelope, returning the response body.
func (c *Client) sendEnvelope(ctx context.Context, env *Envelope) ([]byte, error) {
	body, err := env.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	respBody, err := c.transport.Post(ctx, c.endpoint, body)
	if err != nil {
		return nil, err
	}

	// Fork patch: correlate the response to the request before believing a word
	// of it. See checkRelatesTo — this is the only freshness check in the stack,
	// because the Kerberos sealing layer has none available to it.
	if err := checkRelatesTo(env.Header.MessageID, respBody); err != nil {
		return nil, err
	}

	// Check for SOAP Fault even in successful HTTP responses
	if err := CheckFault(respBody); err != nil {
		return nil, fmt.Errorf("wsman: %w", err)
	}

	return respBody, nil
}

// ErrUncorrelatedResponse is a response whose WS-Addressing RelatesTo does not
// echo the MessageID of the request it is supposed to answer.
var ErrUncorrelatedResponse = errors.New("wsman: response does not correlate to the request")

// relatesToEnvelope extracts just the correlator. Bare local names, matching
// the other response structs here: encoding/xml matches on local name, so this
// is namespace-prefix agnostic (responses use a:RelatesTo).
type relatesToEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Header  struct {
		RelatesTo string `xml:"RelatesTo"`
	} `xml:"Header"`
}

// checkRelatesTo verifies a response answers the request that was just sent.
//
// Fork patch. This is the stack's only replay/substitution defence. Message
// sealing gives confidentiality and (with the integrity checks in
// internal/auth/*) authenticity, but neither mechanism provides freshness for
// Kerberos: the acceptor's GSS sequence number is measured to be constant zero
// on both etypes, so there is no counter to compare — see
// docs/verification.md. WS-Addressing is where the correlator actually lives:
// every request carries a random MessageID and the server echoes it as
// RelatesTo, so an attacker replaying a previously captured (and perfectly
// valid) sealed response is caught here and nowhere else.
//
// A missing RelatesTo is a failure, not a skip. Treating absence as "nothing to
// check" would hand an in-path attacker the bypass — strip the header and the
// check evaporates.
//
// The comparison is case-insensitive on purpose. This package generates
// MessageID inconsistently — Delete builds it with a bare uuid.New().String()
// while every other call site upper-cases it — and the server echoes back
// whatever case it was given, so a case-sensitive compare would reject Delete's
// own response. Note the honest scope: Delete is currently only reached from
// client.RemoveDisconnectedSession, which wsmancer never calls, so a
// case-sensitive compare passes every live path today. That makes this a latent
// trap rather than an active bug — which is exactly why it is pinned by a unit
// test instead of being left to a live harness that cannot reach it.
func checkRelatesTo(requestID string, respBody []byte) error {
	if requestID == "" {
		// No correlator was sent, so there is nothing to verify against. No
		// caller in this package does this; it is not a supported bypass.
		return nil
	}
	var env relatesToEnvelope
	if err := xml.Unmarshal(respBody, &env); err != nil {
		// Not a parseable SOAP envelope. The per-method unmarshal that follows
		// will produce the better diagnostic, so do not mask it here.
		return nil
	}
	if got := env.Header.RelatesTo; !strings.EqualFold(got, requestID) {
		return fmt.Errorf("%w: got RelatesTo %q, sent MessageID %q",
			ErrUncorrelatedResponse, got, requestID)
	}
	return nil
}

// CloseIdleConnections closes any idle connections in the underlying transport.
// This forces a fresh NTLM handshake for subsequent requests.
func (c *Client) CloseIdleConnections() {
	c.transport.CloseIdleConnections()
}

// Response types for XML parsing.

type createResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		ResourceCreated struct {
			Address             string `xml:"Address"`
			ReferenceParameters struct {
				ResourceURI string `xml:"ResourceURI"`
				SelectorSet struct {
					Selectors []Selector `xml:"Selector"`
				} `xml:"SelectorSet"`
			} `xml:"ReferenceParameters"`
		} `xml:"ResourceCreated"`
	} `xml:"Body"`
}

type commandResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		CommandResponse struct {
			CommandID string `xml:"CommandId"`
		} `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell CommandResponse"`
	} `xml:"Body"`
}

type receiveResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		ReceiveResponse struct {
			Streams []struct {
				Name      string `xml:"Name,attr"`
				CommandID string `xml:"CommandId,attr"`
				Content   string `xml:",chardata"`
			} `xml:"Stream"`
			CommandState struct {
				CommandID string `xml:"CommandId,attr"`
				State     string `xml:"State,attr"`
				ExitCode  *int   `xml:"ExitCode"`
			} `xml:"CommandState"`
		} `xml:"ReceiveResponse"`
	} `xml:"Body"`
}

type connectResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		ConnectResponse struct {
			ConnectResponseXml string `xml:"connectResponseXml"`
		} `xml:"ConnectResponse"`
	} `xml:"Body"`
}

// Disconnect disconnects the shell on the server without closing it.
// The shell remains active and can be reconnected to later.
func (c *Client) Disconnect(ctx context.Context, epr *EndpointReference) error {
	env := NewEnvelope().
		WithAction(ActionDisconnect).
		WithTo(c.endpoint).
		WithResourceURI(epr.ResourceURI).
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithShellNamespace()

	for _, s := range epr.Selectors {
		env.WithSelector(s.Name, s.Value)
	}

	// Payload is empty for Disconnect
	// But we need a Body with Disconnect element
	// <w:Disconnect />
	body := struct {
		XMLName xml.Name `xml:"rsp:Disconnect"`
		Rsp     string   `xml:"xmlns:rsp,attr"`
	}{
		Rsp: NsShell,
	}
	bodyBytes, err := xml.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal disconnect body: %w", err)
	}
	env.WithBody(bodyBytes)

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("disconnect: %w", err)
	}

	// Response should be just Empty or DisconnectResponse
	fmt.Fprintf(os.Stderr, "DEBUG: Disconnect Response: %s\n", string(respBody))

	if len(respBody) == 0 {
		return nil
	}
	// We could parse it, but we mainly care strictly about error (fault).
	return nil
}

// Reconnect reconnects to a disconnected shell.
func (c *Client) Reconnect(ctx context.Context, shellID string) error {
	// Reconnect is special: We only have the ShellID from the user.
	// We must assume standard ResourceURI and just ShellID selector.
	// NOTE: This assumes Reconnect doesn't require extra selectors the server generated during Create.
	// If it DOES, then the user must provide ALL selectors, which is hard.
	// For now, valid assumption is ShellID is unique enough for Reconnect.

	env := NewEnvelope().
		WithAction(ActionReconnect).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:"+strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithShellNamespace().
		WithSelector("ShellId", shellID)

	// <w:Reconnect />
	body := struct {
		XMLName xml.Name `xml:"rsp:Reconnect"`
		Rsp     string   `xml:"xmlns:rsp,attr"`
	}{
		Rsp: NsShell,
	}
	bodyBytes, err := xml.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal reconnect body: %w", err)
	}
	env.WithBody(bodyBytes)

	_, err = c.sendEnvelope(ctx, env)
	if err != nil {
		return fmt.Errorf("reconnect: %w", err)
	}

	return nil
}

// Connect connects to an existing disconnected shell using WSManConnectShellEx semantics.
// This is for NEW clients connecting to a session disconnected by a different client.
// The connectXML should contain base64-encoded PSRP handshake data
// (SessionCapability + ConnectRunspacePool messages).
// Returns the base64-decoded response data from the server.
func (c *Client) Connect(ctx context.Context, shellID string, connectXML string) ([]byte, error) {
	env := NewEnvelope().
		WithAction(ActionConnect).
		WithTo(c.endpoint).
		WithResourceURI(ResourceURIPowerShell).
		WithMessageID("uuid:"+strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithShellNamespace().
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S").
		WithLocale("en-US").
		WithDataLocale("en-US").
		WithSelector("ShellId", shellID)

	// Build body with connectXml containing PSRP handshake data
	// Format matches pypsrp exactly: <rsp:Connect><connectXml xmlns="...">base64data</connectXml></rsp:Connect>
	body := `<rsp:Connect xmlns:rsp="` + NsShell + `">
  <connectXml xmlns="http://schemas.microsoft.com/powershell">` + connectXML + `</connectXml>
</rsp:Connect>`
	env.WithBody([]byte(body))

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	// Parse response to extract connectResponseXml
	var resp connectResponse
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		// Return raw response if parsing fails
		return respBody, nil
	}

	// Decode base64 response data
	if resp.Body.ConnectResponse.ConnectResponseXml != "" {
		decoded, err := base64.StdEncoding.DecodeString(resp.Body.ConnectResponse.ConnectResponseXml)
		if err != nil {
			return nil, fmt.Errorf("decode connect response: %w", err)
		}
		return decoded, nil
	}

	return respBody, nil
}

// EnumerateShell represents a shell discovered via WSMan Enumerate.
type EnumerateShell struct {
	ShellID string
	Name    string
	State   string
	Owner   string
}

// enumerateResponse is for parsing WSMan Enumerate response.
type enumerateResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		EnumerateResponse struct {
			Items struct {
				Shells []struct {
					ShellID string `xml:"ShellId"`
					Name    string `xml:"Name"`
					State   string `xml:"State"`
					Owner   string `xml:"Owner"`
				} `xml:"Shell"`
			} `xml:"Items"`
		} `xml:"EnumerateResponse"`
	} `xml:"Body"`
}

// Enumerate lists available shells on the server.
// Returns a list of shells with their IDs, which can be used for reconnection.
func (c *Client) Enumerate(ctx context.Context) ([]EnumerateShell, error) {
	env := NewEnvelope().
		WithAction(ActionEnumerate).
		WithTo(c.endpoint).
		WithResourceURI(NsShell). // Use shell namespace to enumerate shells
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S")

	// Body with OptimizeEnumeration and MaxElements
	body := fmt.Sprintf(`<wsen:Enumerate xmlns:wsen="%s" xmlns:wsman="%s">
  <wsman:OptimizeEnumeration/>
  <wsman:MaxElements>32000</wsman:MaxElements>
</wsen:Enumerate>`, NsEnumeration, NsWsman)
	env.WithBody([]byte(body))

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("enumerate: %w", err)
	}

	// Parse response
	var resp enumerateResponse
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		// Return empty list on parse error, log for debugging
		if os.Getenv("PSRP_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "DEBUG: Enumerate response parse error: %v\nResponse: %s\n", err, string(respBody))
		}
		return nil, nil
	}

	// Convert to EnumerateShell
	var shells []EnumerateShell
	for _, s := range resp.Body.EnumerateResponse.Items.Shells {
		shells = append(shells, EnumerateShell{
			ShellID: s.ShellID,
			Name:    s.Name,
			State:   s.State,
			Owner:   s.Owner,
		})
	}

	return shells, nil
}

// EnumerateCommands lists commands (pipelines) for a specific shell.
// This is used to discover disconnected pipelines within a shell.
func (c *Client) EnumerateCommands(ctx context.Context, shellID string) ([]string, error) {
	env := NewEnvelope().
		WithAction(ActionEnumerate).
		WithTo(c.endpoint).
		WithResourceURI(NsShell + "/Command"). // Command resource URI
		WithMessageID("uuid:" + strings.ToUpper(uuid.New().String())).
		WithReplyTo(AddressAnonymous).
		WithSessionID(c.sessionID).
		WithMaxEnvelopeSize(153600).
		WithOperationTimeout("PT60S")

	// Body with filter by ShellId
	body := fmt.Sprintf(`<wsen:Enumerate xmlns:wsen="%s" xmlns:wsman="%s">
  <wsman:OptimizeEnumeration/>
  <wsman:MaxElements>32000</wsman:MaxElements>
  <wsman:Filter Dialect="http://schemas.dmtf.org/wbem/wsman/1/wsman/SelectorFilter">
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">%s</wsman:Selector>
    </wsman:SelectorSet>
  </wsman:Filter>
</wsen:Enumerate>`, NsEnumeration, NsWsman, shellID)
	env.WithBody([]byte(body))

	respBody, err := c.sendEnvelope(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("enumerate commands: %w", err)
	}

	// Parse response for CommandId elements
	type commandEnumerateResp struct {
		XMLName xml.Name `xml:"Envelope"`
		Body    struct {
			EnumerateResponse struct {
				Items struct {
					Commands []struct {
						CommandID string `xml:"CommandId"`
					} `xml:"Command"`
				} `xml:"Items"`
			} `xml:"EnumerateResponse"`
		} `xml:"Body"`
	}

	var resp commandEnumerateResp
	if err := xml.Unmarshal(respBody, &resp); err != nil {
		if os.Getenv("PSRP_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "DEBUG: EnumerateCommands response parse error: %v\nResponse: %s\n", err, string(respBody))
		}
		return nil, nil
	}

	var commandIDs []string
	for _, cmd := range resp.Body.EnumerateResponse.Items.Commands {
		commandIDs = append(commandIDs, cmd.CommandID)
	}

	return commandIDs, nil
}
