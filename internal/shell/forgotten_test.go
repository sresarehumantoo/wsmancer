package shell

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sresarehumantoo/go-psrp/client"
)

// shellNotFoundSummary is the VERBATIM line the fork's soapFaultSummary produces
// for WinRM's shell-not-found fault, which is the form that actually reaches the
// shell, the raw envelope never does. Taken from the summarizer's own output
// for the fixture in the go-psrp fork's wsman/transport/soapfault_test.go, rather
// than hand-written, so a change to the summary format breaks this test instead of
// silently disarming the classifier.
const shellNotFoundSummary = `wsman fault: s:Sender: w:InvalidSelectors: The request for the ` +
	`Windows Remote Shell with ShellId 4F8A2C11-0000-0000-0000-000000000001 failed because the ` +
	`shell was not found on the server. Possible causes are: the specified ShellId is incorrect ` +
	`or the shell no longer exists on the server. Provide the correct ShellId or create a new ` +
	`shell and retry the operation.: code=2150858843`

func TestShellForgottenRecognisesTheFault(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"the summarized fault as the operator's layer sees it", errors.New(shellNotFoundSummary)},
		{
			"wrapped by the transport, as a returned error",
			fmt.Errorf("wsman receive: receive: transport: request failed: HTTP 500: %s", shellNotFoundSummary),
		},
		// clean() caps each fault field at 600 characters, so a longer provider
		// message can be cut mid-sentence. Either half of the wording must still
		// classify, which is why the two phrases are matched separately.
		{
			"truncated before the second phrase",
			errors.New(`wsman fault: s:Sender: w:InvalidSelectors: The request for the Windows ` +
				`Remote Shell with ShellId X failed because the shell was not found on the server...`),
		},
		{
			"truncated before the first phrase",
			errors.New(`wsman fault: s:Sender: w:InvalidSelectors: ...the shell no longer exists ` +
				`on the server. Provide the correct ShellId: code=2150858843`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !shellForgotten(tc.err) {
				t.Errorf("shellForgotten() = false for a real forgotten shell:\n  %v", tc.err)
			}
		})
	}
}

// The trap this classifier exists to avoid. WSManFault code 2150858843 means
// "invalid selectors" generally, and WinRM uses it for an already-finished
// command as well as for a lost shell, the fork's isCommandGone matches the
// very same code. StopPipelines provokes the command-gone form routinely, so a
// classifier keyed on the code would treat an ordinary Ctrl-C as a lost shell,
// tear down a live runspace and destroy the operator's variables, functions,
// -s scripts and bypass-4msi patch. Recovery is destructive, so a false
// positive here is far worse than a missed diagnosis.
func TestShellForgottenIgnoresTheCommandGoneFaultSharingItsCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{
			"already-finished command, same fault code",
			errors.New(`wsman fault: s:Sender: w:InvalidSelectors: The request for the Windows ` +
				`Remote Shell with ShellId 4F8A2C11 failed because it used a command identifier ` +
				`that does not exist on the server.: code=2150858843`),
		},
		{
			"command completed between Signal and Receive",
			errors.New(`signal terminate 1C5D11D7: wsman fault: w:InvalidSelectors: the command ` +
				`has completed execution: code=2150858843`),
		},
		{"the bare code on its own", errors.New("signal terminate 1C5D11D7: fault 2150858843")},
		{"the subcode on its own", errors.New("wsman fault: w:InvalidSelectors")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if shellForgotten(tc.err) {
				t.Errorf("shellForgotten() = true for a fault that is NOT a lost shell:\n  %v", tc.err)
			}
		})
	}
}

// Recovery discards the runspace, so anything that is merely a failed command or
// a recoverable connection break must not reach it.
func TestShellForgottenIgnoresOrdinaryErrors(t *testing.T) {
	cases := []error{
		nil,
		errors.New("upload: local file not found: /tmp/nope"),
		errors.New(`The term 'foo' is not recognized as the name of a cmdlet`),
		errors.New("Access is denied"),
		errors.New("w:TimedOut"),
		// A dropped connection re-attaches to the SAME shell and keeps the
		// runspace, so misfiling it here would throw away state that survived.
		errors.New(`read fragment header: wsman receive: receive: transport: request failed: ` +
			`Post "http://10.0.0.1:5985/wsman": dial tcp 10.0.0.1:5985: i/o timeout`),
		errors.New(`read response: read tcp 10.0.0.2:46572->10.0.0.1:5985: read: connection reset by peer`),
	}
	for _, err := range cases {
		if shellForgotten(err) {
			t.Errorf("shellForgotten() = true for an ordinary error: %v", err)
		}
	}
}

// The two classifiers must not both claim an error: executeAs and reportErr try
// shellForgotten first, so an overlap would route a recoverable connection break
// into a destructive re-create.
func TestShellForgottenAndConnectionLostAreDisjoint(t *testing.T) {
	forgotten := errors.New(shellNotFoundSummary)
	if connectionLost(forgotten) {
		t.Errorf("connectionLost() also claims the forgotten-shell fault; the two must be disjoint:\n  %v", forgotten)
	}
}

func TestResultShellForgotten(t *testing.T) {
	forgotten := errors.New(shellNotFoundSummary)

	t.Run("error record carried as an error", func(t *testing.T) {
		res := &client.Result{Errors: []interface{}{forgotten}}
		if resultShellForgotten(res) == nil {
			t.Error("resultShellForgotten() = nil for a pipeline aborted by a lost shell")
		}
	})
	t.Run("error record carried as a string", func(t *testing.T) {
		res := &client.Result{Errors: []interface{}{shellNotFoundSummary}}
		if resultShellForgotten(res) == nil {
			t.Error("resultShellForgotten() = nil for a lost shell reported as a string")
		}
	})
	// A command that produced output and then failed is a genuine PowerShell
	// error being reported by a working shell -- re-creating on that would
	// discard a live runspace over a command's own failure.
	t.Run("ignored when the command produced output", func(t *testing.T) {
		res := &client.Result{Output: []interface{}{"some output"}, Errors: []interface{}{forgotten}}
		if err := resultShellForgotten(res); err != nil {
			t.Errorf("resultShellForgotten() = %v for a result that produced output", err)
		}
	})
	t.Run("nil and empty results", func(t *testing.T) {
		if err := resultShellForgotten(nil); err != nil {
			t.Errorf("resultShellForgotten(nil) = %v", err)
		}
		if err := resultShellForgotten(&client.Result{}); err != nil {
			t.Errorf("resultShellForgotten(empty) = %v", err)
		}
	})
}
