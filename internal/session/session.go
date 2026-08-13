// Package session wraps a go-psrp client: it turns parsed CLI options into an
// authenticated PSRP runspace and runs commands against it.
package session

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/smnsjas/go-psrp/client"

	"github.com/sresarehumantoo/wsmancer/internal/auth/certauth"
	"github.com/sresarehumantoo/wsmancer/internal/auth/krbseal"
	"github.com/sresarehumantoo/wsmancer/internal/auth/ntlmseal"
	"github.com/sresarehumantoo/wsmancer/internal/cli"
	"github.com/sresarehumantoo/wsmancer/internal/proxydial"
)

type Session struct {
	// mu guards c, which Renew swaps out. Every other field is fixed at
	// construction. Reads are on the hot path but uncontended; the one genuine
	// concurrent reader is Ctrl-C's StopPipelines, which runs on the signal
	// goroutine while Execute is in flight on the main one.
	mu   sync.RWMutex
	c    *client.Client
	opts *cli.Options
	mode string // human-readable auth description, for the banner
	// proxy is the SOCKS5 proxy's host:port, or "" when dialling directly. It
	// comes from the dialer rather than from the flag so that any credentials in
	// the URL cannot reach a banner or a log line.
	proxy string
}

// client returns the live client. Callers must not cache it: Renew replaces it.
func (s *Session) client() *client.Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.c
}

// Renew replaces the underlying client with a freshly connected one, for when
// the target has forgotten our shell (a WinRM restart, or the IdleTimeout
// elapsing) and no amount of re-dialling can get it back.
//
// It has to build a whole new client rather than reconnect this one: the fork's
// Close latches `closed` and Connect refuses a closed client, while a client
// whose shell is gone still reports itself connected, so Connect would return
// nil and change nothing.
//
// The new client is connected *before* the swap, so a failure leaves the caller
// holding the original, dead, but no worse than it was, and still able to
// report the failure. The old client is then closed with the force strategy,
// which skips the network calls: its shell no longer exists, so a graceful
// close would only block on faults for a shell the server has already dropped.
//
// This does not restore session state, and it is not meant to. The runspace is
// new: working directory, variables, functions, -s scripts and any bypass-4msi
// patch are gone. Callers must tell the operator so, see internal/shell's
// recoverShell, and the note on shellForgotten about why silence would be
// worse than the error.
func (s *Session) Renew(ctx context.Context) error {
	fresh, _, _, err := build(s.opts)
	if err != nil {
		return err
	}
	if err := fresh.Connect(ctx); err != nil {
		_ = fresh.CloseWithStrategy(ctx, client.CloseStrategyForce)
		return err
	}

	s.mu.Lock()
	old := s.c
	s.c = fresh
	s.mu.Unlock()

	if old != nil {
		_ = old.CloseWithStrategy(ctx, client.CloseStrategyForce)
	}
	return nil
}

// New builds the client and selects an auth provider. Both providers are our
// own: stock go-psrp cannot talk to a default-configured WinRM listener because
// it does not seal WSMan message payloads (see internal/auth/*).
func New(o *cli.Options) (*Session, error) {
	c, mode, proxy, err := build(o)
	if err != nil {
		return nil, err
	}
	return &Session{c: c, opts: o, mode: mode, proxy: proxy}, nil
}

// build constructs a client from the options, along with the banner's auth
// description and the proxy address. It is separate from New so that Renew can
// do it again, and so both paths select the auth provider by exactly the same
// rules rather than drifting apart. mode and proxy are pure functions of o, so
// Renew discards them and the banner printed at startup stays true.
func build(o *cli.Options) (*client.Client, string, string, error) {
	cfg := client.DefaultConfig()
	cfg.Port = o.Port
	cfg.UseTLS = o.SSL
	cfg.Timeout = 120 * time.Second
	cfg.AuthType = client.AuthNTLM

	// TLS is driven entirely through the authenticator's own single connection
	// (below), so go-psrp's transport never dials, leaving its InsecureSkipVerify
	// at the default keeps it from printing a TLS warning, including on plain
	// HTTP where there is no TLS at all. On HTTPS we build the real config here.
	var tlsCfg *tls.Config
	if o.SSL {
		var err error
		if tlsCfg, err = buildServerTLSConfig(o); err != nil {
			return nil, "", "", err
		}
		if o.Insecure {
			fmt.Fprintln(os.Stderr, "WARNING: TLS certificate verification disabled (--insecure). "+
				"The connection is encrypted but not authenticated: a man-in-the-middle can read and "+
				"alter traffic. Prefer --ca-cert or --accept-fingerprint.")
		}
	}

	// The proxy dialer, if any. Every provider takes it, because every provider
	// opens the tool's one outbound connection itself; nil means dial directly.
	// The URL was already validated by cli.Options.validate, so this cannot fail
	// here, but it is checked rather than dropped, since a future caller
	// building Options by hand would otherwise proxy nothing, silently.
	dialer, err := proxydial.New(o.Proxy)
	if err != nil {
		return nil, "", "", err
	}

	user, domain := splitUser(o.User, o.Realm)
	cfg.Username, cfg.Domain = user, domain

	var mode string
	switch o.AuthMode() {
	case cli.AuthCertificate:
		prov, err := certauth.New(certauth.Config{TLSConfig: tlsCfg, UserAgent: o.UserAgent, Dialer: dialer})
		if err != nil {
			return nil, "", "", err
		}
		cfg.CustomAuthenticator = prov
		// No username is sent at all: the target decides who the certificate maps
		// to, so anything we put here would be a guess printed as fact.
		cfg.Username, cfg.Domain = "", ""
		mode = "client certificate (no sealing; TLS carries it)"

	case cli.AuthKerberos:
		spn := fmt.Sprintf("%s/%s", o.SPNPrefix, o.IP)
		prov, err := krbseal.New(krbseal.Config{
			TicketPath:  o.CCache,
			SPN:         spn,
			SkewSeconds: o.Skew,
			UserAgent:   o.UserAgent,
			TLSConfig:   tlsCfg,
			SealEnabled: true,
			Dialer:      dialer,
		})
		if err != nil {
			return nil, "", "", fmt.Errorf("kerberos: %w", err)
		}
		cfg.CustomAuthenticator = prov
		mode = fmt.Sprintf("Kerberos + sealing (%s)", spn)

	case cli.AuthHash:
		nt, err := parseNTHash(o.Hash)
		if err != nil {
			return nil, "", "", err
		}
		prov, err := ntlmseal.New(ntlmseal.Config{
			User: user, Domain: domain, NTHash: nt, UserAgent: o.UserAgent, TLSConfig: tlsCfg,
			Dialer: dialer,
		})
		if err != nil {
			return nil, "", "", fmt.Errorf("ntlm: %w", err)
		}
		cfg.CustomAuthenticator = prov
		mode = "NTLM pass-the-hash + sealing"

	default:
		if o.Password == "" {
			return nil, "", "", errors.New("no credentials: give -p/--password, -H/--hash or -K/--ccache " +
				"(with a terminal, leaving -p off prompts for the password)")
		}
		cfg.Password = o.Password
		prov, err := ntlmseal.New(ntlmseal.Config{
			User: user, Domain: domain, Password: o.Password, UserAgent: o.UserAgent, TLSConfig: tlsCfg,
			Dialer: dialer,
		})
		if err != nil {
			return nil, "", "", fmt.Errorf("ntlm: %w", err)
		}
		cfg.CustomAuthenticator = prov
		mode = "NTLM password + sealing"
	}

	// Passing a full URL makes go-psrp use it verbatim, which is how -U/--url
	// and a non-default port take effect.
	c, err := client.New(o.Endpoint(), cfg)
	if err != nil {
		return nil, "", "", err
	}
	if os.Getenv("WSMANCER_DEBUG") != "" {
		c.SetSlogLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	return c, mode, dialer.Addr(), nil
}

func (s *Session) AuthMode() string { return s.mode }

// ProxyAddr is the SOCKS5 proxy's host:port, or "" for a direct connection.
// Credentials are never included; see Session.proxy.
func (s *Session) ProxyAddr() string { return s.proxy }
func (s *Session) Endpoint() string  { return s.client().Endpoint() }

func (s *Session) Connect(ctx context.Context) error { return s.client().Connect(ctx) }

func (s *Session) Close(ctx context.Context) error { return s.client().Close(ctx) }

// StopPipelines terminates whatever is running on the target. Canceling the
// context of a Run only abandons the local wait, the remote pipeline keeps going
// and, with a single runspace, blocks every later command. Ctrl-C has to do this
// as well to actually interrupt anything.
func (s *Session) StopPipelines(ctx context.Context) error { return s.client().StopPipelines(ctx) }

// RunRaw executes a script and keeps the pipeline's objects intact. This is the
// path -o json uses: no remote formatting, so typed properties survive.
func (s *Session) RunRaw(ctx context.Context, script string) (*client.Result, error) {
	return s.client().Execute(ctx, script)
}

// RunFormatted executes a command and lets PowerShell format it remotely, which
// is what makes text mode look like a real console (tables, columns) instead of
// a list of ToString() values.
//
// The command is handed to Invoke-Expression via a here-string so that any
// quoting inside it survives, and so it runs in the caller's scope, meaning
// `cd` and variable assignments persist across commands like a real shell.
func (s *Session) RunFormatted(ctx context.Context, cmd string) (*client.Result, error) {
	if !safeForHereString(cmd) {
		// Can't embed it safely; run as-is and format locally instead of
		// risking a mangled script.
		return s.RunRaw(ctx, cmd)
	}
	script := "Invoke-Expression @'\n" + cmd + "\n'@ | Out-String -Width 512"
	return s.client().Execute(ctx, script)
}

// safeForHereString rejects commands containing a here-string terminator at the
// start of a line, which would close the literal early.
func safeForHereString(cmd string) bool {
	for _, line := range strings.Split(cmd, "\n") {
		if strings.HasPrefix(strings.TrimRight(line, " \t\r"), "'@") {
			return false
		}
	}
	return true
}

// Pwd returns the remote working directory, for the prompt.
func (s *Session) Pwd(ctx context.Context) (string, error) {
	res, err := s.client().Execute(ctx, "(Get-Location).Path")
	if err != nil {
		return "", err
	}
	if len(res.Output) == 0 {
		return "", errors.New("no output from Get-Location")
	}
	if str, ok := res.Output[0].(string); ok {
		return strings.TrimSpace(str), nil
	}
	return strings.TrimSpace(fmt.Sprintf("%v", res.Output[0])), nil
}

// splitUser accepts DOMAIN\user and user@domain as well as a bare username with
// -r/--realm. NTLM needs the domain set explicitly or the account is not found.
func splitUser(user, realm string) (string, string) {
	if i := strings.IndexAny(user, `\/`); i >= 0 {
		return user[i+1:], user[:i]
	}
	if i := strings.LastIndex(user, "@"); i > 0 {
		return user[:i], user[i+1:]
	}
	return user, realm
}

// parseNTHash accepts a bare 32-hex NT hash or the LM:NT form pasted from
// secretsdump output.
func parseNTHash(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("-H/--hash is not valid hex: %w", err)
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("-H/--hash must be a 16-byte NT hash (32 hex chars), got %d", len(b))
	}
	return b, nil
}
