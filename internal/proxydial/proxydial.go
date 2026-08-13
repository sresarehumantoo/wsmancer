// Package proxydial routes this tool's one outbound TCP connection through a
// SOCKS5 proxy, so a WinRM listener that is only reachable from inside a
// network can be driven from outside it.
//
// Why this exists as code rather than as advice to run proxychains: it cannot
// work. proxychains hooks connect(2) by LD_PRELOAD-ing a shim over libc, and a
// static Go binary, which is what this tool builds to, deliberately, issues
// its syscalls directly and never links libc's connect at all. The shim is
// simply never called, and the dial goes out of the attacker's own interface:
// it does not error, it silently ignores the proxy. So a pivot has to be
// dialled from inside the process.
//
// Only SOCKS5 is accepted. The proxies that matter here, chisel, ligolo-ng,
// Metasploit's socks_proxy, ssh -D, all speak it, and an HTTP CONNECT proxy
// solves the opposite problem (egress from a corporate network to the internet)
// rather than ingress to an internal listener.
//
// Names are resolved *at the proxy*, never locally. That is what "socks5h"
// means elsewhere, and it is the only useful behavior here: an internal
// hostname usually has no answer on the attacker's resolver, and Kerberos wants
// the target's real FQDN in the SPN. Both scheme spellings behave this way, so
// socks5:// and socks5h:// are accepted as synonyms, there is no local
// resolution mode to distinguish them.
package proxydial

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// dialTimeout bounds reaching the proxy, the SOCKS negotiation that follows, the
// connection to the target beyond it, and (in DialTLS) the handshake, the whole
// of what tls.DialWithDialer's Timeout used to cover. A var, not a const, only so
// the tests can drive the deadline paths without taking 15 seconds to do it.
var dialTimeout = 15 * time.Second

// Dialer is the subset of a net.Dialer that the auth providers use. A nil
// *Dialer is valid and dials directly, so callers can hold one unconditionally
// and never branch on whether a proxy was asked for.
type Dialer struct {
	// forward is nil when no proxy was configured.
	forward proxy.ContextDialer
	// addr is the proxy's host:port, for error messages.
	addr string
}

// New builds a Dialer from a proxy URL such as socks5://127.0.0.1:1080 or
// socks5://user:pass@10.10.14.3:1080. An empty string yields a direct dialer,
// which is the no-proxy case rather than an error.
//
// It performs no I/O: the proxy is contacted on the first dial, so a wrong
// address surfaces as a connection error against a real request rather than at
// flag-parse time. That also makes it safe for the CLI to call purely to
// validate the string.
func New(raw string) (*Dialer, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	// Checked before url.Parse, which rejects a bare "host:port" with "first path
	// segment in URL cannot contain colon", accurate, and no help at all to
	// someone who just left the scheme off.
	if !strings.Contains(raw, "://") {
		return nil, fmt.Errorf("--proxy %q: missing scheme (want socks5://%s)", raw, raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("--proxy %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("--proxy %q: unsupported scheme %q, only socks5 is supported, "+
			"which is what chisel, ligolo-ng, msf socks_proxy and ssh -D speak", raw, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("--proxy %q: missing host (want socks5://host:port)", raw)
	}
	// A bare host is almost always a typo rather than an intent to use SOCKS's
	// unassigned default port, and "connection refused" would be a poor way to
	// find that out.
	if u.Port() == "" {
		return nil, fmt.Errorf("--proxy %q: missing port (want socks5://%s:1080)", raw, u.Host)
	}

	var auth *proxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pass}
	}
	d, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: dialTimeout})
	if err != nil {
		return nil, fmt.Errorf("--proxy %q: %w", raw, err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		// x/net's SOCKS5 dialer has implemented ContextDialer since 2019; this is
		// a guard against a future version silently regressing us to a dial that
		// ignores cancellation.
		return nil, errors.New("internal: SOCKS5 dialer does not support contexts")
	}
	return &Dialer{forward: cd, addr: u.Host}, nil
}

// Addr reports the proxy's host:port, or "" for a direct dialer. It is for
// banners and error text; nothing behavioural keys off it.
func (d *Dialer) Addr() string {
	if d == nil {
		return ""
	}
	return d.addr
}

// DialContext dials addr, through the proxy when there is one.
//
// The host in addr is passed to the proxy as a name whenever it is not already
// an IP literal, x/net's SOCKS5 client only resolves locally if it is handed a
// literal, so an internal FQDN is looked up on the far side. See the package
// comment.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Bound every dial, unconditionally. Two reasons, and the second is why this
	// is not gated on the context already having a deadline:
	//
	//   - A command's context is cancel-only (see the auth providers), so a proxy
	//     that accepts the TCP connection and then says nothing would otherwise
	//     hang the dial forever, the failure mode deadCommsBackstop exists for
	//     one layer up.
	//   - It preserves what the net.Dialer{Timeout: 15s} this replaced did. The
	//     callers' contexts do carry deadlines (60s at connect), and inheriting
	//     those would quietly stretch "this host is dead" from 15s to a minute.
	//
	// WithTimeout keeps an earlier deadline if the caller's is sooner, so this
	// only ever tightens.
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if d == nil || d.forward == nil {
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	}
	conn, err := d.forward.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("via socks5 %s: %w", d.addr, err)
	}
	return conn, nil
}

// DialTLS dials addr and completes a TLS handshake over the result.
//
// It replaces tls.DialWithDialer, which cannot be pointed at a proxy. Two of
// that function's behaviors are load-bearing and are reproduced here rather
// than left to the caller:
//
//   - ServerName defaults to the dialled host when the config does not set one.
//     Without it the handshake sends no SNI and certificate verification has no
//     name to check, so a correct certificate is rejected, and on a proxied
//     connection the address is the *target's*, not the proxy's, which is the
//     name that must go out.
//   - One deadline covers the dial *and* the handshake, as DialWithDialer's
//     Timeout did. It has to be established here rather than left to
//     DialContext, whose own bound is released the moment it returns, a peer
//     that completes the TCP connection and then says nothing during the
//     handshake would otherwise block for as long as the caller's context
//     allows, which for a command context is forever.
func DialTLS(ctx context.Context, d *Dialer, network, addr string, cfg *tls.Config) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if cfg.ServerName == "" {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			host = addr
		}
		cfg = cfg.Clone()
		cfg.ServerName = host
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}
