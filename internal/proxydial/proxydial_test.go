package proxydial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewRejectsBadURLs(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"http proxy", "http://127.0.0.1:8080", "only socks5"},
		{"socks4", "socks4://127.0.0.1:1080", "only socks5"},
		{"no scheme", "127.0.0.1:1080", "scheme"},
		{"no port", "socks5://127.0.0.1", "missing port"},
		{"no host", "socks5://", "missing host"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := New(c.raw)
			if err == nil {
				t.Fatalf("New(%q) = %v, want an error", c.raw, d)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("New(%q) error = %q, want it to mention %q", c.raw, err, c.want)
			}
			// The message has to name the flag, since this surfaces at startup
			// with nothing else around it to say where the string came from.
			if !strings.Contains(err.Error(), "--proxy") {
				t.Errorf("New(%q) error = %q, want it to name --proxy", c.raw, err)
			}
		})
	}
}

func TestNewAccepts(t *testing.T) {
	for _, raw := range []string{
		"socks5://127.0.0.1:1080",
		"socks5h://127.0.0.1:1080",
		"SOCKS5://127.0.0.1:1080",
		"socks5://user:pass@127.0.0.1:1080",
	} {
		d, err := New(raw)
		if err != nil {
			t.Fatalf("New(%q): %v", raw, err)
		}
		if d.Addr() != "127.0.0.1:1080" {
			t.Errorf("New(%q).Addr() = %q, want the host:port with no credentials", raw, d.Addr())
		}
	}
}

// A nil *Dialer is the no-proxy case and must dial directly rather than panic,
// every provider holds one unconditionally.
func TestNilDialerDialsDirect(t *testing.T) {
	if d, err := New(""); err != nil || d != nil {
		t.Fatalf(`New("") = (%v, %v), want (nil, nil)`, d, err)
	}
	backend := echoServer(t)
	var d *Dialer
	conn, err := d.DialContext(context.Background(), "tcp", backend)
	if err != nil {
		t.Fatalf("nil dialer DialContext: %v", err)
	}
	defer conn.Close()
	if got := roundTrip(t, conn, "direct"); got != "direct" {
		t.Errorf("echo = %q, want %q", got, "direct")
	}
}

// The load-bearing property: the target's name is resolved *at the proxy*.
// The hostname used here exists in no resolver anywhere, only in the test
// proxy's routing table, so a build that resolved locally cannot pass.
func TestDialSendsHostnameToProxy(t *testing.T) {
	backend := echoServer(t)
	const internalName = "dc01.internal.invalid"
	px := startSOCKS(t, map[string]string{internalName + ":5985": backend}, nil)

	d, err := New("socks5://" + px.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", internalName+":5985")
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	if got := roundTrip(t, conn, "pivot"); got != "pivot" {
		t.Errorf("echo through proxy = %q, want %q", got, "pivot")
	}
	atyp, addr := px.lastRequest()
	if atyp != atypDomain {
		t.Errorf("proxy saw ATYP %d, want %d (domain name), the name was resolved locally", atyp, atypDomain)
	}
	if addr != internalName {
		t.Errorf("proxy saw address %q, want %q", addr, internalName)
	}
}

// An IP literal has nothing to resolve, and must go out as an IP address rather
// than as the string.
func TestDialSendsIPLiteralAsIP(t *testing.T) {
	backend := echoServer(t)
	px := startSOCKS(t, nil, nil)

	d, err := New("socks5://" + px.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", backend)
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()
	if atyp, _ := px.lastRequest(); atyp != atypIPv4 {
		t.Errorf("proxy saw ATYP %d, want %d (IPv4)", atyp, atypIPv4)
	}
}

func TestDialSendsCredentials(t *testing.T) {
	backend := echoServer(t)
	px := startSOCKS(t, nil, &creds{user: "op", pass: "s3cr3t"})

	d, err := New("socks5://op:s3cr3t@" + px.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", backend)
	if err != nil {
		t.Fatalf("dial with credentials: %v", err)
	}
	conn.Close()

	// And the negative half: the wrong password must be refused, or "it worked"
	// above would prove only that the proxy ignored what we sent.
	bad, err := New("socks5://op:wrong@" + px.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c, err := bad.DialContext(context.Background(), "tcp", backend); err == nil {
		c.Close()
		t.Error("dial with the wrong password succeeded, want it refused")
	}
}

// A dial error must name the proxy: "connection refused" against an address the
// operator never typed is the confusing case this wraps.
func TestDialErrorNamesProxy(t *testing.T) {
	d, err := New("socks5://127.0.0.1:1") // nothing listens on port 1
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = d.DialContext(context.Background(), "tcp", "10.0.0.1:5985")
	if err == nil {
		t.Fatal("dial to a dead proxy succeeded")
	}
	if !strings.Contains(err.Error(), "socks5 127.0.0.1:1") {
		t.Errorf("error = %q, want it to name the proxy", err)
	}
}

func TestDialContextRespectsCancellation(t *testing.T) {
	px := startSOCKS(t, nil, nil)
	d, err := New("socks5://" + px.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c, err := d.DialContext(ctx, "tcp", "10.0.0.1:5985"); err == nil {
		c.Close()
		t.Fatal("dial with a canceled context succeeded")
	}
}

// DialTLS replaces tls.DialWithDialer, so it must reproduce the behavior that
// function is relied on for: defaulting ServerName to the dialled host.
//
// The name is dialled through the proxy, which is both the realistic case and
// the only way to get a *name* (rather than an IP) in front of DialTLS in a
// test, and the name has to be the one the target's certificate carries. A
// build that left ServerName empty fails here twice over: no SNI goes out, and
// crypto/tls refuses the handshake outright ("either ServerName or
// InsecureSkipVerify must be specified").
func TestDialTLSDefaultsServerName(t *testing.T) {
	srv := quietTLSServer(t)
	px := startSOCKS(t, map[string]string{"example.com:5986": strings.TrimPrefix(srv.URL, "https://")}, nil)

	d, err := New("socks5://" + px.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	conn, err := DialTLS(context.Background(), d, "tcp", "example.com:5986", &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if state.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q, SNI is the target's name, not the proxy's", state.ServerName, "example.com")
	}
	if !state.HandshakeComplete {
		t.Error("handshake did not complete")
	}
}

// The same defaulting, for an IP target, where it is invisible in
// ConnectionState, because crypto/tls never puts an IP literal in SNI. What it
// still does is give certificate verification a name to check against the IP
// SANs, so a build that skipped the defaulting fails the handshake here.
func TestDialTLSDefaultsServerNameForIP(t *testing.T) {
	srv := quietTLSServer(t)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	host := strings.TrimPrefix(srv.URL, "https://")

	conn, err := DialTLS(context.Background(), nil, "tcp", host, &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatalf("DialTLS to an IP: %v", err)
	}
	defer conn.Close()
	if !conn.(*tls.Conn).ConnectionState().HandshakeComplete {
		t.Error("handshake did not complete")
	}
}

// An explicit ServerName is the caller's verification policy (internal/session
// sets it) and must survive untouched.
func TestDialTLSKeepsExplicitServerName(t *testing.T) {
	srv := quietTLSServer(t)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	host := strings.TrimPrefix(srv.URL, "https://")

	conn, err := DialTLS(context.Background(), nil, "tcp", host, &tls.Config{
		RootCAs: pool, ServerName: "example.com",
	})
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer conn.Close()
	if got := conn.(*tls.Conn).ConnectionState().ServerName; got != "example.com" {
		t.Errorf("ServerName = %q, want it left as example.com", got)
	}
}

// TLS *through* the proxy, the combination the -S plus --proxy case uses.
func TestDialTLSThroughProxy(t *testing.T) {
	srv := quietTLSServer(t)
	host := strings.TrimPrefix(srv.URL, "https://")
	px := startSOCKS(t, nil, nil)

	d, err := New("socks5://" + px.addr())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	conn, err := DialTLS(context.Background(), d, "tcp", host, &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatalf("DialTLS through proxy: %v", err)
	}
	defer conn.Close()
	if !conn.(*tls.Conn).ConnectionState().HandshakeComplete {
		t.Error("handshake through the proxy did not complete")
	}
	if atyp, _ := px.lastRequest(); atyp == 0 {
		t.Error("the proxy saw no request, the TLS dial bypassed it")
	}
}

// A failed handshake must not leak the underlying socket. Asserted from the
// server's side, it reads EOF only because the client actually closed, since
// "DialTLS returned an error" is true whether or not the socket was cleaned up.
func TestDialTLSClosesOnHandshakeFailure(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Junk rather than silence, so the handshake fails on the spot instead of
		// waiting out dialTimeout: what is under test here is the cleanup, not the
		// deadline (TestDialTLSBoundsTheHandshake covers that).
		_, _ = c.Write([]byte("this is not a TLS record\n"))
		accepted <- c
	}()

	if _, err := DialTLS(context.Background(), nil, "tcp", ln.Addr().String(), &tls.Config{
		ServerName: "nowhere.invalid",
	}); err == nil {
		t.Fatal("TLS handshake against a server that speaks no TLS succeeded")
	}

	select {
	case c := <-accepted:
		defer c.Close()
		// Drain rather than read one byte: the client's ClientHello is still
		// buffered, and reading that back proves nothing. io.Copy ends with a nil
		// error at EOF, and with a timeout if the socket is still open, which is
		// what a leak looks like.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.Copy(io.Discard, c); err != nil {
			t.Errorf("server never saw EOF after a failed handshake (%v), the client leaked the socket", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never accepted the connection")
	}
}

// A peer that completes the TCP connection and then says nothing must not hang
// the handshake. This is the case DialContext's own bound cannot cover, it
// releases its deadline when it returns, and the caller's context here has no
// deadline at all, which is exactly what a command context looks like.
func TestDialTLSBoundsTheHandshake(t *testing.T) {
	restore := dialTimeout
	dialTimeout = 300 * time.Millisecond
	t.Cleanup(func() { dialTimeout = restore })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and stall: never write a ServerHello, never close.
			t.Cleanup(func() { c.Close() })
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := DialTLS(context.Background(), nil, "tcp", ln.Addr().String(),
			&tls.Config{ServerName: "stalled.invalid"})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("handshake against a stalled peer succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DialTLS hung on a stalled peer, the handshake is not bounded")
	}
}

// ---- test helpers ---------------------------------------------------------

const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

type creds struct{ user, pass string }

// socksServer is a minimal SOCKS5 server: enough of RFC 1928/1929 to prove what
// the client sends. routes maps a requested "host:port" to a real address, which
// is how a name that resolves nowhere can still be reached, exactly the job a
// pivot proxy does.
type socksServer struct {
	ln     net.Listener
	routes map[string]string
	auth   *creds

	mu       sync.Mutex
	seenATYP byte
	seenAddr string
}

func startSOCKS(t *testing.T, routes map[string]string, auth *creds) *socksServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &socksServer{ln: ln, routes: routes, auth: auth}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *socksServer) addr() string { return s.ln.Addr().String() }

func (s *socksServer) lastRequest() (byte, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seenATYP, s.seenAddr
}

func (s *socksServer) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	// Greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if s.auth != nil {
		if !bytesContain(methods, 2) {
			c.Write([]byte{5, 0xff})
			return
		}
		if _, err := c.Write([]byte{5, 2}); err != nil {
			return
		}
		if !s.readUserPass(c) {
			return
		}
	} else if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	host, err := s.readAddr(c, req[3])
	if err != nil {
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(c, port); err != nil {
		return
	}
	target := net.JoinHostPort(host, itoa(int(port[0])<<8|int(port[1])))

	s.mu.Lock()
	s.seenATYP, s.seenAddr = req[3], host
	s.mu.Unlock()

	dest := target
	if routed, ok := s.routes[target]; ok {
		dest = routed
	}
	up, err := net.DialTimeout("tcp", dest, 5*time.Second)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	go io.Copy(up, c)
	io.Copy(c, up)
}

func (s *socksServer) readUserPass(c net.Conn) bool {
	head := make([]byte, 2) // VER ULEN
	if _, err := io.ReadFull(c, head); err != nil {
		return false
	}
	user := make([]byte, head[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return false
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return false
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return false
	}
	if string(user) != s.auth.user || string(pass) != s.auth.pass {
		c.Write([]byte{1, 1}) // failure
		return false
	}
	_, err := c.Write([]byte{1, 0})
	return err == nil
}

func (s *socksServer) readAddr(c net.Conn, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4, atypIPv6:
		n := 4
		if atyp == atypIPv6 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", errors.New("bad ATYP")
}

// quietTLSServer is an httptest TLS server whose error log is discarded: these
// tests close the connection without a TLS close_notify, and the resulting
// "use of closed network connection" lines are noise that would bury a real
// failure.
func quietTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// echoServer returns the address of a listener that echoes one line back.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func roundTrip(t *testing.T, conn net.Conn, msg string) string {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(buf)
}

func bytesContain(b []byte, want byte) bool {
	for _, x := range b {
		if x == want {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
