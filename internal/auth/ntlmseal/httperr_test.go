package ntlmseal

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/sresarehumantoo/wsmancer/internal/proxydial"
)

func fakeServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(c)
		}
	}()
	return ln.Addr().String()
}

func respondHTTP(c net.Conn, status int, body string) {
	buf := make([]byte, 4096)
	c.Read(buf)
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
	c.Write([]byte(resp))
	c.Close()
}

func TestDialAndHandshakeHTTPErrors(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantSubstr string
	}{
		{
			name:       "404 from server",
			status:     404,
			body:       "<html>Not Found</html>",
			wantSubstr: "server returned HTTP 404",
		},
		{
			name:       "403 forbidden",
			status:     403,
			body:       "Forbidden",
			wantSubstr: "server returned HTTP 403",
		},
		{
			name:       "500 internal server error",
			status:     500,
			body:       "Internal Server Error",
			wantSubstr: "server returned HTTP 500",
		},
		{
			name:       "401 without negotiate header",
			status:     401,
			body:       "",
			wantSubstr: "no Negotiate challenge",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := fakeServer(t, func(c net.Conn) {
				respondHTTP(c, tc.status, tc.body)
			})

			dialer, _ := proxydial.New("")
			p, err := New(Config{
				User:     "user",
				Password: "pass",
				Dialer:   dialer,
			})
			if err != nil {
				t.Fatal(err)
			}
			rt := &connRoundTripper{p: p}
			req, _ := http.NewRequest("POST", "http://"+addr+"/wsman", nil)

			err = rt.dialAndHandshake(req)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error = %q, want substring %q", err, tc.wantSubstr)
			}
		})
	}
}
