package krbseal

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
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

func TestSendHTTPErrors(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantSubstr string
	}{
		{
			name:       "404 not found",
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
			name:       "301 redirect",
			status:     301,
			body:       "",
			wantSubstr: "server returned HTTP 301",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := fakeServer(t, func(c net.Conn) {
				respondHTTP(c, tc.status, tc.body)
			})

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })

			p := &Provider{cfg: Config{
				UserAgent:   "test",
				SealEnabled: false,
			}}
			rt := &connRoundTripper{
				p:    p,
				conn: conn,
				br:   bufio.NewReader(conn),
			}
			req, _ := http.NewRequest("POST", "http://"+addr+"/wsman", nil)

			_, err = rt.send(req, []byte("<s:Envelope/>"))
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error = %q, want substring %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestSendPassesThroughSealedErrors(t *testing.T) {
	ct := "multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-encrypted\";boundary=\"Encrypted Boundary\""
	cases := []struct {
		name   string
		status int
	}{
		{"sealed 500 (SOAP fault)", 500},
		{"sealed 200 (normal)", 200},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := fakeServer(t, func(c net.Conn) {
				buf := make([]byte, 4096)
				c.Read(buf)
				body := "sealed-body"
				resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
					tc.status, http.StatusText(tc.status), ct, len(body), body)
				c.Write([]byte(resp))
				c.Close()
			})

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })

			p := &Provider{cfg: Config{
				UserAgent:   "test",
				SealEnabled: false,
			}}
			rt := &connRoundTripper{
				p:    p,
				conn: conn,
				br:   bufio.NewReader(conn),
			}
			req, _ := http.NewRequest("POST", "http://"+addr+"/wsman", nil)

			resp, err := rt.send(req, []byte("<s:Envelope/>"))
			if err != nil {
				t.Fatalf("sealed response should not be rejected early, got: %v", err)
			}
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}
