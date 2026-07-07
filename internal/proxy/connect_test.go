package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// startEcho starts a TCP echo server and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func startProxy(t *testing.T, onConnect OnConnectFunc) string {
	t.Helper()
	p := NewConnectProxy(onConnect)
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p.Addr()
}

// doConnect issues a CONNECT and returns the connection and the status line.
func doConnect(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	// Drain response headers up to the blank line
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, br, strings.TrimSpace(status)
}

func TestConnectTunnelAllow(t *testing.T) {
	echo := startEcho(t)
	proxyAddr := startProxy(t, func(e ConnEntry) ConnResult { return ConnAllow })

	conn, br, status := doConnect(t, proxyAddr, echo)
	if !strings.Contains(status, "200") {
		t.Fatalf("expected 200, got %q", status)
	}

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("expected echo %q, got %q", "hello", buf)
	}
}

func TestConnectTunnelDeny(t *testing.T) {
	echo := startEcho(t)
	var got ConnEntry
	proxyAddr := startProxy(t, func(e ConnEntry) ConnResult {
		got = e
		return ConnDeny
	})

	_, _, status := doConnect(t, proxyAddr, echo)
	if !strings.Contains(status, "403") {
		t.Fatalf("expected 403, got %q", status)
	}
	if got.Dest != echo {
		t.Fatalf("expected rule evaluation for %q, got %q", echo, got.Dest)
	}
}

// clientHello captures the TLS ClientHello bytes for a given server name.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		tc := tls.Client(c1, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		tc.Handshake() // blocks after the first flight; unblocked by pipe close
	}()
	buf := make([]byte, 8192)
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c2.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("capture ClientHello: n=%d err=%v", n, err)
	}
	return buf[:n]
}

func TestConnectDomainFronting(t *testing.T) {
	echo := startEcho(t)

	var mu sync.Mutex
	var calls []ConnEntry
	proxyAddr := startProxy(t, func(e ConnEntry) ConnResult {
		mu.Lock()
		calls = append(calls, e)
		mu.Unlock()
		if e.SNI == "evil.example" {
			return ConnDeny
		}
		return ConnAllow
	})

	conn, br, status := doConnect(t, proxyAddr, echo)
	if !strings.Contains(status, "200") {
		t.Fatalf("expected 200, got %q", status)
	}

	// CONNECT host was allowed; now the ClientHello names a different domain.
	hello := clientHello(t, "evil.example")
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}

	// The proxy must drop the connection without relaying to the target.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := br.Read(buf); err != io.EOF {
		t.Fatalf("expected EOF (connection dropped), got err=%v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("expected 2 rule evaluations (CONNECT + SNI), got %d", len(calls))
	}
	if calls[1].SNI != "evil.example" {
		t.Fatalf("expected second evaluation with SNI, got %+v", calls[1])
	}
}

func TestConnectSNIMatchNoReevaluation(t *testing.T) {
	// SNI matching the CONNECT host must not trigger a second evaluation.
	echo := startEcho(t)

	var mu sync.Mutex
	var calls int
	proxyAddr := startProxy(t, func(e ConnEntry) ConnResult {
		mu.Lock()
		calls++
		mu.Unlock()
		return ConnAllow
	})

	// CONNECT with a hostname, then send a ClientHello for the same name.
	_, port, _ := net.SplitHostPort(echo)
	conn, br, status := doConnect(t, proxyAddr, "localhost:"+port)
	if !strings.Contains(status, "200") {
		t.Fatalf("expected 200, got %q", status)
	}
	hello := clientHello(t, "localhost")
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	// Echo server reflects the ClientHello bytes back through the tunnel.
	buf := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read relayed bytes: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected 1 rule evaluation, got %d", calls)
	}
}

func TestHTTPAbsoluteURI(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer backend.Close()

	allow := true
	proxyAddr := startProxy(t, func(e ConnEntry) ConnResult {
		if allow {
			return ConnAllow
		}
		return ConnDeny
	})

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("expected 200 ok, got %d %q", resp.StatusCode, body)
	}

	allow = false
	resp, err = client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestHTTPRelativeURIRejected(t *testing.T) {
	proxyAddr := startProxy(t, func(e ConnEntry) ConnResult { return ConnAllow })
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "400") {
		t.Fatalf("expected 400, got %q", status)
	}
}
