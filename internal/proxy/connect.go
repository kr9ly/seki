// Explicit HTTP proxy (CONNECT tunneling + absolute-URI plain HTTP) used by
// the darwin backend. Platform-neutral: interception happens because the
// Seatbelt profile leaves the proxy as the only route out and HTTP(S)_PROXY
// points cooperative clients here — not via packet redirection.
//
// Rule evaluation is hostname-based: CONNECT carries the destination name in
// the request line, so no DNS checkpoint is needed (the proxy resolves names
// itself, outside the sandbox). The TLS ClientHello is still peeked after the
// tunnel is established: an SNI that differs from the CONNECT host (domain
// fronting) triggers a second rule evaluation.
package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kr9ly/seki/internal/sni"
)

// ConnectProxy is an explicit HTTP proxy applying seki's network rules.
type ConnectProxy struct {
	onConnect OnConnectFunc
	dialer    *net.Dialer
	ln        net.Listener
}

// NewConnectProxy creates an explicit proxy. onConnect is called with the
// CONNECT/request hostname (and SNI when it diverges); ConnPrompt must be
// resolved inside the callback, same contract as the transparent proxy.
func NewConnectProxy(onConnect OnConnectFunc) *ConnectProxy {
	return &ConnectProxy{
		onConnect: onConnect,
		dialer:    &net.Dialer{Timeout: 10 * time.Second},
	}
}

// Start listens on listenAddr ("127.0.0.1:0" picks a free port) and begins
// accepting connections. Non-blocking; the listener is ready on return.
func (p *ConnectProxy) Start(listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	p.ln = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(conn)
		}
	}()
	return nil
}

// Addr returns the bound listen address (host:port).
func (p *ConnectProxy) Addr() string {
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// Close stops the proxy.
func (p *ConnectProxy) Close() error {
	if p.ln != nil {
		return p.ln.Close()
	}
	return nil
}

func (p *ConnectProxy) decide(e ConnEntry) ConnResult {
	if p.onConnect == nil {
		return ConnAllow
	}
	return p.onConnect(e)
}

func (p *ConnectProxy) handle(client net.Conn) {
	defer client.Close()

	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(client, br, req)
		return
	}
	p.handleHTTP(client, br, req)
}

// handleConnect tunnels a CONNECT request after rule evaluation.
func (p *ConnectProxy) handleConnect(client net.Conn, br *bufio.Reader, req *http.Request) {
	host, port := splitHostPortDefault(req.Host, "443")
	if host == "" {
		httpError(client, "400 Bad Request", "seki: malformed CONNECT target\n")
		return
	}
	dest := net.JoinHostPort(host, port)

	entry := ConnEntry{Time: time.Now(), Dest: dest}
	if p.decide(entry) == ConnDeny {
		// Denied before the tunnel exists, so the client gets a visible
		// HTTP error instead of a silent reset.
		httpError(client, "403 Forbidden", "seki: blocked by network rules: "+dest+"\n")
		return
	}

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// Peek the first client bytes for the TLS ClientHello. The client only
	// starts TLS after our 200, so this happens post-tunnel (unlike the
	// transparent proxy, which peeks before rule evaluation).
	buf := make([]byte, 4096)
	n := peekClient(client, br, buf)
	if n > 0 {
		if domain := sni.Extract(buf[:n]); domain != "" {
			entry.SNI = domain
			if !strings.EqualFold(domain, host) {
				// Domain fronting: CONNECT said one name, TLS says another.
				// Re-evaluate with the SNI; the callback logs both.
				if p.decide(entry) == ConnDeny {
					return
				}
			}
		}
	}

	remote, err := p.dialer.Dial("tcp", dest)
	if err != nil {
		return
	}
	defer remote.Close()

	if n > 0 {
		if _, err := remote.Write(buf[:n]); err != nil {
			return
		}
	}
	relay(client, br, remote)
}

// handleHTTP proxies a plain HTTP request (absolute-URI form).
func (p *ConnectProxy) handleHTTP(client net.Conn, br *bufio.Reader, req *http.Request) {
	if !req.URL.IsAbs() {
		httpError(client, "400 Bad Request", "seki: proxy requests must use an absolute URI\n")
		return
	}
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "80"
	}
	dest := net.JoinHostPort(host, port)

	entry := ConnEntry{Time: time.Now(), Dest: dest}
	if p.decide(entry) == ConnDeny {
		httpError(client, "403 Forbidden", "seki: blocked by network rules: "+dest+"\n")
		return
	}

	remote, err := p.dialer.Dial("tcp", dest)
	if err != nil {
		httpError(client, "502 Bad Gateway", "seki: connect "+dest+": "+err.Error()+"\n")
		return
	}
	defer remote.Close()

	// One request per connection: a reused proxy connection could switch
	// Host on the next request and slip past the rule evaluation above.
	req.Header.Del("Proxy-Connection")
	req.Header.Set("Connection", "close")
	req.Close = true
	if err := req.Write(remote); err != nil {
		return
	}
	io.Copy(client, remote)
}

// peekClient reads whatever the client sends within a short deadline.
// Bytes already buffered by the request parser are returned immediately.
func peekClient(client net.Conn, br *bufio.Reader, buf []byte) int {
	if br.Buffered() == 0 {
		client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		defer client.SetReadDeadline(time.Time{})
	}
	n, _ := br.Read(buf)
	return n
}

// relay copies bytes bidirectionally until both directions close.
// br may hold bytes already read from client.
func relay(client net.Conn, br *bufio.Reader, remote net.Conn) {
	done := make(chan struct{})
	go func() {
		io.Copy(remote, br)
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	io.Copy(client, remote)
	<-done
}

// splitHostPortDefault splits "host:port", falling back to defaultPort.
func splitHostPortDefault(hostport, defaultPort string) (string, string) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, defaultPort
	}
	return host, port
}

func httpError(w io.Writer, status, msg string) {
	fmt.Fprintf(w, "HTTP/1.1 %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, len(msg), msg)
}
