package proxy

import (
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/kr9ly/seki/internal/sni"
)

// ConnEntry represents a logged TCP connection.
type ConnEntry struct {
	Time time.Time
	Dest string
	SNI  string
}

// ConnResult is the action to take for a connection.
type ConnResult int

const (
	ConnAllow  ConnResult = iota // proceed with connection
	ConnDeny                     // drop immediately
	ConnPrompt                   // block, wait for approval queue
)

// OnConnectFunc is called for each proxied TCP connection.
// Returns the action to take.
type OnConnectFunc func(ConnEntry) ConnResult

// Proxy intercepts redirected TCP connections inside the network namespace.
// It uses SO_ORIGINAL_DST to recover the real destination and SO_MARK
// to bypass iptables REDIRECT on its own outgoing connections.
type Proxy struct {
	listenAddr string
	onConnect  OnConnectFunc
	ln         net.Listener
}

// NewProxy creates a TCP proxy.
// listenAddr: address to listen on (e.g., "127.0.0.1:10200")
func NewProxy(listenAddr string, onConnect OnConnectFunc) *Proxy {
	return &Proxy{
		listenAddr: listenAddr,
		onConnect:  onConnect,
	}
}

// Start begins accepting connections. Non-blocking.
// Blocks until the listener is ready.
func (p *Proxy) Start() error {
	ln, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", p.listenAddr, err)
	}
	p.ln = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(conn.(*net.TCPConn))
		}
	}()

	return nil
}

// Close stops the proxy.
func (p *Proxy) Close() error {
	if p.ln != nil {
		return p.ln.Close()
	}
	return nil
}

// markDialer creates outgoing connections with SO_MARK=1
// to bypass iptables REDIRECT rules.
var markDialer = &net.Dialer{
	Timeout: 10 * time.Second,
	Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x24, 1) // SO_MARK = 36
		})
	},
}

func (p *Proxy) handle(client *net.TCPConn) {
	defer client.Close()

	// Recover the original destination from iptables REDIRECT
	origDst, err := getOriginalDst(client)
	if err != nil {
		return
	}
	dest := origDst.String()

	entry := ConnEntry{Time: time.Now(), Dest: dest}

	// Peek first bytes for SNI extraction (before rule evaluation,
	// so we can show domain name in approval queue)
	buf := make([]byte, 4096)
	client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, _ := client.Read(buf)
	client.SetReadDeadline(time.Time{})

	if n > 0 {
		if domain := sni.Extract(buf[:n]); domain != "" {
			entry.SNI = domain
		}
	}

	// Evaluate rules — may block on approval queue for prompt
	if p.onConnect != nil {
		switch p.onConnect(entry) {
		case ConnDeny:
			return
		case ConnAllow:
			// proceed
		}
		// ConnPrompt is handled inside onConnect (blocks until resolved)
		// If it returns ConnDeny after prompt, we already returned above
	}

	// Connect to the real destination with SO_MARK to bypass iptables
	remote, err := markDialer.Dial("tcp", dest)
	if err != nil {
		return
	}
	defer remote.Close()

	// Forward first chunk and relay
	if n > 0 {
		remote.Write(buf[:n])
	}

	// Bidirectional relay
	done := make(chan struct{})
	go func() {
		io.Copy(remote, client)
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	io.Copy(client, remote)
	<-done
}
