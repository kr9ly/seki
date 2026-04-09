package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/kr9ly/seki/internal/sni"
)

// ConnEntry represents a logged TCP connection.
type ConnEntry struct {
	Time time.Time
	Dest string
	SNI  string
}

// OnConnectFunc is called for each proxied TCP connection.
type OnConnectFunc func(ConnEntry)

// Proxy is the host-side TCP proxy that receives forwarded connections
// from the child-side redirect proxy and connects to the actual destination.
type Proxy struct {
	listenAddr string
	onConnect  OnConnectFunc
	ln         net.Listener
}

// NewProxy creates a host-side TCP proxy.
// listenAddr: address to listen on (e.g., "10.200.1.1:10201")
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
			go p.handle(conn)
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

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()

	reader := bufio.NewReader(client)

	// Read destination header from child-side redirect proxy
	destLine, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "[seki] proxy: failed to read dest header: %v\n", err)
		return
	}
	dest := strings.TrimSpace(destLine)

	// Connect to the original destination
	remote, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[seki] proxy: connect %s: %v\n", dest, err)
		return
	}
	defer remote.Close()

	entry := ConnEntry{Time: time.Now(), Dest: dest}

	// Read first data chunk from client for SNI extraction
	// The bufio reader may have buffered data from the header read
	firstChunk, err := p.readFirst(reader)
	if err == nil && len(firstChunk) > 0 {
		if domain := sni.Extract(firstChunk); domain != "" {
			entry.SNI = domain
		}
		// Forward the first chunk to remote
		remote.Write(firstChunk)
	}

	if p.onConnect != nil {
		p.onConnect(entry)
	}

	// Bidirectional relay for the rest
	done := make(chan struct{})
	go func() {
		io.Copy(remote, reader) // drains bufio buffer, then reads from client
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	io.Copy(client, remote)
	<-done
}

// readFirst reads the first chunk of data, waiting briefly if needed.
func (p *Proxy) readFirst(reader *bufio.Reader) ([]byte, error) {
	// Check if bufio already has data buffered
	if reader.Buffered() > 0 {
		return reader.Peek(reader.Buffered())
	}

	// Wait briefly for the first data (TLS ClientHello)
	buf := make([]byte, 4096)
	n, err := reader.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}
