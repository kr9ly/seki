package proxy

import (
	"fmt"
	"io"
	"net"
)

// RedirectProxy runs inside the child namespace.
// It accepts redirected TCP connections, resolves the original destination
// via SO_ORIGINAL_DST, and forwards to the host-side proxy with a destination header.
type RedirectProxy struct {
	listenAddr string
	sekiAddr   string
	ln         net.Listener
}

// NewRedirectProxy creates a redirect proxy that forwards to the host-side proxy.
// listenAddr: address to listen on in the child namespace (e.g., "127.0.0.1:10200")
// sekiAddr: host-side proxy address reachable via veth (e.g., "10.200.1.1:10201")
func NewRedirectProxy(listenAddr, sekiAddr string) *RedirectProxy {
	return &RedirectProxy{
		listenAddr: listenAddr,
		sekiAddr:   sekiAddr,
	}
}

// Start begins accepting connections. Non-blocking.
func (rp *RedirectProxy) Start() error {
	ln, err := net.Listen("tcp", rp.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", rp.listenAddr, err)
	}
	rp.ln = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go rp.handle(conn.(*net.TCPConn))
		}
	}()

	return nil
}

// Close stops the redirect proxy.
func (rp *RedirectProxy) Close() error {
	if rp.ln != nil {
		return rp.ln.Close()
	}
	return nil
}

func (rp *RedirectProxy) handle(client *net.TCPConn) {
	defer client.Close()

	origDst, err := getOriginalDst(client)
	if err != nil {
		return
	}

	seki, err := net.Dial("tcp", rp.sekiAddr)
	if err != nil {
		return
	}
	defer seki.Close()

	// Send original destination as header line
	fmt.Fprintf(seki, "%s\n", origDst.String())

	// Bidirectional relay
	done := make(chan struct{})
	go func() {
		io.Copy(seki, client)
		if tc, ok := seki.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	io.Copy(client, seki)
	<-done
}
