// Package bridge implements a small host-side TCP forwarder tied to a
// sandbox's lifetime. The darwin backend uses it to paper over loopback
// address-family asymmetries: the sandbox shares the host network stack, so
// a listener on one loopback family can hand connections to a server that
// only binds the other (e.g. adb clients probing [::1]:5037 while the adb
// server listens on 127.0.0.1 only).
package bridge

import (
	"io"
	"net"
	"time"
)

// Bridge forwards every connection accepted on its listener to a fixed
// upstream address. Close stops accepting; in-flight connections drain on
// their own.
type Bridge struct {
	Name    string
	ln      net.Listener
	connect string
}

// Start binds listen and begins forwarding to connect. Callers should treat
// an address-in-use error as "already bridged" rather than fatal: bridges
// share the host network stack, so a concurrent sandbox (or a real server)
// may legitimately hold the address.
func Start(name, listen, connect string) (*Bridge, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	b := &Bridge{Name: name, ln: ln, connect: connect}
	go b.acceptLoop()
	return b, nil
}

// Addr returns the bound listen address.
func (b *Bridge) Addr() net.Addr { return b.ln.Addr() }

// Close stops the listener. Established connections are left to finish.
func (b *Bridge) Close() { b.ln.Close() }

func (b *Bridge) acceptLoop() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.forward(c)
	}
}

func (b *Bridge) forward(down net.Conn) {
	defer down.Close()
	up, err := net.DialTimeout("tcp", b.connect, 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()

	// Propagate half-closes: protocols like adb's rely on the server's FIN
	// reaching the client while the reverse direction stays open.
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, down)
	go pipe(down, up)
	<-done
	<-done
}
