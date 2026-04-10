package sshagent

import (
	"io"
	"net"
	"os"
)

// Proxy is a transparent Unix-socket proxy between the sandbox's SSH_AUTH_SOCK
// and the host's ssh-agent socket. It forwards raw bytes without parsing the
// SSH agent protocol — the sandbox sees an ssh-agent socket, but all signing
// operations are handled by the host agent.
type Proxy struct {
	ln       net.Listener
	path     string // proxy socket path (sandbox side)
	upstream string // host's SSH_AUTH_SOCK path
}

// NewProxy creates a Unix socket at proxyPath and starts accepting connections.
// upstream is the host ssh-agent socket (value of SSH_AUTH_SOCK on the host).
func NewProxy(proxyPath, upstream string) (*Proxy, error) {
	// Remove stale socket from a previous run
	os.Remove(proxyPath)

	ln, err := net.Listen("unix", proxyPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(proxyPath, 0600); err != nil {
		ln.Close()
		os.Remove(proxyPath)
		return nil, err
	}

	p := &Proxy{
		ln:       ln,
		path:     proxyPath,
		upstream: upstream,
	}
	go p.accept()
	return p, nil
}

// Close shuts down the proxy listener and removes the socket file.
func (p *Proxy) Close() error {
	err := p.ln.Close()
	os.Remove(p.path)
	return err
}

// accept runs the connection accept loop in a goroutine.
func (p *Proxy) accept() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

// handle forwards bytes between the sandbox-side connection and the host's
// ssh-agent socket. Two goroutines copy in each direction; whichever finishes
// first closes both connections so the other goroutine unblocks.
func (p *Proxy) handle(conn net.Conn) {
	defer conn.Close()

	up, err := net.Dial("unix", p.upstream)
	if err != nil {
		return
	}
	defer up.Close()

	done := make(chan struct{}, 2)

	// sandbox → host
	go func() {
		io.Copy(up, conn)
		done <- struct{}{}
	}()

	// host → sandbox
	go func() {
		io.Copy(conn, up)
		done <- struct{}{}
	}()

	// Wait for either direction to finish, then close both sides.
	<-done
	conn.Close()
	up.Close()
	<-done // drain so goroutines exit cleanly
}
