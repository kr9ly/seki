package netns

import (
	"fmt"
	"io"
	"net"

	"github.com/kr9ly/seki/internal/proxy"
)

// hostForwarder listens on sandbox localhost (IPv4 + IPv6) and forwards
// to the host via the slirp4netns gateway. This makes host services
// (e.g. MCP servers) transparently accessible from inside the sandbox.
type hostForwarder struct {
	listeners []net.Listener
}

func startHostForwarder(port int) (*hostForwarder, error) {
	target := fmt.Sprintf("%s:%d", SlirpGateway, port)

	addrs := []string{
		fmt.Sprintf("127.0.0.1:%d", port),
		fmt.Sprintf("[::1]:%d", port),
	}

	var listeners []net.Listener
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// IPv6 may be unavailable; require at least IPv4.
			if len(listeners) > 0 {
				break
			}
			return nil, err
		}
		listeners = append(listeners, ln)
		go acceptLoop(ln, target)
	}

	return &hostForwarder{listeners: listeners}, nil
}

func acceptLoop(ln net.Listener, target string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go forwardConn(conn, target)
	}
}

func forwardConn(client net.Conn, target string) {
	defer client.Close()

	remote, err := proxy.MarkDialer.Dial("tcp", target)
	if err != nil {
		return
	}
	defer remote.Close()

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

func (f *hostForwarder) Close() error {
	var firstErr error
	for _, ln := range f.listeners {
		if err := ln.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
