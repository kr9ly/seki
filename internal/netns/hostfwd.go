package netns

import (
	"fmt"
	"io"
	"net"

	"github.com/kr9ly/seki/internal/proxy"
)

// hostForwarder listens on sandbox localhost and forwards to the host
// via the slirp4netns gateway. This makes host services (e.g. MCP servers)
// transparently accessible from inside the sandbox.
type hostForwarder struct {
	ln net.Listener
}

func startHostForwarder(port int) (*hostForwarder, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	target := fmt.Sprintf("%s:%d", SlirpGateway, port)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go forwardConn(conn, target)
		}
	}()

	return &hostForwarder{ln: ln}, nil
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
	return f.ln.Close()
}
