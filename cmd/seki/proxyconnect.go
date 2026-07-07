// seki proxy-connect: stdio ↔ CONNECT-proxy relay for ssh ProxyCommand.
//
// The darwin backend sets
//   GIT_SSH_COMMAND=ssh -o ProxyCommand="seki proxy-connect %h %p"
// so git-over-ssh traffic reaches the seki proxy and lands on hostname-based
// rule evaluation (ssh itself ignores HTTP(S)_PROXY). Platform-neutral: works
// wherever SEKI_PROXY_ADDR points at a seki CONNECT proxy.

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

func cmdProxyConnect() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: seki proxy-connect <host> <port>")
		os.Exit(1)
	}
	host, port := os.Args[2], os.Args[3]

	addr := os.Getenv("SEKI_PROXY_ADDR")
	if addr == "" {
		fmt.Fprintln(os.Stderr, "seki proxy-connect: SEKI_PROXY_ADDR not set (not inside a seki sandbox with an explicit proxy)")
		os.Exit(1)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki proxy-connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	target := net.JoinHostPort(host, port)
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki proxy-connect: read response: %v\n", err)
		os.Exit(1)
	}
	if !strings.Contains(status, " 200 ") {
		fmt.Fprintf(os.Stderr, "seki proxy-connect: %s: %s\n", target, strings.TrimSpace(status))
		os.Exit(1)
	}
	// Drain headers up to the blank line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki proxy-connect: read response: %v\n", err)
			os.Exit(1)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	done := make(chan struct{})
	go func() {
		io.Copy(conn, os.Stdin)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	io.Copy(os.Stdout, br)
	<-done
}
