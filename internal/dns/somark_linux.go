//go:build linux

package dns

import "syscall"

// setSOMarkControl sets SO_MARK=1 on a socket to bypass iptables REDIRECT rules.
func setSOMarkControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x24, 1) // SO_MARK = 0x24 (36)
	})
}
