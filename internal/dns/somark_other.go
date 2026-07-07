//go:build !linux

package dns

import "syscall"

// setSOMarkControl is a no-op outside Linux: SO_MARK is a Linux-only
// mechanism for bypassing iptables REDIRECT, which does not exist here.
func setSOMarkControl(network, address string, c syscall.RawConn) error {
	return nil
}
