//go:build linux

package socket

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkTrust verifies whether a connection comes from a process in the host
// user namespace (trusted) or a sandboxed user namespace (untrusted).
// Uses SO_PEERCRED to get the peer PID, then compares /proc/<pid>/ns/user.
func (s *Server) checkTrust(conn net.Conn) bool {
	s.mu.Lock()
	hostNS := s.hostUserNS
	s.mu.Unlock()
	if hostNS == "" {
		return true // trust check not configured
	}

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil || credErr != nil || cred == nil {
		return false
	}
	peerNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/user", cred.Pid))
	if err != nil {
		return false
	}
	return peerNS == hostNS
}
