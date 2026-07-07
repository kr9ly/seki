//go:build darwin

package socket

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkTrust verifies the connecting peer via LOCAL_PEERCRED (euid match).
// On darwin the primary defense is the Seatbelt profile denying sandboxed
// processes access to the control socket path entirely (see DESIGN.md
// "ソケット信頼検証（darwin）"); this check is defense in depth.
// The hostUserNS field is a Linux concept and is ignored here.
func (s *Server) checkTrust(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Xucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if err != nil || credErr != nil || cred == nil {
		return false
	}
	return int(cred.Uid) == os.Geteuid()
}
