package proxy

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// getOriginalDst retrieves the original destination address of a redirected TCP connection
// using SO_ORIGINAL_DST. Only works in the same network namespace as the iptables REDIRECT rule.
func getOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("syscall conn: %w", err)
	}

	var addr unix.RawSockaddrInet4
	var getSockoptErr error

	err = raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(addr))
		// SO_ORIGINAL_DST = 80
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			unix.SOL_IP,
			80,
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			getSockoptErr = errno
		}
	})
	if err != nil {
		return nil, err
	}
	if getSockoptErr != nil {
		return nil, fmt.Errorf("SO_ORIGINAL_DST: %w", getSockoptErr)
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	// Port is in network byte order (big-endian)
	port := int(addr.Port>>8) | int(addr.Port&0xff)<<8
	return &net.TCPAddr{IP: ip, Port: port}, nil
}
