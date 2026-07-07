//go:build linux

package sandbox

import (
	"github.com/kr9ly/seki/internal/netns"
)

// linuxBackend implements Backend on top of unprivileged user/net namespaces
// with a transparent (iptables REDIRECT) proxy.
type linuxBackend struct{}

func platformBackend() Backend {
	return linuxBackend{}
}

func (linuxBackend) Name() string { return "linux-netns" }

func (linuxBackend) Exec(args []string) (Instance, error) {
	sb, err := netns.Exec(args)
	if err != nil {
		return nil, err
	}
	return sb, nil
}
