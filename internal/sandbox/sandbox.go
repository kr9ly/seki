// Package sandbox defines the platform-neutral seam between the seki CLI
// and the OS-specific isolation backend. The Linux backend builds on user/net
// namespaces with a transparent proxy (internal/netns); the darwin backend
// (Seatbelt + explicit proxy, see DESIGN.md) plugs in behind the same
// interface.
package sandbox

// Instance is a running sandbox hosting the user command.
type Instance interface {
	// Wait blocks until the user command exits. Returns *exec.ExitError
	// (or equivalent) when the command exits non-zero.
	Wait() error
	// Close releases sandbox resources (proxies, forwarders, sockets).
	Close()
}

// Backend creates sandboxes on a specific platform.
type Backend interface {
	// Name identifies the backend (e.g. "linux-netns", "darwin-seatbelt").
	Name() string
	// Exec starts the user command inside a new sandbox.
	Exec(args []string) (Instance, error)
}

// Default returns the backend for the current platform.
func Default() Backend {
	return platformBackend()
}
