//go:build !linux && !darwin

package sandbox

import "fmt"

// stubBackend is a placeholder on platforms without an isolation backend.
type stubBackend struct{}

func platformBackend() Backend {
	return stubBackend{}
}

func (stubBackend) Name() string { return "stub" }

func (stubBackend) Exec(args []string) (Instance, error) {
	return nil, fmt.Errorf("sandbox backend not implemented on this platform (see DESIGN.md \"macOS ネイティブ対応\")")
}
