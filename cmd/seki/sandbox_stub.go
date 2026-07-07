//go:build !linux

// Stubs for platform-specific commands on platforms without a sandbox
// backend implementation. The darwin backend (Seatbelt + explicit proxy)
// is designed but not implemented — see DESIGN.md.

package main

import (
	"fmt"
	"os"
)

func platformUnsupported(cmd string) {
	fmt.Fprintf(os.Stderr, "seki %s: not supported on this platform (darwin backend not implemented — see DESIGN.md)\n", cmd)
	os.Exit(1)
}

func cmdNsSetup()   { platformUnsupported("__ns-setup") }
func cmdNsExec()    { platformUnsupported("__ns-exec") }
func cmdChild()     { platformUnsupported("__child") }
func cmdNewUIDMap() { platformUnsupported("newuidmap") }
func cmdNewGIDMap() { platformUnsupported("newgidmap") }
func cmdForward()   { platformUnsupported("forward") }
func cmdHostPort()  { platformUnsupported("host-port") }
