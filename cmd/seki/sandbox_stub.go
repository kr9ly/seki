//go:build !linux && !darwin

// Stubs for platform-specific commands on platforms without a sandbox
// backend implementation.

package main

import (
	"fmt"
	"os"
)

func platformUnsupported(cmd string) {
	fmt.Fprintf(os.Stderr, "seki %s: not supported on this platform\n", cmd)
	os.Exit(1)
}

func cmdNsSetup()   { platformUnsupported("__ns-setup") }
func cmdNsExec()    { platformUnsupported("__ns-exec") }
func cmdChild()     { platformUnsupported("__child") }
func cmdNewUIDMap() { platformUnsupported("newuidmap") }
func cmdNewGIDMap() { platformUnsupported("newgidmap") }
func cmdForward()   { platformUnsupported("forward") }
func cmdHostPort()  { platformUnsupported("host-port") }
