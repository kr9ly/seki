//go:build darwin

// darwin command entrypoints. The darwin backend has no namespace re-exec
// model, so the Linux __ns-*/__child entrypoints must never be invoked here;
// port-forwarding commands are no-ops because the sandbox shares the host
// network — a dev server bound inside the sandbox is already reachable at
// localhost on the host.

package main

import (
	"fmt"
	"os"
)

func darwinNoNamespace(cmd string) {
	fmt.Fprintf(os.Stderr, "seki %s: internal Linux entrypoint, not used by the darwin backend\n", cmd)
	os.Exit(1)
}

func cmdNsSetup()   { darwinNoNamespace("__ns-setup") }
func cmdNsExec()    { darwinNoNamespace("__ns-exec") }
func cmdChild()     { darwinNoNamespace("__child") }
func cmdNewUIDMap() { darwinNoNamespace("newuidmap") }
func cmdNewGIDMap() { darwinNoNamespace("newgidmap") }

func cmdForward() {
	port := ""
	if len(os.Args) > 2 {
		port = os.Args[2]
	}
	fmt.Fprintf(os.Stderr, "seki forward: not needed on macOS — the sandbox shares the host network.\n")
	if port != "" {
		fmt.Fprintf(os.Stderr, "  your server is already reachable at localhost:%s\n", port)
	}
}

func cmdHostPort() {
	fmt.Fprintln(os.Stderr, "seki host-port: not needed on macOS — host localhost ports are directly reachable from the sandbox.")
}
