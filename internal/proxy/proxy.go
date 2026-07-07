// Package proxy implements the TCP checkpoint of the seki sandbox.
// The connection-entry types and rule-evaluation callback here are
// platform-neutral; the interception mechanism is per-OS (Linux:
// transparent iptables REDIRECT proxy in transparent_linux.go).
package proxy

import (
	"time"
)

// ConnEntry represents a logged TCP connection.
type ConnEntry struct {
	Time time.Time
	Dest string
	SNI  string
}

// ConnResult is the action to take for a connection.
type ConnResult int

const (
	ConnAllow  ConnResult = iota // proceed with connection
	ConnDeny                     // drop immediately
	ConnPrompt                   // block, wait for approval queue
)

// OnConnectFunc is called for each proxied TCP connection.
// Returns the action to take.
type OnConnectFunc func(ConnEntry) ConnResult
