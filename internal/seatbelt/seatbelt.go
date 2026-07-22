// Package seatbelt generates the SBPL sandbox profile used by the darwin
// backend. Generation is platform-neutral so it can be unit-tested anywhere;
// applying the profile (/usr/bin/sandbox-exec) is darwin-only.
//
// The profile encodes the darwin design from DESIGN.md: everything is
// allowed except networking, which is denied wholesale and carved back to
// loopback only. The seki CONNECT proxy on localhost is then the single
// route out. Several rules below encode assumptions that the macOS spike
// (DESIGN.md「スパイク計画」) must confirm on a real machine; each is marked
// with "SPIKE:" in the profile comments.
package seatbelt

import (
	"fmt"
	"strings"
)

// Params configures profile generation.
type Params struct {
	// ProxyPort is the localhost TCP port of the seki CONNECT proxy.
	// The loopback carve-out already covers it; recorded in the profile
	// header for diagnostics and possible future tightening.
	ProxyPort int
	// ReadOnlyPaths are directory trees the sandbox must not write
	// (e.g. ~/.config/seki — rules and credential config).
	ReadOnlyPaths []string
	// DenySockets are unix socket paths the sandbox must not connect to
	// (the watch/control socket: connecting would allow self-approval).
	DenySockets []string
}

// quote escapes a string for an SBPL double-quoted literal.
func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// Profile renders the SBPL profile.
func Profile(p Params) string {
	var b strings.Builder

	fmt.Fprintf(&b, `(version 1)

;; seki darwin backend profile (generated — do not edit).
;; seki proxy port: %d
;;
;; Design: seki guards the network exit, not the filesystem (DESIGN.md).
;; Everything is allowed except networking; loopback is carved back so the
;; CONNECT proxy on localhost is the only route out. In SBPL, later rules
;; take precedence over earlier ones.

(allow default)

;; --- Network: deny by default ---------------------------------------------
(deny network*)

;; Loopback: sandbox-internal client/server flows (dev servers, test suites)
;; and the seki CONNECT proxy. Non-loopback stays denied — cooperative
;; processes follow HTTP(S)_PROXY through the checkpoint, everything else
;; gets EPERM.
;;
;; Carve-outs are per-operation on purpose. seki guards the network EXIT:
;; only outbound is filtered; bind and inbound are open. Rationale, from
;; three real-Mac incidents:
;; - outbound: filter by REMOTE only. A local filter reopens ALL outbound
;;   traffic — an unbound socket's wildcard local matches
;;   (local ip "localhost:*") (v0.2.0).
;; - bind: unconditional — bind moves no data; a loopback-only bind rule
;;   broke JVM tooling, which binds wildcard (v0.2.1).
;; - inbound: unconditional — listen(2) is checked as network-inbound, so
;;   any filter must match it too. A remote filter never matches listen
;;   (no peer yet, v0.2.2), and a local loopback filter fails IPv6
;;   dual-stack listeners (the v4 wildcard matches "localhost:*" but the
;;   v6 wildcard :: does not, v0.2.3). Host/LAN reachability of in-sandbox
;;   servers is outside the threat model: an inbound connection is only
;;   two-way once an OUTSIDE party initiates it — sandboxed code cannot
;;   signal out to invite one, and UDP replies are network-outbound and
;;   stay denied.
(allow network-bind)
(allow network-inbound)
(allow network-outbound (remote ip "localhost:*"))
;; IPv6 loopback needs its own carve-out: "localhost:*" under plain ip
;; matches the v4 loopback and the v4 wildcard, but neither ::1 nor the v6
;; wildcard :: — clients that connect to :: (kernel routes it to loopback)
;; get EPERM (adb-style tools hitting *:5037, v0.2.5).
;; SPIKE: confirm on a real Mac that ip6 "localhost:*" matches both ::1 and
;; the v6 wildcard ::.
(allow network-outbound (remote ip6 "localhost:*"))

;; Unix sockets: ssh-agent proxy, credential helper, build tooling.
(allow network* (local unix-socket))
(allow network* (remote unix-socket))
`, p.ProxyPort)

	b.WriteString(`
;; --- DNS -------------------------------------------------------------------
;; Hostname resolution happens only inside the seki proxy. Blocking local
;; resolution also closes DNS tunneling, and removes HTTPS/SVCB lookups (so
;; the ECH bypass disappears structurally).
;; SPIKE: verify both getaddrinfo paths are actually blocked on macOS 26
;; (unix socket AND mach lookup — DESIGN.md スパイク計画 #2).
(deny network* (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
(deny network* (remote unix-socket (path-literal "/var/run/mDNSResponder")))
(deny mach-lookup (global-name "com.apple.mDNSResponder"))
(deny mach-lookup (global-name "com.apple.dnssd.service"))
;; A local resolver/forwarder on loopback would reopen the tunnel through
;; the loopback carve-outs above; deny port 53 explicitly — on both address
;; families, since each has its own carve-out.
(deny network* (remote ip "localhost:53"))
(deny network* (remote ip6 "localhost:53"))
`)

	if len(p.DenySockets) > 0 {
		b.WriteString(`
;; --- seki control sockets ---------------------------------------------------
;; The watch/control socket must be unreachable from inside: on darwin the
;; sandbox runs as the same euid, so LOCAL_PEERCRED cannot distinguish it
;; from watch — this path deny is the primary defense (DESIGN.md
;; 「ソケット信頼検証（darwin）」).
`)
		for _, sock := range p.DenySockets {
			fmt.Fprintf(&b, "(deny network* (remote unix-socket (path-literal %s)))\n", quote(sock))
		}
	}

	if len(p.ReadOnlyPaths) > 0 {
		b.WriteString(`
;; --- Files -------------------------------------------------------------------
;; seki config (rules, credential config) is read-only inside the sandbox.
`)
		for _, path := range p.ReadOnlyPaths {
			fmt.Fprintf(&b, "(deny file-write* (subpath %s))\n", quote(path))
		}
	}

	return b.String()
}
