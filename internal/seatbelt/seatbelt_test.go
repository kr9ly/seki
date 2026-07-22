package seatbelt

import (
	"strings"
	"testing"
)

func TestProfileStructure(t *testing.T) {
	p := Profile(Params{
		ProxyPort:     10200,
		ReadOnlyPaths: []string{"/Users/alice/.config/seki"},
		DenySockets: []string{
			"/Users/alice/.config/seki/seki-123.sock",
		},
	})

	// Ordering: SBPL gives precedence to later rules, so the deny-all must
	// come before the loopback carve-outs, and the specific denies after.
	denyAll := strings.Index(p, "(deny network*)")
	allowLoopback := strings.Index(p, `(allow network-outbound (remote ip "localhost:*"))`)
	allowLoopback6 := strings.Index(p, `(allow network-outbound (remote ip6 "localhost:*"))`)
	denyDNS := strings.Index(p, "mDNSResponder")
	denyCtl := strings.Index(p, "seki-123.sock")

	if denyAll == -1 || allowLoopback == -1 || allowLoopback6 == -1 || denyDNS == -1 || denyCtl == -1 {
		t.Fatalf("missing expected rules in profile:\n%s", p)
	}
	if !(denyAll < allowLoopback && allowLoopback < denyDNS && allowLoopback < denyCtl) {
		t.Fatalf("rule ordering violates SBPL later-wins precedence:\n%s", p)
	}
	if !(denyAll < allowLoopback6 && allowLoopback6 < denyDNS) {
		t.Fatalf("ip6 carve-out ordering violates SBPL later-wins precedence:\n%s", p)
	}

	// Only outbound is filtered, and by REMOTE only (all confirmed on a
	// real Mac):
	// - an outbound local filter reopens all outbound traffic — an unbound
	//   socket's wildcard local matches "localhost:*" (v0.2.0).
	// - any inbound filter breaks listen(2), which is checked as
	//   network-inbound: a remote filter never matches it (no peer yet,
	//   v0.2.2) and a local loopback filter fails IPv6 dual-stack
	//   listeners (:: does not match "localhost:*", v0.2.3).
	for _, banned := range []string{
		`(allow network* (local ip`,
		`(allow network* (remote ip`,
		`(allow network-outbound (local ip`,
		`(allow network-inbound (remote ip`,
		`(allow network-inbound (local ip`,
	} {
		if strings.Contains(p, banned) {
			t.Errorf("profile contains forbidden rule shape %q", banned)
		}
	}

	for _, want := range []string{
		"(allow network-bind)",
		"(allow network-inbound)",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("profile missing %q", want)
		}
	}

	for _, want := range []string{
		"(version 1)",
		"(allow default)",
		`(deny file-write* (subpath "/Users/alice/.config/seki"))`,
		`(deny network* (remote unix-socket (path-literal "/Users/alice/.config/seki/seki-123.sock")))`,
		`(deny network* (remote ip "localhost:53"))`,
		`(deny network* (remote ip6 "localhost:53"))`,
		`(deny mach-lookup (global-name "com.apple.mDNSResponder"))`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("profile missing %q", want)
		}
	}
}

func TestQuoteEscaping(t *testing.T) {
	p := Profile(Params{
		ReadOnlyPaths: []string{`/Users/we"ird/.config/seki`},
	})
	if !strings.Contains(p, `"/Users/we\"ird/.config/seki"`) {
		t.Errorf("quote escaping failed:\n%s", p)
	}
}
