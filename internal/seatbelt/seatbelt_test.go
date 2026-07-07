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
	allowLoopback := strings.Index(p, `(allow network* (remote ip "localhost:*"))`)
	denyDNS := strings.Index(p, "mDNSResponder")
	denyCtl := strings.Index(p, "seki-123.sock")

	if denyAll == -1 || allowLoopback == -1 || denyDNS == -1 || denyCtl == -1 {
		t.Fatalf("missing expected rules in profile:\n%s", p)
	}
	if !(denyAll < allowLoopback && allowLoopback < denyDNS && allowLoopback < denyCtl) {
		t.Fatalf("rule ordering violates SBPL later-wins precedence:\n%s", p)
	}

	for _, want := range []string{
		"(version 1)",
		"(allow default)",
		`(deny file-write* (subpath "/Users/alice/.config/seki"))`,
		`(deny network* (remote unix-socket (path-literal "/Users/alice/.config/seki/seki-123.sock")))`,
		`(deny network* (remote ip "localhost:53"))`,
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
