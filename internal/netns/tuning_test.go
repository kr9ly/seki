//go:build linux

package netns

import (
	"strings"
	"testing"
)

func TestValidateNetnsSysctl(t *testing.T) {
	cases := []struct {
		key, value string
		ok         bool
	}{
		{"net.ipv4.ip_local_port_range", "10240 65535", true},
		{"net.ipv4.ip_local_port_range", "10240\t65535", true},
		{"net.core.somaxconn", "65535", true},
		{"net.ipv4.tcp_max_syn_backlog", "65535", true},
		// Not on the allowlist: would weaken inspection or is not per-netns.
		{"net.ipv4.ip_forward", "1", false},
		{"net.ipv4.conf.all.route_localnet", "1", false},
		{"kernel.hostname", "1", false},
		{"net.ipv4.ip_local_port_range/../../../kernel/hostname", "1", false},
		// Bad values.
		{"net.core.somaxconn", "", false},
		{"net.core.somaxconn", " ", false},
		{"net.core.somaxconn", "1\n2", false},
		{"net.core.somaxconn", "abc", false},
		{"net.core.somaxconn", "-1", false},
	}
	for _, c := range cases {
		err := validateNetnsSysctl(c.key, c.value)
		if (err == nil) != c.ok {
			t.Errorf("validateNetnsSysctl(%q, %q) = %v, want ok=%v", c.key, c.value, err, c.ok)
		}
	}
}

// The notrack rules must never untrack a flow that seki NATs. These are the
// invariants that keep inspection intact; see loopbackNotrackRules.
func TestLoopbackNotrackRules(t *testing.T) {
	rules := loopbackNotrackRules()
	joined := make([]string, len(rules))
	for i, r := range rules {
		joined[i] = strings.Join(r, " ")
	}

	notrackIdx := -1
	for i, r := range joined {
		if strings.Contains(r, "--notrack") {
			if notrackIdx != -1 {
				t.Fatalf("more than one notrack rule: %v", joined)
			}
			notrackIdx = i
			if !strings.Contains(r, "-A "+loNotrackChain+" ") {
				t.Errorf("notrack rule outside %s: %s", loNotrackChain, r)
			}
		}
	}
	if notrackIdx == -1 {
		t.Fatal("no notrack rule")
	}

	// DNS (pre-DNAT port 53, post-DNAT DNSPort) is excluded before notrack.
	for _, proto := range []string{"udp", "tcp"} {
		for _, port := range []string{"53", DNSPort} {
			for _, dir := range []string{"--dport", "--sport"} {
				want := "-A " + loNotrackChain + " -p " + proto + " " + dir + " " + port + " -j RETURN"
				found := false
				for _, r := range joined[:notrackIdx] {
					if strings.Contains(r, want) {
						found = true
					}
				}
				if !found {
					t.Errorf("missing exclusion before notrack: %s", want)
				}
			}
		}
	}

	// Every jump into the chain is limited to lo with 127/8 on both ends.
	jumps := 0
	for _, r := range joined {
		if !strings.Contains(r, "-j "+loNotrackChain) {
			continue
		}
		jumps++
		if !strings.Contains(r, "-s 127.0.0.0/8 -d 127.0.0.0/8") {
			t.Errorf("jump not limited to loopback addresses: %s", r)
		}
		if !strings.Contains(r, "-o lo") && !strings.Contains(r, "-i lo") {
			t.Errorf("jump not limited to lo: %s", r)
		}
	}
	if jumps != 2 {
		t.Errorf("jumps = %d, want 2 (OUTPUT, PREROUTING)", jumps)
	}
	if jumps > 0 && !strings.Contains(joined[len(joined)-1], "-j "+loNotrackChain) {
		t.Errorf("jump rules must come last: %v", joined)
	}
}
