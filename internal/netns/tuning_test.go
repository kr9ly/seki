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
// invariants that keep inspection intact; see loopbackNotrackRuleset.
func TestLoopbackNotrackRuleset(t *testing.T) {
	var lines []string
	for _, l := range strings.Split(loopbackNotrackRuleset(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	index := func(want string) int {
		t.Helper()
		found := -1
		for i, l := range lines {
			if l == want {
				if found != -1 {
					t.Fatalf("duplicate line %q", want)
				}
				found = i
			}
		}
		if found == -1 {
			t.Fatalf("missing line %q in:\n%s", want, strings.Join(lines, "\n"))
		}
		return found
	}

	// DNS (pre-DNAT port 53, post-DNAT DNSPort) is excluded before notrack,
	// in both directions and for both protocols.
	ports := "{ 53, " + DNSPort + " }"
	dport := index("meta l4proto { tcp, udp } th dport " + ports + " return")
	sport := index("meta l4proto { tcp, udp } th sport " + ports + " return")
	notrack := index("notrack")
	if dport > notrack || sport > notrack {
		t.Errorf("DNS exclusions must come before notrack:\n%s", strings.Join(lines, "\n"))
	}

	// notrack appears once, and the only way to it is limited to lo with
	// 127/8 on both ends.
	index(`oif "lo" ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 jump lo`)
	for _, l := range lines {
		if strings.Contains(l, "notrack") && l != "notrack" && !strings.HasPrefix(l, "table ip ") {
			t.Errorf("unexpected notrack rule: %s", l)
		}
		if strings.Contains(l, "jump") && !strings.HasPrefix(l, `oif "lo" ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 `) {
			t.Errorf("jump not limited to loopback: %s", l)
		}
	}
	index("type filter hook output priority raw; policy accept;")
}

// The iptables fallback must keep the same invariants.
func TestLoopbackNotrackIptablesRules(t *testing.T) {
	rules := loopbackNotrackIptablesRules()
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

	// --ports covers the source and the destination port.
	for _, proto := range []string{"udp", "tcp"} {
		want := "-A " + loNotrackChain + " -p " + proto + " -m multiport --ports 53," + DNSPort + " -j RETURN"
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

	// The jump into the chain is limited to lo with 127/8 on both ends.
	jumps := 0
	for _, r := range joined {
		if !strings.Contains(r, "-j "+loNotrackChain) {
			continue
		}
		jumps++
		if !strings.Contains(r, "-o lo -s 127.0.0.0/8 -d 127.0.0.0/8") {
			t.Errorf("jump not limited to loopback: %s", r)
		}
	}
	if jumps != 1 {
		t.Errorf("jumps = %d, want 1 (OUTPUT)", jumps)
	}
	if !strings.Contains(joined[len(joined)-1], "-j "+loNotrackChain) {
		t.Errorf("jump rule must come last: %v", joined)
	}
}

// seki isolate reads the sysctls here and writes them back in the nested
// namespace, so every value read must pass the validation applied on write.
func TestCurrentNetnsSysctlsRoundTrip(t *testing.T) {
	got := CurrentNetnsSysctls()
	if len(got) == 0 {
		t.Skip("no allowlisted sysctl is readable here")
	}
	for key, value := range got {
		if err := validateNetnsSysctl(key, value); err != nil {
			t.Errorf("CurrentNetnsSysctls()[%q] = %q: %v", key, value, err)
		}
	}
}
