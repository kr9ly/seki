//go:build linux

package netns

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// allowedNetnsSysctls lists the sysctls that config.json's netns_sysctls may
// set. Every key here is per-network-namespace, so writing it only affects
// the sandbox, and none of them touches seki's inspection path (routing,
// forwarding and netfilter knobs are deliberately absent).
var allowedNetnsSysctls = map[string]bool{
	"net.ipv4.ip_local_port_range": true,
	"net.core.somaxconn":           true,
	"net.ipv4.tcp_max_syn_backlog": true,
}

// validateNetnsSysctl checks one netns_sysctls entry against the allowlist
// and restricts the value to digits and spaces/tabs, which is all the
// allowed keys accept.
func validateNetnsSysctl(key, value string) error {
	if !allowedNetnsSysctls[key] {
		return fmt.Errorf("key not allowed")
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("empty value")
	}
	for _, r := range value {
		if (r < '0' || r > '9') && r != ' ' && r != '\t' {
			return fmt.Errorf("value %q must be digits separated by spaces", value)
		}
	}
	return nil
}

// applyNetnsSysctls writes the configured sysctls into the sandbox's network
// namespace. It runs in ChildSetup, where the process is still uid 0 in the
// user namespace that owns the netns; the user command later runs in a
// nested user namespace and cannot change these values.
//
// Failures are reported and skipped: a bad entry must not keep the sandbox
// from starting.
func applyNetnsSysctls(sysctls map[string]string) {
	keys := make([]string, 0, len(sysctls))
	for k := range sysctls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := sysctls[key]
		if err := validateNetnsSysctl(key, value); err != nil {
			fmt.Fprintf(os.Stderr, "seki: netns_sysctls %s: %v (skipped)\n", key, err)
			continue
		}
		path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "seki: netns_sysctls %s: %v (skipped)\n", key, err)
		}
	}
}

// loNotrackTable is the nft table holding the loopback notrack rules. It is
// separate from the tables iptables manages, so the two never collide.
const loNotrackTable = "seki_lo_notrack"

// loNotrackChain is the raw-table chain used by the iptables fallback.
const loNotrackChain = "SEKI_LO_NOTRACK"

// loopbackNotrackRuleset returns the nft ruleset that exempts
// sandbox-internal loopback traffic from connection tracking.
//
// Only packets with both source and destination in 127.0.0.0/8 are
// exempted. That keeps every inspected flow tracked:
//
//   - TCP REDIRECT to the proxy and DNAT of external DNS keep the client's
//     tap0 source address, so neither direction is 127/8 on both ends.
//   - Host port forwards (PREROUTING DNAT from tap0) have a slirp peer.
//   - DNS via resolv.conf (127.0.0.1:53, DNATed to DNSPort) is 127/8 on both
//     ends, so ports 53 and DNSPort are excluded explicitly.
//
// The rules run on every loopback packet, so they are kept short: one rule
// in the base chain, and the DNS ports matched as a set. Only the output
// hook is needed. A packet keeps its untracked mark across lo, so conntrack
// skips it at prerouting too, and nothing with 127/8 on both ends reaches
// prerouting without passing output first.
func loopbackNotrackRuleset() string {
	ports := "{ 53, " + DNSPort + " }"
	return "table ip " + loNotrackTable + ` {
	chain output {
		type filter hook output priority raw; policy accept;
		oif "lo" ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 jump lo
	}
	chain lo {
		meta l4proto { tcp, udp } th dport ` + ports + ` return
		meta l4proto { tcp, udp } th sport ` + ports + ` return
		notrack
	}
}
`
}

// loopbackNotrackIptablesRules is the fallback for hosts without nft. It has
// the same meaning as loopbackNotrackRuleset, at a higher per-packet cost.
func loopbackNotrackIptablesRules() [][]string {
	rules := [][]string{{"-t", "raw", "-N", loNotrackChain}}
	for _, proto := range []string{"udp", "tcp"} {
		// --ports matches the source or the destination port.
		rules = append(rules, []string{"-t", "raw", "-A", loNotrackChain,
			"-p", proto, "-m", "multiport", "--ports", "53," + DNSPort, "-j", "RETURN"})
	}
	rules = append(rules,
		[]string{"-t", "raw", "-A", loNotrackChain, "-j", "CT", "--notrack"},
		[]string{"-t", "raw", "-A", "OUTPUT", "-o", "lo",
			"-s", "127.0.0.0/8", "-d", "127.0.0.0/8", "-j", loNotrackChain},
	)
	return rules
}

// setupLoopbackNotrack loads loopbackNotrackRuleset with nft, or applies the
// iptables fallback when nft is not installed. nft loads the ruleset
// atomically. In the fallback the jump rule comes last, so a failure partway
// leaves the chain unreferenced and tracking unchanged.
func setupLoopbackNotrack() error {
	if _, err := exec.LookPath("nft"); err != nil {
		for _, args := range loopbackNotrackIptablesRules() {
			if err := run("iptables", args...); err != nil {
				return err
			}
		}
		return nil
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(loopbackNotrackRuleset())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// CurrentNetnsSysctls reads the allowlisted sysctls from the calling
// process's network namespace. seki isolate uses it to carry the sandbox's
// values into the nested namespace, which would otherwise start from the
// kernel defaults. Keys that cannot be read are left out.
func CurrentNetnsSysctls() map[string]string {
	out := make(map[string]string, len(allowedNetnsSysctls))
	for key := range allowedNetnsSysctls {
		data, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
		if err != nil {
			continue
		}
		// Multi-value sysctls are tab-separated when read back.
		out[key] = strings.Join(strings.Fields(string(data)), " ")
	}
	return out
}

// ApplyNetnsSysctls writes sysctls into the calling process's network
// namespace, with the same allowlist and skip-on-failure behavior as the
// sandbox setup.
func ApplyNetnsSysctls(sysctls map[string]string) {
	applyNetnsSysctls(sysctls)
}
