//go:build linux

package netns

import (
	"fmt"
	"os"
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

// loNotrackChain is the raw-table chain holding the loopback notrack rules.
const loNotrackChain = "SEKI_LO_NOTRACK"

// loopbackNotrackRules returns the iptables argument lists that exempt
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
// The PREROUTING hook is covered as well as OUTPUT; a packet already tracked
// at OUTPUT keeps its conntrack entry across lo and is left alone there.
func loopbackNotrackRules() [][]string {
	rules := [][]string{{"-t", "raw", "-N", loNotrackChain}}
	for _, proto := range []string{"udp", "tcp"} {
		for _, port := range []string{"53", DNSPort} {
			for _, dir := range []string{"--dport", "--sport"} {
				rules = append(rules, []string{"-t", "raw", "-A", loNotrackChain,
					"-p", proto, dir, port, "-j", "RETURN"})
			}
		}
	}
	rules = append(rules,
		[]string{"-t", "raw", "-A", loNotrackChain, "-j", "CT", "--notrack"},
		[]string{"-t", "raw", "-A", "OUTPUT", "-o", "lo",
			"-s", "127.0.0.0/8", "-d", "127.0.0.0/8", "-j", loNotrackChain},
		[]string{"-t", "raw", "-A", "PREROUTING", "-i", "lo",
			"-s", "127.0.0.0/8", "-d", "127.0.0.0/8", "-j", loNotrackChain},
	)
	return rules
}

// setupLoopbackNotrack applies loopbackNotrackRules. The jump rules come
// last, so a failure partway leaves the chain unreferenced and tracking
// unchanged.
func setupLoopbackNotrack() error {
	for _, args := range loopbackNotrackRules() {
		if err := run("iptables", args...); err != nil {
			return err
		}
	}
	return nil
}
