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
