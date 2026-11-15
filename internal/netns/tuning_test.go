//go:build linux

package netns

import "testing"

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
