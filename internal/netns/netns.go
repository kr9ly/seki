package netns

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	sekidns "github.com/kr9ly/seki/internal/dns"
	"github.com/kr9ly/seki/internal/logger"
	"github.com/kr9ly/seki/internal/proxy"
	"github.com/kr9ly/seki/internal/rules"
)

const (
	VethHost     = "seki0"
	VethChild    = "seki1"
	HostAddr     = "10.200.1.1/24"
	ChildAddr    = "10.200.1.2/24"
	GatewayIP    = "10.200.1.1"
	ProxyPort    = "10201"
	RedirectPort = "10200"
)

// Sandbox holds the state of an isolated network namespace.
// Host-side changes are limited to the veth pair, which is auto-cleaned
// when the namespace is destroyed (even on crash/SIGKILL).
type Sandbox struct {
	cmd     *exec.Cmd
	cleanup []func()
}

// Exec starts the given command inside a new network+mount namespace.
func Exec(args []string) (*Sandbox, error) {
	if os.Getuid() != 0 {
		return nil, fmt.Errorf("seki exec requires root privileges (need CAP_NET_ADMIN for namespace setup)")
	}

	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}

	sb := &Sandbox{}

	// Sync pipe: parent writes when host-side setup is done
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create pipe: %w", err)
	}
	defer pw.Close()

	// Re-exec as __child in new namespaces
	childArgs := append([]string{"__child", "--"}, args...)
	cmd := exec.Command(self, childArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	cmd.ExtraFiles = []*os.File{pr} // fd 3
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
	}

	if err := cmd.Start(); err != nil {
		pr.Close()
		return nil, fmt.Errorf("start child: %w", err)
	}
	pr.Close()
	sb.cmd = cmd

	if err := sb.setupHost(cmd.Process.Pid); err != nil {
		cmd.Process.Kill()
		sb.Close()
		return nil, fmt.Errorf("setup host networking: %w", err)
	}

	// Open log database
	log, err := logger.Open()
	if err != nil {
		cmd.Process.Kill()
		sb.Close()
		return nil, fmt.Errorf("open logger: %w", err)
	}
	sb.cleanup = append(sb.cleanup, func() { log.Close() })
	fmt.Fprintf(os.Stderr, "[seki] session: %s\n", log.SessionID())

	// Load rules
	ruleset, err := rules.Load()
	if err != nil {
		cmd.Process.Kill()
		sb.Close()
		return nil, fmt.Errorf("load rules: %w", err)
	}
	if ruleset.LearningMode {
		fmt.Fprintf(os.Stderr, "[seki] mode: learning (logging only, no blocking)\n")
	} else {
		fmt.Fprintf(os.Stderr, "[seki] mode: enforce\n")
	}

	// Detect upstream DNS
	upstream, err := sekidns.DetectUpstream()
	if err != nil {
		cmd.Process.Kill()
		sb.Close()
		return nil, fmt.Errorf("detect upstream DNS: %w", err)
	}

	// Start DNS resolver on the gateway address
	resolver := sekidns.NewResolver(GatewayIP+":53", upstream, func(q sekidns.QueryEntry) {
		res := ruleset.Evaluate(q.Domain, "")
		tag := ""
		if res.Rule != nil && res.Rule.Tag != "" {
			tag = " [" + res.Rule.Tag + "]"
		}
		if res.Learned {
			fmt.Fprintf(os.Stderr, "[seki] dns: %s (%s) — would deny%s\n", q.Domain, q.QType, tag)
		} else if res.Action == rules.Deny {
			fmt.Fprintf(os.Stderr, "[seki] dns: %s (%s) — DENIED%s\n", q.Domain, q.QType, tag)
		} else {
			fmt.Fprintf(os.Stderr, "[seki] dns: %s (%s)%s\n", q.Domain, q.QType, tag)
		}
		log.LogDNS(q.Domain, q.QType)
	})
	if err := resolver.Start(); err != nil {
		cmd.Process.Kill()
		sb.Close()
		return nil, fmt.Errorf("start DNS resolver: %w", err)
	}
	sb.cleanup = append(sb.cleanup, func() { resolver.Close() })

	// Start TCP proxy on the gateway address
	tcpProxy := proxy.NewProxy(GatewayIP+":"+ProxyPort, func(c proxy.ConnEntry) {
		domain := c.SNI
		ip := ""
		if host, _, err := net.SplitHostPort(c.Dest); err == nil {
			ip = host
		}
		res := ruleset.Evaluate(domain, ip)
		tag := ""
		if res.Rule != nil && res.Rule.Tag != "" {
			tag = " [" + res.Rule.Tag + "]"
		}
		label := c.Dest
		if c.SNI != "" {
			label = c.Dest + " (" + c.SNI + ")"
		}
		if res.Learned {
			fmt.Fprintf(os.Stderr, "[seki] tcp: %s — would deny%s\n", label, tag)
		} else if res.Action == rules.Deny {
			fmt.Fprintf(os.Stderr, "[seki] tcp: %s — DENIED%s\n", label, tag)
		} else {
			fmt.Fprintf(os.Stderr, "[seki] tcp: %s%s\n", label, tag)
		}
		log.LogTCP(c.Dest, c.SNI)
	})
	if err := tcpProxy.Start(); err != nil {
		cmd.Process.Kill()
		sb.Close()
		return nil, fmt.Errorf("start TCP proxy: %w", err)
	}
	sb.cleanup = append(sb.cleanup, func() { tcpProxy.Close() })

	// Signal child to proceed
	pw.Write([]byte{1})

	return sb, nil
}

// Wait waits for the child process to exit.
func (sb *Sandbox) Wait() error {
	return sb.cmd.Wait()
}

// Close tears down host-side resources.
// Only the veth pair needs explicit cleanup; it is also auto-cleaned
// when the child namespace is destroyed.
func (sb *Sandbox) Close() {
	for i := len(sb.cleanup) - 1; i >= 0; i-- {
		sb.cleanup[i]()
	}
}

func (sb *Sandbox) setupHost(childPID int) error {
	// Clean up stale veth from a previous crashed run
	run("ip", "link", "del", VethHost)

	if err := run("ip", "link", "add", VethHost, "type", "veth", "peer", "name", VethChild); err != nil {
		return fmt.Errorf("create veth pair: %w", err)
	}
	sb.cleanup = append(sb.cleanup, func() {
		run("ip", "link", "del", VethHost)
	})

	if err := run("ip", "link", "set", VethChild, "netns", strconv.Itoa(childPID)); err != nil {
		return fmt.Errorf("move veth to child ns: %w", err)
	}

	if err := run("ip", "addr", "add", HostAddr, "dev", VethHost); err != nil {
		return fmt.Errorf("assign host addr: %w", err)
	}
	if err := run("ip", "link", "set", VethHost, "up"); err != nil {
		return fmt.Errorf("bring up host veth: %w", err)
	}

	return nil
}

// ChildSetup configures networking inside the child namespace.
// All iptables rules here are namespace-scoped and auto-cleaned on namespace destruction.
// Returns the redirect proxy (caller must keep it alive while the user command runs).
func ChildSetup() (*proxy.RedirectProxy, error) {
	// Wait for parent to finish host-side setup
	sync := os.NewFile(3, "sync")
	buf := make([]byte, 1)
	if _, err := sync.Read(buf); err != nil {
		return nil, fmt.Errorf("wait for parent: %w", err)
	}
	sync.Close()

	// Configure interfaces
	if err := run("ip", "link", "set", "lo", "up"); err != nil {
		return nil, fmt.Errorf("loopback up: %w", err)
	}
	if err := run("ip", "addr", "add", ChildAddr, "dev", VethChild); err != nil {
		return nil, fmt.Errorf("assign child addr: %w", err)
	}
	if err := run("ip", "link", "set", VethChild, "up"); err != nil {
		return nil, fmt.Errorf("bring up child veth: %w", err)
	}
	if err := run("ip", "route", "add", "default", "via", GatewayIP); err != nil {
		return nil, fmt.Errorf("add default route: %w", err)
	}

	// Start child-side redirect proxy (must be running before iptables REDIRECT)
	rp := proxy.NewRedirectProxy("127.0.0.1:"+RedirectPort, GatewayIP+":"+ProxyPort)
	if err := rp.Start(); err != nil {
		return nil, fmt.Errorf("start redirect proxy: %w", err)
	}

	// DNS redirect: all DNS queries go to seki's resolver via DNAT
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53",
		"-j", "DNAT", "--to-destination", GatewayIP+":53"); err != nil {
		rp.Close()
		return nil, fmt.Errorf("dns redirect (udp): %w", err)
	}
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53",
		"-j", "DNAT", "--to-destination", GatewayIP+":53"); err != nil {
		rp.Close()
		return nil, fmt.Errorf("dns redirect (tcp): %w", err)
	}

	// TCP redirect: loopback and veth subnet are excluded, everything else goes to redirect proxy
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.0/8",
		"-j", "RETURN"); err != nil {
		rp.Close()
		return nil, fmt.Errorf("tcp return loopback: %w", err)
	}
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "10.200.1.0/24",
		"-j", "RETURN"); err != nil {
		rp.Close()
		return nil, fmt.Errorf("tcp return veth: %w", err)
	}
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp",
		"-j", "REDIRECT", "--to-ports", RedirectPort); err != nil {
		rp.Close()
		return nil, fmt.Errorf("tcp redirect: %w", err)
	}

	// UDP policy: allow DNS (already DNATed above), allow gateway, drop everything else
	if err := run("iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"); err != nil {
		rp.Close()
		return nil, fmt.Errorf("udp allow dns: %w", err)
	}
	if err := run("iptables", "-A", "OUTPUT", "-p", "udp", "-d", GatewayIP, "-j", "ACCEPT"); err != nil {
		rp.Close()
		return nil, fmt.Errorf("udp allow gateway: %w", err)
	}
	if err := run("iptables", "-A", "OUTPUT", "-p", "udp", "-j", "DROP"); err != nil {
		rp.Close()
		return nil, fmt.Errorf("udp drop: %w", err)
	}

	return rp, nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}
