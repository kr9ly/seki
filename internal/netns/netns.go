package netns

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kr9ly/seki/internal/approval"
	"github.com/kr9ly/seki/internal/credential"
	sekidns "github.com/kr9ly/seki/internal/dns"
	"github.com/kr9ly/seki/internal/logger"
	"github.com/kr9ly/seki/internal/proxy"
	"github.com/kr9ly/seki/internal/rules"
	"github.com/kr9ly/seki/internal/socket"
	"github.com/kr9ly/seki/internal/sshagent"
)

const (
	ProxyPort = "10200"
	DNSPort   = "5353"
	// slirp4netns defaults
	SlirpDNS = "10.0.2.3"
)

// Sandbox holds the state of an isolated network namespace.
type Sandbox struct {
	cmd     *exec.Cmd
	slirp   *exec.Cmd
	exitPw  *os.File // closing this stops slirp4netns
	cleanup []func()
}

// Exec starts the given command inside a new user+network+mount namespace.
// No root privileges required — uses unprivileged user namespaces + slirp4netns.
func Exec(args []string) (*Sandbox, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}

	// Check slirp4netns is available
	if _, err := exec.LookPath("slirp4netns"); err != nil {
		return nil, fmt.Errorf("slirp4netns not found: install with 'apt install slirp4netns'")
	}

	sb := &Sandbox{}

	// Set per-session socket name so multiple seki exec can coexist
	sockName := fmt.Sprintf("seki-%d.sock", os.Getpid())
	os.Setenv("SEKI_SOCK", sockName)
	credSockName := fmt.Sprintf("seki-cred-%d.sock", os.Getpid())
	os.Setenv("SEKI_CRED_SOCK", credSockName)

	// Pass caller's cwd so watch can display which project a session belongs to
	if cwd, err := os.Getwd(); err == nil {
		os.Setenv("SEKI_CWD", cwd)
	}

	// Sync pipe: parent writes after slirp4netns is ready
	syncPr, syncPw, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create sync pipe: %w", err)
	}

	// Exit pipe: closing write end stops slirp4netns
	exitPr, exitPw, err := os.Pipe()
	if err != nil {
		syncPr.Close()
		syncPw.Close()
		return nil, fmt.Errorf("create exit pipe: %w", err)
	}
	sb.exitPw = exitPw

	// Start credential socket server before cmd.Start() so the path is
	// known when we build cmd.Env below.
	credCfg, err := credential.LoadConfig()
	if credCfg == nil {
		credCfg = &credential.Config{}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki: credential config: %v\n", err)
	} else if len(credCfg.Credentials) > 0 {
		hostEnv := envToMap(os.Environ())
		credSrv, err := credential.NewServer(credCfg, hostEnv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki: credential server: %v\n", err)
		} else {
			sb.cleanup = append(sb.cleanup, func() { credSrv.Close() })
		}
	}

	// Start SSH agent proxy if host has ssh-agent running. This also runs
	// before cmd.Start() so the socket path is available for cmd.Env.
	var sshProxyPath string
	if hostSSHAuth := os.Getenv("SSH_AUTH_SOCK"); hostSSHAuth != "" {
		home, _ := os.UserHomeDir()
		sshProxyPath = filepath.Join(home, ".config", "seki",
			fmt.Sprintf("seki-ssh-%d.sock", os.Getpid()))
		sshProxy, err := sshagent.NewProxy(sshProxyPath, hostSSHAuth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki: ssh agent proxy: %v\n", err)
			sshProxyPath = "" // fallback: no proxy
		} else {
			sb.cleanup = append(sb.cleanup, func() { sshProxy.Close() })
		}
	}

	// Re-exec as __child in new user+network+mount namespaces
	childArgs := append([]string{"__child", "--"}, args...)
	cmd := exec.Command(self, childArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = buildChildEnv(self, sshProxyPath, credCfg.SecretKeys())
	cmd.ExtraFiles = []*os.File{syncPr} // fd 3
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}

	if err := cmd.Start(); err != nil {
		syncPr.Close()
		syncPw.Close()
		exitPr.Close()
		exitPw.Close()
		return nil, fmt.Errorf("start child: %w", err)
	}
	syncPr.Close()
	sb.cmd = cmd

	// Ready pipe: slirp4netns writes a byte when tap0 is configured
	readyPr, readyPw, err := os.Pipe()
	if err != nil {
		cmd.Process.Kill()
		syncPw.Close()
		exitPr.Close()
		exitPw.Close()
		return nil, fmt.Errorf("create ready pipe: %w", err)
	}

	// Start slirp4netns
	// --configure: auto-configure tap0 IP/route
	// ExtraFiles[0]=readyPw (fd 3), ExtraFiles[1]=exitPr (fd 4)
	slirpCmd := exec.Command("slirp4netns",
		"--configure",
		"--mtu", "65520",
		"-r", "3", // ready fd
		"-e", "4", // exit fd
		fmt.Sprintf("%d", cmd.Process.Pid),
		"tap0",
	)
	slirpCmd.ExtraFiles = []*os.File{readyPw, exitPr}
	slirpCmd.Stdout = nil
	slirpCmd.Stderr = nil

	if err := slirpCmd.Start(); err != nil {
		cmd.Process.Kill()
		syncPw.Close()
		readyPr.Close()
		readyPw.Close()
		exitPr.Close()
		exitPw.Close()
		return nil, fmt.Errorf("start slirp4netns: %w", err)
	}
	readyPw.Close()
	exitPr.Close()
	sb.slirp = slirpCmd

	// Wait for slirp4netns to signal tap0 is ready
	buf := make([]byte, 1)
	if _, err := readyPr.Read(buf); err != nil {
		cmd.Process.Kill()
		slirpCmd.Process.Kill()
		syncPw.Close()
		readyPr.Close()
		return nil, fmt.Errorf("wait for slirp4netns: %w", err)
	}
	readyPr.Close()

	// Start Unix socket server for watch clients
	sock, err := socket.NewServer()
	if err != nil {
		cmd.Process.Kill()
		slirpCmd.Process.Kill()
		syncPw.Close()
		return nil, fmt.Errorf("start socket server: %w", err)
	}
	sb.cleanup = append(sb.cleanup, func() { sock.Close() })

	// Re-broadcast messages from watch to all clients (including child)
	sock.OnMessage(func(e socket.Event) {
		sock.Emit(e)
	})

	// Signal child: slirp4netns is ready, proceed with setup
	syncPw.Write([]byte{1})
	syncPw.Close()

	return sb, nil
}

// Wait waits for the child process to exit, then cleans up slirp4netns.
func (sb *Sandbox) Wait() error {
	err := sb.cmd.Wait()

	// Close exit pipe to stop slirp4netns
	if sb.exitPw != nil {
		sb.exitPw.Close()
	}
	if sb.slirp != nil {
		sb.slirp.Wait()
	}

	return err
}

// Close tears down resources.
func (sb *Sandbox) Close() {
	for i := len(sb.cleanup) - 1; i >= 0; i-- {
		sb.cleanup[i]()
	}
}

// ChildState holds resources started inside the child namespace.
type ChildState struct {
	log      *logger.Logger
	resolver *sekidns.Resolver
	proxy    *proxy.Proxy
	sock     *socket.Client
	Queue    *approval.Queue
}

const approvalTimeout = 30 * time.Second

// Close tears down child resources.
func (cs *ChildState) Close() {
	if cs.proxy != nil {
		cs.proxy.Close()
	}
	if cs.resolver != nil {
		cs.resolver.Close()
	}
	if cs.sock != nil {
		cs.sock.Close()
	}
	if cs.log != nil {
		cs.log.Close()
	}
}

// ChildSetup configures networking and starts services inside the child namespace.
// All iptables rules are namespace-scoped and auto-cleaned on namespace destruction.
func ChildSetup() (*ChildState, error) {
	// Wait for parent to signal slirp4netns is ready
	sync := os.NewFile(3, "sync")
	buf := make([]byte, 1)
	if _, err := sync.Read(buf); err != nil {
		return nil, fmt.Errorf("wait for parent: %w", err)
	}
	sync.Close()

	// Bring up loopback (slirp4netns --configure handles tap0)
	if err := run("ip", "link", "set", "lo", "up"); err != nil {
		return nil, fmt.Errorf("loopback up: %w", err)
	}

	// Override /etc/resolv.conf to point to seki's DNS resolver
	if err := overrideResolvConf(); err != nil {
		return nil, fmt.Errorf("override resolv.conf: %w", err)
	}

	// Protect seki config from modification by sandboxed process
	if err := protectSekiConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "seki: protect config: %v\n", err)
	}

	// Bind-mount user's .ssh to /root/.ssh so SSH works under uid 0 mapping
	if err := bindSSH(); err != nil {
		// Non-fatal: SSH might not be needed
		fmt.Fprintf(os.Stderr, "seki: ssh bind-mount: %v\n", err)
	}

	cs := &ChildState{}

	// Open log database
	log, err := logger.Open()
	if err != nil {
		return nil, fmt.Errorf("open logger: %w", err)
	}
	cs.log = log

	// Load rules
	ruleset, err := rules.Load()
	if err != nil {
		cs.Close()
		return nil, fmt.Errorf("load rules: %w", err)
	}

	// Connect to parent's socket server for event exchange
	sock, err := socket.Connect(false)
	if err != nil {
		sock = nil
	}
	cs.sock = sock

	sessionCwd := os.Getenv("SEKI_CWD")
	emitEvent := func(e socket.Event) {
		if cs.sock != nil {
			e.Cwd = sessionCwd
			cs.sock.Emit(e)
		}
	}

	// Listen for approve/deny messages from watch (via parent re-broadcast)
	if sock != nil {
		go func() {
			for sock.Next() {
				e, err := sock.Event()
				if err != nil {
					continue
				}
				switch e.Type {
				case "approve":
					if cs.Queue != nil {
						cs.Queue.Resolve(e.Domain, true)
					}
				case "deny":
					if cs.Queue != nil {
						cs.Queue.Resolve(e.Domain, false)
					}
				}
			}
		}()
	}

	// Emit status
	emitEvent(socket.Event{
		Type:         "status",
		Session:      log.SessionID(),
		LearningMode: ruleset.LearningMode,
	})

	// Start DNS resolver (upstream: slirp4netns DNS relay)
	resolver := sekidns.NewResolver("127.0.0.1:"+DNSPort, SlirpDNS+":53", func(q sekidns.QueryEntry) bool {
		res := ruleset.Evaluate(q.Domain, "")
		ruleTag := ""
		if res.Rule != nil && res.Rule.Tag != "" {
			ruleTag = res.Rule.Tag
		}
		log.LogDNS(q.Domain, q.QType, res.Action)
		emitEvent(socket.Event{
			Type: "dns", Domain: q.Domain, QType: q.QType,
			Action: res.Action, Tag: ruleTag, Learned: res.Learned,
		})
		return res.Action == rules.Allow || res.Action == rules.Prompt
	})
	if err := resolver.Start(); err != nil {
		cs.Close()
		return nil, fmt.Errorf("start DNS resolver: %w", err)
	}
	cs.resolver = resolver

	// Approval queue for prompt action
	queue := approval.NewQueue()
	cs.Queue = queue

	// Start TCP proxy
	tcpProxy := proxy.NewProxy("127.0.0.1:"+ProxyPort, func(c proxy.ConnEntry) proxy.ConnResult {
		domain := c.SNI
		ip := ""
		if host, _, err := net.SplitHostPort(c.Dest); err == nil {
			ip = host
		}
		// Resolve domain from DNS cache if SNI is empty
		if domain == "" && ip != "" {
			domain = resolver.LookupIP(ip)
		}
		res := ruleset.Evaluate(domain, ip)
		ruleTag := ""
		if res.Rule != nil && res.Rule.Tag != "" {
			ruleTag = res.Rule.Tag
		}
		log.LogTCP(c.Dest, c.SNI, res.Action)
		emitEvent(socket.Event{
			Type: "tcp", Dest: c.Dest, SNI: c.SNI, Domain: domain,
			Action: res.Action, Tag: ruleTag, Learned: res.Learned,
		})

		switch res.Action {
		case rules.Allow:
			return proxy.ConnAllow
		case rules.Prompt:
			// Block and wait for approval
			queueDomain := domain
			if queueDomain == "" {
				queueDomain = c.Dest
			}
			emitEvent(socket.Event{
				Type: "approval", Domain: queueDomain, Dest: c.Dest,
				Action: "prompt", QueueSize: queue.Size() + 1,
			})
			if queue.Submit(queueDomain, c.Dest, approvalTimeout) {
				return proxy.ConnAllow
			}
			return proxy.ConnDeny
		default: // deny
			return proxy.ConnDeny
		}
	})
	if err := tcpProxy.Start(); err != nil {
		cs.Close()
		return nil, fmt.Errorf("start TCP proxy: %w", err)
	}
	cs.proxy = tcpProxy

	// Apply iptables rules (all namespace-scoped)
	if err := setupIptables(); err != nil {
		cs.Close()
		return nil, fmt.Errorf("iptables: %w", err)
	}

	return cs, nil
}

// setupIptables configures packet redirection inside the namespace.
func setupIptables() error {
	// SO_MARK=1 connections bypass all REDIRECT/DNAT (seki's own traffic)
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT",
		"-m", "mark", "--mark", "0x1", "-j", "RETURN"); err != nil {
		return fmt.Errorf("mark bypass: %w", err)
	}

	// DNS redirect: all DNS queries go to seki's resolver
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53",
		"-j", "DNAT", "--to-destination", "127.0.0.1:"+DNSPort); err != nil {
		return fmt.Errorf("dns redirect (udp): %w", err)
	}
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53",
		"-j", "DNAT", "--to-destination", "127.0.0.1:"+DNSPort); err != nil {
		return fmt.Errorf("dns redirect (tcp): %w", err)
	}

	// TCP: exclude loopback from REDIRECT
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.0/8",
		"-j", "RETURN"); err != nil {
		return fmt.Errorf("tcp return loopback: %w", err)
	}

	// TCP: redirect everything else to seki's proxy
	if err := run("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp",
		"-j", "REDIRECT", "--to-ports", ProxyPort); err != nil {
		return fmt.Errorf("tcp redirect: %w", err)
	}

	// UDP policy: allow seki's own traffic (marked), allow loopback (DNATed DNS), drop rest
	if err := run("iptables", "-A", "OUTPUT", "-p", "udp",
		"-m", "mark", "--mark", "0x1", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("udp allow marked: %w", err)
	}
	if err := run("iptables", "-A", "OUTPUT", "-p", "udp", "-d", "127.0.0.0/8",
		"-j", "ACCEPT"); err != nil {
		return fmt.Errorf("udp allow loopback: %w", err)
	}
	if err := run("iptables", "-A", "OUTPUT", "-p", "udp",
		"-j", "DROP"); err != nil {
		return fmt.Errorf("udp drop: %w", err)
	}

	return nil
}

// overrideResolvConf bind-mounts a custom resolv.conf pointing to seki's DNS.
func overrideResolvConf() error {
	// Make mount namespace private to prevent propagation
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make private: %w", err)
	}

	// Write temp resolv.conf (use PID to avoid collisions)
	content := []byte("nameserver 127.0.0.1\n")
	tmpPath := fmt.Sprintf("/tmp/seki-resolv-%d.conf", os.Getpid())
	if err := os.WriteFile(tmpPath, content, 0644); err != nil {
		return fmt.Errorf("write temp resolv.conf: %w", err)
	}
	defer os.Remove(tmpPath)

	// Bind mount over /etc/resolv.conf
	if err := syscall.Mount(tmpPath, "/etc/resolv.conf", "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mount: %w", err)
	}

	return nil
}

// protectSekiConfig bind-mounts ~/.config/seki/ as read-only to prevent
// the sandboxed process from tampering with rules or credential config.
func protectSekiConfig() error {
	home := os.Getenv("HOME")
	if home == "" {
		return nil
	}
	sekiDir := filepath.Join(home, ".config", "seki")
	if _, err := os.Stat(sekiDir); err != nil {
		return nil // no config dir, nothing to protect
	}
	// Bind mount on itself
	if err := syscall.Mount(sekiDir, sekiDir, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mount: %w", err)
	}
	// Remount as read-only
	if err := syscall.Mount("", sekiDir, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount ro: %w", err)
	}
	return nil
}

// bindSSH copies SSH config and known_hosts to /root/.ssh inside the namespace.
// Inside the user namespace uid is mapped to 0, so SSH looks for /root/.ssh
// via getpwuid(0) instead of HOME. Private keys are intentionally NOT copied;
// authentication is handled by the SSH agent proxy running on the host.
func bindSSH() error {
	home := os.Getenv("HOME")
	if home == "" {
		return nil
	}
	sshDir := home + "/.ssh"
	if _, err := os.Stat(sshDir); err != nil {
		return nil
	}
	// /root is owned by real root — mount tmpfs so we can write under our uid mapping
	if err := syscall.Mount("tmpfs", "/root", "tmpfs", 0, "size=1m"); err != nil {
		return fmt.Errorf("tmpfs /root: %w", err)
	}
	if err := os.MkdirAll("/root/.ssh", 0700); err != nil {
		return fmt.Errorf("mkdir /root/.ssh: %w", err)
	}

	// Copy only config and known_hosts — NOT private keys
	for _, name := range []string{"config", "known_hosts"} {
		src := filepath.Join(sshDir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			continue // file doesn't exist, skip
		}
		dst := filepath.Join("/root/.ssh", name)
		if err := os.WriteFile(dst, data, 0600); err != nil {
			return fmt.Errorf("copy %s: %w", name, err)
		}
	}
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// buildChildEnv constructs the environment for the child process.
// It injects git credential helper config, filters conflicting GIT_CONFIG_* vars,
// and strips secret environment variables referenced by credential config.
// If sshProxyPath is non-empty, SSH_AUTH_SOCK is replaced with the proxy socket path.
func buildChildEnv(sekiBin string, sshProxyPath string, secretKeys []string) []string {
	env := os.Environ()

	// Build set of secret key prefixes for O(1) lookup.
	secrets := make(map[string]struct{}, len(secretKeys))
	for _, k := range secretKeys {
		secrets[k+"="] = struct{}{}
	}

	filtered := make([]string, 0, len(env)+4)
	for _, e := range env {
		if strings.HasPrefix(e, "GIT_CONFIG_COUNT=") ||
			strings.HasPrefix(e, "GIT_CONFIG_KEY_") ||
			strings.HasPrefix(e, "GIT_CONFIG_VALUE_") {
			continue
		}
		if sshProxyPath != "" && strings.HasPrefix(e, "SSH_AUTH_SOCK=") {
			continue
		}
		// Strip secret env vars — values stay on host, injected via credential proxy.
		skip := false
		for prefix := range secrets {
			if strings.HasPrefix(e, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		filtered = append(filtered, e)
	}
	filtered = append(filtered,
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=credential.helper",
		fmt.Sprintf("GIT_CONFIG_VALUE_0=!%s credential", sekiBin),
	)
	if sshProxyPath != "" {
		filtered = append(filtered, "SSH_AUTH_SOCK="+sshProxyPath)
	}
	return filtered
}

// envToMap converts os.Environ() slice to a map.
func envToMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, e := range environ {
		if k, v, ok := strings.Cut(e, "="); ok {
			m[k] = v
		}
	}
	return m
}
