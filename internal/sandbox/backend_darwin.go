//go:build darwin

// darwin backend: Seatbelt (sandbox-exec) + explicit CONNECT proxy.
//
// Unlike the Linux backend there is no namespace re-exec dance: the parent
// seki process hosts every checkpoint service itself (rule engine, logger,
// approval queue, watch socket, CONNECT proxy, credential/ssh-agent
// proxies), generates a Seatbelt profile that denies all non-loopback
// networking, and runs the user command under /usr/bin/sandbox-exec with
// HTTP(S)_PROXY pointing at the CONNECT proxy. Cooperative processes go
// through the checkpoint; everything else gets EPERM from Seatbelt.
//
// NOT YET VALIDATED ON A REAL MAC — the Seatbelt spike (DESIGN.md
// 「スパイク計画」) must confirm the profile semantics before this backend
// can be trusted.

package sandbox

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	gosync "sync"
	"syscall"
	"time"

	"github.com/kr9ly/seki/internal/approval"
	"github.com/kr9ly/seki/internal/bridge"
	"github.com/kr9ly/seki/internal/credential"
	"github.com/kr9ly/seki/internal/logger"
	"github.com/kr9ly/seki/internal/profile"
	"github.com/kr9ly/seki/internal/proxy"
	"github.com/kr9ly/seki/internal/rules"
	"github.com/kr9ly/seki/internal/seatbelt"
	"github.com/kr9ly/seki/internal/socket"
	"github.com/kr9ly/seki/internal/sshagent"
)

const sandboxExecPath = "/usr/bin/sandbox-exec"

type darwinBackend struct{}

func platformBackend() Backend {
	return darwinBackend{}
}

func (darwinBackend) Name() string { return "darwin-seatbelt" }

func (darwinBackend) Exec(args []string) (Instance, error) {
	return darwinExec(args)
}

// darwinSandbox is a running Seatbelt sandbox and its host-side services.
type darwinSandbox struct {
	cmd     *exec.Cmd
	cleanup []func()
}

func (sb *darwinSandbox) Wait() error {
	return sb.cmd.Wait()
}

func (sb *darwinSandbox) Close() {
	for i := len(sb.cleanup) - 1; i >= 0; i-- {
		sb.cleanup[i]()
	}
}

var approvalTimeout = func() time.Duration {
	if s := os.Getenv("SEKI_APPROVAL_TIMEOUT"); s != "" {
		var v int
		if _, err := fmt.Sscanf(s, "%d", &v); err == nil && v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	return 30 * time.Second
}()

func darwinExec(args []string) (*darwinSandbox, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}
	if _, err := os.Stat(sandboxExecPath); err != nil {
		return nil, fmt.Errorf("%s not found: %w", sandboxExecPath, err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("user home: %w", err)
	}
	cfgDir := filepath.Join(home, ".config", "seki")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		return nil, fmt.Errorf("config dir: %w", err)
	}

	sb := &darwinSandbox{}
	fail := func(err error) (*darwinSandbox, error) {
		sb.Close()
		return nil, err
	}

	pid := os.Getpid()
	// Control socket (watch): denied to the sandbox by the Seatbelt profile.
	ctlSockName := fmt.Sprintf("seki-%d.sock", pid)
	os.Setenv("SEKI_SOCK", ctlSockName)
	// Sandbox-facing event socket: hooks/emit connect here; always untrusted.
	sbSockName := fmt.Sprintf("seki-sb-%d.sock", pid)
	credSockName := fmt.Sprintf("seki-cred-%d.sock", pid)
	os.Setenv("SEKI_CRED_SOCK", credSockName)
	cwd, _ := os.Getwd()
	os.Setenv("SEKI_CWD", cwd)

	globalCfg, err := profile.LoadGlobalConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki: global config: %v\n", err)
		globalCfg = &profile.GlobalConfig{}
	}
	if len(globalCfg.Services) > 0 {
		fmt.Fprintln(os.Stderr, "seki: services are not supported by the darwin backend yet — ignoring")
	}

	// Loopback bridges: host-side forwarders tied to this sandbox's lifetime.
	// The address is shared with the host and sibling sandboxes (no netns on
	// darwin), so an already-bound listen address means someone is serving it
	// — skip, don't fail. Consequence: the sandbox that started a bridge takes
	// it down on exit even if a sibling still uses it; the next sandbox
	// re-creates it.
	for _, br := range profile.MatchBridges(cwd, globalCfg.Bridges) {
		b, err := bridge.Start(br.Name, br.Listen, br.Connect)
		if err != nil {
			if errors.Is(err, syscall.EADDRINUSE) {
				fmt.Fprintf(os.Stderr, "seki: bridge %s: %s already has a listener — skipping\n", br.Name, br.Listen)
			} else {
				fmt.Fprintf(os.Stderr, "seki: bridge %s: %v\n", br.Name, err)
			}
			continue
		}
		fmt.Fprintf(os.Stderr, "seki: bridge %s: %s → %s\n", br.Name, br.Listen, br.Connect)
		sb.cleanup = append(sb.cleanup, func() { b.Close() })
	}

	log, err := logger.Open()
	if err != nil {
		return fail(fmt.Errorf("open logger: %w", err))
	}
	sb.cleanup = append(sb.cleanup, func() { log.Close() })

	ruleset, err := rules.Load()
	if err != nil {
		return fail(fmt.Errorf("load rules: %w", err))
	}
	var rulesMu gosync.RWMutex

	// Watch socket server (control) + sandbox event listener.
	sock, err := socket.NewServer()
	if err != nil {
		return fail(fmt.Errorf("start socket server: %w", err))
	}
	sb.cleanup = append(sb.cleanup, func() { sock.Close() })
	sbSockPath := filepath.Join(cfgDir, sbSockName)
	if err := sock.ListenUntrusted(sbSockPath); err != nil {
		return fail(fmt.Errorf("start sandbox socket: %w", err))
	}

	emitEvent := func(e socket.Event) {
		if e.Cwd == "" {
			e.Cwd = cwd
		}
		sock.Emit(e)
	}

	// Approval queue for prompt rules.
	queue := approval.NewQueue()

	// Approve/deny arrive from watch on the control socket (the untrusted
	// listener drops them). Everything is re-broadcast so in-sandbox hook
	// clients see cmd_approve/cmd_deny responses.
	sock.OnMessage(func(e socket.Event) {
		switch e.Type {
		case "approve":
			queue.Resolve(e.Domain, true)
			rulesMu.Lock()
			_ = ruleset.AddRule(e.Domain, rules.Allow, "", rules.KindNetwork)
			rulesMu.Unlock()
		case "deny":
			queue.Resolve(e.Domain, false)
			rulesMu.Lock()
			_ = ruleset.AddRule(e.Domain, rules.Deny, "", rules.KindNetwork)
			rulesMu.Unlock()
		}
		sock.Emit(e)
	})

	// Credential helper socket (git credential fill via host-held secrets).
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

	// SSH agent proxy (signing stays on the host).
	var sshProxyPath string
	if hostSSHAuth := os.Getenv("SSH_AUTH_SOCK"); hostSSHAuth != "" {
		sshProxyPath = filepath.Join(cfgDir, fmt.Sprintf("seki-ssh-%d.sock", pid))
		sshProxy, err := sshagent.NewProxy(sshProxyPath, hostSSHAuth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki: ssh agent proxy: %v\n", err)
			sshProxyPath = ""
		} else {
			sb.cleanup = append(sb.cleanup, func() { sshProxy.Close() })
		}
	}

	// CONNECT proxy — the single route out of the sandbox.
	cp := proxy.NewConnectProxy(func(c proxy.ConnEntry) proxy.ConnResult {
		// Dest carries the hostname (CONNECT is name-based); SNI is set
		// when the ClientHello names a different domain (fronting check).
		domain := c.SNI
		host, _, err := net.SplitHostPort(c.Dest)
		if err != nil {
			host = c.Dest
		}
		if domain == "" {
			domain = host
		}
		ip := ""
		if net.ParseIP(host) != nil {
			ip = host
		}
		rulesMu.RLock()
		res := ruleset.Evaluate(domain, ip)
		rulesMu.RUnlock()
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
			emitEvent(socket.Event{
				Type: "approval", Domain: domain, Dest: c.Dest,
				Action: "prompt", QueueSize: queue.Size() + 1,
			})
			if queue.Submit(domain, c.Dest, approvalTimeout) {
				return proxy.ConnAllow
			}
			return proxy.ConnDeny
		default:
			return proxy.ConnDeny
		}
	})
	if err := cp.Start("127.0.0.1:0"); err != nil {
		return fail(fmt.Errorf("start CONNECT proxy: %w", err))
	}
	sb.cleanup = append(sb.cleanup, func() { cp.Close() })
	proxyAddr := cp.Addr()

	// Claude profile switching: no mount namespace on darwin, so instead of
	// bind-mounting .credentials.json we point CLAUDE_CONFIG_DIR at a
	// per-profile directory (credentials live there directly; no sync-back).
	claudeProfile, claudeEnv := resolveClaudeProfile(cwd, home)

	// Session status for watch.
	emitEvent(socket.Event{
		Type:         "status",
		Session:      log.SessionID(),
		LearningMode: ruleset.LearningMode,
		Profile:      claudeProfile,
	})

	// Seatbelt profile.
	_, proxyPortStr, _ := net.SplitHostPort(proxyAddr)
	proxyPort := 0
	fmt.Sscanf(proxyPortStr, "%d", &proxyPort)
	sbpl := seatbelt.Profile(seatbelt.Params{
		ProxyPort:     proxyPort,
		ReadOnlyPaths: []string{cfgDir},
		DenySockets:   []string{filepath.Join(cfgDir, ctlSockName)},
	})
	profilePath := filepath.Join(cfgDir, fmt.Sprintf("seki-profile-%d.sb", pid))
	if err := os.WriteFile(profilePath, []byte(sbpl), 0600); err != nil {
		return fail(fmt.Errorf("write seatbelt profile: %w", err))
	}
	sb.cleanup = append(sb.cleanup, func() { os.Remove(profilePath) })

	cmd := exec.Command(sandboxExecPath, append([]string{"-f", profilePath, args[0]}, args[1:]...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = buildSandboxEnv(self, sshProxyPath, credCfg.SecretKeys(),
		globalCfg.SandboxEnv, proxyAddr, sbSockName, claudeEnv)

	if err := cmd.Start(); err != nil {
		return fail(fmt.Errorf("start sandbox-exec: %w", err))
	}
	sb.cmd = cmd
	return sb, nil
}

// resolveClaudeProfile maps the working directory to a Claude profile and
// returns extra env vars pointing Claude Code at the per-profile config dir.
// The SEKI_CLAUDE_PROFILE override (set by `seki exec --claude-profile`)
// wins over cwd-based resolution.
func resolveClaudeProfile(cwd, home string) (string, []string) {
	name := os.Getenv("SEKI_CLAUDE_PROFILE")
	if name == "" {
		cfg, err := profile.LoadConfig()
		if err != nil || cfg == nil || cwd == "" {
			return "", nil
		}
		name = cfg.Resolve(cwd)
	}
	if name == "" {
		return "", nil
	}
	dir := filepath.Join(home, ".claude-profiles", name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "seki: claude profile dir: %v\n", err)
		return "", nil
	}
	fmt.Fprintf(os.Stderr, "seki: claude profile: %s\n", name)
	return name, []string{"CLAUDE_CONFIG_DIR=" + dir}
}

// buildSandboxEnv constructs the sandboxed command's environment: proxy
// variables (the only route out), git credential helper injection, SSH agent
// proxy socket, ssh forced through the CONNECT proxy, and secret filtering.
func buildSandboxEnv(sekiBin, sshProxyPath string, secretKeys []string,
	sandboxEnv map[string]string, proxyAddr, sbSockName string, extra []string) []string {

	env := os.Environ()
	secrets := make(map[string]struct{}, len(secretKeys))
	for _, k := range secretKeys {
		secrets[k+"="] = struct{}{}
	}

	drop := []string{
		"GIT_CONFIG_COUNT=", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_",
		"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY=",
		"http_proxy=", "https_proxy=", "all_proxy=", "no_proxy=",
		"GIT_SSH_COMMAND=",
		// The sandbox must see its own socket, not the control socket.
		"SEKI_SOCK=",
	}

	filtered := make([]string, 0, len(env)+16)
	for _, e := range env {
		skip := false
		for _, prefix := range drop {
			if strings.HasPrefix(e, prefix) {
				skip = true
				break
			}
		}
		if !skip && sshProxyPath != "" && strings.HasPrefix(e, "SSH_AUTH_SOCK=") {
			skip = true
		}
		if !skip {
			for prefix := range secrets {
				if strings.HasPrefix(e, prefix) {
					skip = true
					break
				}
			}
		}
		if skip {
			continue
		}
		filtered = append(filtered, e)
	}

	proxyURL := "http://" + proxyAddr
	filtered = append(filtered,
		"SEKI_ACTIVE=1",
		"SEKI_SOCK="+sbSockName,
		"SEKI_PROXY_ADDR="+proxyAddr,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"ALL_PROXY="+proxyURL,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"all_proxy="+proxyURL,
		"no_proxy=localhost,127.0.0.1,::1",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=credential.helper",
		fmt.Sprintf("GIT_CONFIG_VALUE_0=!%s credential", sekiBin),
		// ssh ignores proxy env vars; force it through the CONNECT proxy so
		// git-over-ssh lands on hostname-based rule evaluation.
		fmt.Sprintf(`GIT_SSH_COMMAND=ssh -o ProxyCommand="%s proxy-connect %%h %%p"`, sekiBin),
	)
	if sshProxyPath != "" {
		filtered = append(filtered, "SSH_AUTH_SOCK="+sshProxyPath)
	}
	for k, v := range sandboxEnv {
		filtered = append(filtered, k+"="+v)
	}
	filtered = append(filtered, extra...)
	return filtered
}

// envToMap converts os.Environ() form to a map.
func envToMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, e := range environ {
		if k, v, ok := strings.Cut(e, "="); ok {
			m[k] = v
		}
	}
	return m
}
