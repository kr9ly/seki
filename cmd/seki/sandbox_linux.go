//go:build linux

// Linux backend entrypoints: namespace child processes (__ns-setup,
// __ns-exec, __child), the services supervisor, uid/gid map helpers,
// and slirp4netns port forwarding. The darwin backend will provide its
// own equivalents (see DESIGN.md "macOS ネイティブ対応（darwin backend）").

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kr9ly/seki/internal/netns"
	"github.com/kr9ly/seki/internal/profile"
	"github.com/kr9ly/seki/internal/rules"
	"github.com/kr9ly/seki/internal/socket"
	"golang.org/x/sys/unix"
)

// cmdNsSetup is an intermediate process for setting up multi-entry uid/gid maps.
// It runs in the new user namespace with uid 65534 (no capabilities needed).
// It waits for the parent to call newuidmap/newgidmap, then re-execs as __child.
// The re-exec triggers capability recalculation with uid_map set, giving __child
// full capabilities as uid 0.
//
// fd layout:
//
//	fd 3 = sync pipe (passed through to __child for slirp4netns readiness)
//	fd 4 = mapReady pipe (read by this process; closed before re-exec)
func cmdNsSetup() {
	args := argsAfterSep(os.Args[2:])
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "seki __ns-setup: no command specified")
		os.Exit(1)
	}

	// Wait for parent to set uid/gid maps via newuidmap/newgidmap.
	// Use raw syscall to avoid Go setting close-on-exec on the fd.
	buf := make([]byte, 1)
	syscall.Read(4, buf)
	syscall.Close(4)

	// Re-exec as __child. fd 3 (sync pipe) stays open across exec.
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki __ns-setup: executable path: %v\n", err)
		os.Exit(1)
	}
	argv := append([]string{self, "__child", "--"}, args...)
	if err := syscall.Exec(self, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "seki __ns-setup: exec __child: %v\n", err)
		os.Exit(1)
	}
}

// cmdNsExec runs in the inner user namespace with ambient capabilities
// (CAP_SETUID, CAP_SETGID, CAP_SYS_ADMIN). It waits for uid_map to be set,
// then sets up the namespace (tmpfs mounts, newuidmap wrapper, Podman config)
// and execs the user command. Ambient caps survive all execs in the chain.
//
// When services are declared in the global config, cmdNsExec acts as a
// supervisor instead of exec-ing the user command directly: it spawns the
// declared services, waits for readiness, runs the user command as a child
// process, then shuts the services down on exit. This keeps the no-services
// path entirely unchanged.
func cmdNsExec() {
	args := argsAfterSep(os.Args[2:])
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "seki __ns-exec: no command specified")
		os.Exit(1)
	}

	// Wait for parent to write uid/gid maps.
	buf := make([]byte, 1)
	syscall.Read(3, buf)
	syscall.Close(3)

	// Make the mount tree shared so Podman rootless (which creates nested
	// mount namespaces) can see mounts from this namespace. CLONE_NEWNS
	// copies the parent's tree as slave; we promote back to shared here.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_SHARED, ""); err != nil {
		fmt.Fprintf(os.Stderr, "seki __ns-exec: make-rshared /: %v\n", err)
	}

	// Mount writable tmpfs on system paths that Podman needs.
	// We have CAP_SYS_ADMIN via ambient caps.
	// Preserve existing entries by bind-mounting them back after the tmpfs
	// overlay. seki's job is network isolation, not filesystem sandboxing,
	// so we should not destroy unrelated runtime state (e.g. WSL interop
	// sockets under /run/WSL/).
	for _, dir := range []string{"/var", "/run"} {
		mountTmpfsPreserving(dir)
	}
	os.MkdirAll("/var/tmp", 0777)
	os.MkdirAll("/run/lock", 0755)
	// Recreate XDG_RUNTIME_DIR on the fresh tmpfs
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		os.MkdirAll(xdg, 0700)
	}

	// Bind-mount seki over /usr/bin/newuidmap and /usr/bin/newgidmap.
	// The real setuid helpers don't work inside user namespaces (setuid
	// bit is ignored). Our wrapper uses ambient CAP_SETUID/CAP_SETGID
	// to write uid_map/gid_map directly.
	self, _ := os.Executable()
	for _, target := range []string{"/usr/bin/newuidmap", "/usr/bin/newgidmap"} {
		if err := syscall.Mount(self, target, "", syscall.MS_BIND, ""); err != nil {
			fmt.Fprintf(os.Stderr, "seki __ns-exec: bind-mount %s: %v\n", target, err)
		}
	}

	// Ensure Podman config files exist
	setupPodmanConfig()

	// Load global config to check for service declarations.
	// Filter services by the sandbox's cwd (SEKI_CWD) using match patterns.
	// If the filtered list is empty, behave identically to no services declared.
	gc, err := profile.LoadGlobalConfig()
	var activeServices []profile.Service
	if err == nil && len(gc.Services) > 0 {
		cwd := os.Getenv("SEKI_CWD")
		activeServices = profile.MatchServices(cwd, gc.Services)
	}

	if len(activeServices) == 0 {
		// No applicable services (or config error) — keep the original exec path unchanged.
		path, err := exec.LookPath(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki __ns-exec: %v\n", err)
			os.Exit(127)
		}
		if err := syscall.Exec(path, args, os.Environ()); err != nil {
			fmt.Fprintf(os.Stderr, "seki __ns-exec: exec %v: %v\n", args[0], err)
			os.Exit(1)
		}
		return // unreachable but keeps the compiler happy
	}

	// When CLONE_NEWPID was used (set by cmdChild when services are declared),
	// this process is pid 1 in the new pid namespace. Remount /proc so that
	// ps, procfs tools, and Podman see this namespace's pids rather than the
	// outer one.
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		// Non-fatal: only happens when CLONE_NEWPID was not set (e.g. during
		// unit tests or if the parent omitted it), so we warn and continue.
		fmt.Fprintf(os.Stderr, "seki __ns-exec: remount /proc: %v\n", err)
	}

	// Supervisor mode: spawn services, run user command, then shut down.
	os.Exit(runSupervisor(args, activeServices))
}

// svcState tracks a running service spawned by the supervisor.
type svcState struct {
	svc profile.Service
	cmd *exec.Cmd
	pid int
}

// runSupervisor starts the declared services, runs the user command as a child
// process (not exec), waits for all children reaping as pid 1, then shuts
// down the services in reverse order. Returns the user command's exit code.
func runSupervisor(userArgs []string, services []profile.Service) int {
	// ---- start services ----
	started := make([]svcState, 0, len(services))

	for _, svc := range services {
		if len(svc.Command) == 0 {
			fmt.Fprintf(os.Stderr, "seki supervisor: service %q has empty command, skipping\n", svc.Name)
			continue
		}
		logFile, err := openServiceLog(svc.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki supervisor: open log for %q: %v\n", svc.Name, err)
		}

		env := os.Environ()
		for k, v := range svc.Env {
			env = append(env, k+"="+v)
		}

		cmd := exec.Command(svc.Command[0], svc.Command[1:]...)
		cmd.Env = env
		if logFile != nil {
			cmd.Stdout = logFile
			cmd.Stderr = logFile
		} else {
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
		}
		// Each service gets its own process group so we can send SIGTERM/SIGKILL
		// to the whole group cleanly.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "seki supervisor: start service %q: %v\n", svc.Name, err)
			if logFile != nil {
				logFile.Close()
			}
			continue
		}
		if logFile != nil {
			logFile.Close() // child has inherited the fd; we can close our copy
		}
		started = append(started, svcState{svc: svc, cmd: cmd, pid: cmd.Process.Pid})
	}

	// ---- wait for readiness ----
	for _, st := range started {
		if st.svc.ReadySocket == "" {
			continue
		}
		sockPath := os.ExpandEnv(st.svc.ReadySocket)
		timeout := st.svc.ReadyTimeoutSec
		if timeout <= 0 {
			timeout = 15
		}
		deadline := time.Now().Add(time.Duration(timeout) * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			conn, err := net.Dial("unix", sockPath)
			if err == nil {
				conn.Close()
				ready = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ready {
			fmt.Fprintf(os.Stderr, "seki supervisor: service %q not ready after %ds (continuing)\n",
				st.svc.Name, timeout)
		}
	}

	// ---- start user command ----
	userPath, err := exec.LookPath(userArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki __ns-exec: %v\n", err)
		// Shut down services even if user command cannot start.
		shutdownServices(started)
		return 127
	}
	userCmd := exec.Command(userPath, userArgs[1:]...)
	userCmd.Stdin = os.Stdin
	userCmd.Stdout = os.Stdout
	userCmd.Stderr = os.Stderr
	userCmd.Env = os.Environ()
	// No Setpgid: user command shares the foreground pgrp so Ctrl-C reaches it.

	// As pid 1 we must reap all orphans ourselves. Use Start + manual Wait4 loop
	// rather than cmd.Wait() to avoid racing with the zombie reaping loop.
	if err := userCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "seki __ns-exec: start user command: %v\n", err)
		shutdownServices(started)
		return 1
	}
	userPid := userCmd.Process.Pid

	// Handle SIGTERM: forward to user command; ignore SIGINT (it goes to the
	// foreground pgrp which already includes the user command).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	signal.Ignore(syscall.SIGINT)
	go func() {
		for sig := range sigCh {
			userCmd.Process.Signal(sig)
		}
	}()

	// ---- pid-1 zombie reaping loop ----
	userExitCode := 0
	svcPids := make(map[int]string, len(started)) // pid → name
	for _, st := range started {
		svcPids[st.pid] = st.svc.Name
	}

	for {
		var wstatus syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &wstatus, 0, nil)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			// ECHILD: no more children
			break
		}
		if pid == userPid {
			if wstatus.Exited() {
				userExitCode = wstatus.ExitStatus()
			} else if wstatus.Signaled() {
				userExitCode = 128 + int(wstatus.Signal())
			}
			// User command has exited — begin shutdown.
			break
		}
		if name, ok := svcPids[pid]; ok {
			if !wstatus.Exited() || wstatus.ExitStatus() != 0 {
				fmt.Fprintf(os.Stderr, "seki supervisor: service %q exited unexpectedly (status %v)\n",
					name, wstatus)
			}
		}
	}

	signal.Stop(sigCh)
	close(sigCh)

	shutdownServices(started)
	return userExitCode
}

// shutdownServices stops the started services in reverse order.
func shutdownServices(started []svcState) {
	for i := len(started) - 1; i >= 0; i-- {
		st := started[i]
		// Run optional stop_command first (e.g. "podman stop --all").
		if len(st.svc.StopCommand) > 0 {
			stopCtx := exec.Command(st.svc.StopCommand[0], st.svc.StopCommand[1:]...)
			stopCtx.Stdout = io.Discard
			stopCtx.Stderr = os.Stderr
			done := make(chan error, 1)
			if err := stopCtx.Start(); err == nil {
				go func() { done <- stopCtx.Wait() }()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					stopCtx.Process.Kill()
				}
			}
		}

		pgid := -st.pid // negative pgid = process group of st.pid
		// SIGTERM to the service's process group.
		syscall.Kill(pgid, syscall.SIGTERM)

		// Wait up to 5s for the service to exit.
		terminated := make(chan struct{})
		go func(cmd *exec.Cmd) {
			cmd.Wait() //nolint:errcheck
			close(terminated)
		}(st.cmd)

		select {
		case <-terminated:
		case <-time.After(5 * time.Second):
			// Still running — force kill.
			syscall.Kill(pgid, syscall.SIGKILL)
			<-terminated
		}
	}
}

// openServiceLog opens (or creates) the log file for a service under
// ~/.cache/seki/services/<name>.log. Returns nil on error (caller logs).
func openServiceLog(name string) (*os.File, error) {
	home := os.Getenv("HOME")
	if home == "" {
		return nil, fmt.Errorf("HOME not set")
	}
	dir := filepath.Join(home, ".cache", "seki", "services")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	logPath := filepath.Join(dir, name+".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	// Write a start marker so log lines from different sessions are separated.
	fmt.Fprintf(f, "\n--- seki service %q started at %s ---\n", name, time.Now().Format(time.RFC3339))
	return f, nil
}

func cmdChild() {
	args := argsAfterSep(os.Args[2:])
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "seki __child: no command specified")
		os.Exit(1)
	}

	// ChildSetup starts DNS resolver, TCP proxy, and configures iptables.
	// These must stay alive while the user command runs.
	state, err := netns.ChildSetup()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki: namespace setup failed: %v\n", err)
		os.Exit(1)
	}
	defer state.Close()

	// Run user command in a nested user namespace as uid SandboxUID (1000).
	// The outer namespace keeps uid 0 for ChildSetup's mount/iptables.
	// When subuid is available, the range is also mapped into the inner
	// namespace. cmdChild (uid 0 in outer ns) has CAP_SETUID so it can
	// write multi-entry uid_map directly.
	subUID, subGID := netns.ParseSubIDEnv()
	useSubIDs := subUID != nil && subGID != nil

	// Check whether services apply for this cwd so we can add CLONE_NEWPID.
	// Config errors are non-fatal: treat as no services.
	// Use the same MatchServices filter as cmdNsExec so the two sides agree.
	gc, _ := profile.LoadGlobalConfig()
	var activeServices []profile.Service
	if gc != nil && len(gc.Services) > 0 {
		cwd := os.Getenv("SEKI_CWD")
		activeServices = profile.MatchServices(cwd, gc.Services)
	}
	hasServices := len(activeServices) > 0

	if !useSubIDs && hasServices {
		// Services require the __ns-exec supervisor path (which adds /proc remount
		// and the zombie-reaping loop). The no-subuid path does not go through
		// __ns-exec, so it cannot host services.
		fmt.Fprintf(os.Stderr, "seki: subuid not available — services will not be started\n")
		hasServices = false
	}

	if useSubIDs {
		// Multi-entry uid_map: use __ns-exec to wait for parent's direct
		// write, then re-exec to gain capabilities for the user command.
		mapReadyPr, mapReadyPw, err := os.Pipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki: create map-ready pipe: %v\n", err)
			os.Exit(1)
		}

		self, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki: executable path: %v\n", err)
			os.Exit(1)
		}
		nsExecArgs := append([]string{self, "__ns-exec", "--"}, args...)
		cmd := exec.Command(nsExecArgs[0], nsExecArgs[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(), "SEKI_ACTIVE=1")
		cmd.ExtraFiles = []*os.File{mapReadyPr} // fd 3 = mapReady

		cloneFlags := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS)
		if hasServices {
			// Add CLONE_NEWPID so the supervisor (__ns-exec) becomes pid 1.
			// When the supervisor exits, the kernel sends SIGKILL to all remaining
			// processes in the namespace — double-fork daemons cannot escape.
			cloneFlags |= syscall.CLONE_NEWPID
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			// CLONE_NEWNS: needed for tmpfs mounts and bind-mounting newuidmap wrapper
			// CLONE_NEWPID (conditional): supervisor mode — orphan reaping + kill-on-exit
			Cloneflags: cloneFlags,
			// Ambient caps survive exec: the user command (and Podman, and our
			// newuidmap wrapper) all inherit these capabilities.
			AmbientCaps: []uintptr{
				uintptr(unix.CAP_SETUID),
				uintptr(unix.CAP_SETGID),
				uintptr(unix.CAP_SYS_ADMIN),
			},
		}

		if err := cmd.Start(); err != nil {
			mapReadyPr.Close()
			mapReadyPw.Close()
			fmt.Fprintf(os.Stderr, "seki: start user command: %v\n", err)
			os.Exit(1)
		}
		mapReadyPr.Close()

		// Write uid/gid maps directly. cmdChild runs as uid 0 in the outer
		// namespace with CAP_SETUID/CAP_SETGID — multi-entry writes succeed.
		pid := cmd.Process.Pid
		uidMap := fmt.Sprintf("%d 0 1\n%d %d %d\n",
			netns.SandboxUID, subUID.Start, subUID.Start, subUID.Count)
		gidMap := fmt.Sprintf("%d 0 1\n%d %d %d\n",
			netns.SandboxGID, subGID.Start, subGID.Start, subGID.Count)

		if err := os.WriteFile(fmt.Sprintf("/proc/%d/uid_map", pid), []byte(uidMap), 0); err != nil {
			cmd.Process.Kill()
			mapReadyPw.Close()
			fmt.Fprintf(os.Stderr, "seki: write uid_map: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(fmt.Sprintf("/proc/%d/gid_map", pid), []byte(gidMap), 0); err != nil {
			cmd.Process.Kill()
			mapReadyPw.Close()
			fmt.Fprintf(os.Stderr, "seki: write gid_map: %v\n", err)
			os.Exit(1)
		}

		mapReadyPw.Write([]byte{1})
		mapReadyPw.Close()

		cmdErr := cmd.Wait()
		netns.SyncBackCredentials()
		if cmdErr != nil {
			if exitErr, ok := cmdErr.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			fmt.Fprintf(os.Stderr, "seki: exec %v: %v\n", args[0], cmdErr)
			os.Exit(1)
		}
	} else {
		// No subuid: single-entry mapping via Go's built-in write.
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(), "SEKI_ACTIVE=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{
				{ContainerID: netns.SandboxUID, HostID: 0, Size: 1},
			},
			GidMappings: []syscall.SysProcIDMap{
				{ContainerID: netns.SandboxGID, HostID: 0, Size: 1},
			},
		}

		cmdErr := cmd.Run()
		netns.SyncBackCredentials()
		if cmdErr != nil {
			if exitErr, ok := cmdErr.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			fmt.Fprintf(os.Stderr, "seki: exec %v: %v\n", args[0], cmdErr)
			os.Exit(1)
		}
	}
}

// cmdNewUIDMap is a drop-in replacement for /usr/bin/newuidmap.
// It writes to /proc/PID/uid_map directly using ambient CAP_SETUID.
func cmdNewUIDMap() {
	if len(os.Args) < 5 || (len(os.Args)-2)%3 != 0 {
		fmt.Fprintf(os.Stderr, "usage: newuidmap <pid> <inner> <outer> <count> [...]\n")
		os.Exit(1)
	}
	pid := os.Args[1]

	var mapping strings.Builder
	for i := 2; i < len(os.Args); i += 3 {
		fmt.Fprintf(&mapping, "%s %s %s\n", os.Args[i], os.Args[i+1], os.Args[i+2])
	}

	if err := os.WriteFile(fmt.Sprintf("/proc/%s/uid_map", pid), []byte(mapping.String()), 0); err != nil {
		fmt.Fprintf(os.Stderr, "newuidmap: write to uid_map failed: %v\n", err)
		os.Exit(1)
	}
}

// cmdNewGIDMap is a drop-in replacement for /usr/bin/newgidmap.
// It writes to /proc/PID/gid_map directly using ambient CAP_SETGID.
func cmdNewGIDMap() {
	if len(os.Args) < 5 || (len(os.Args)-2)%3 != 0 {
		fmt.Fprintf(os.Stderr, "usage: newgidmap <pid> <inner> <outer> <count> [...]\n")
		os.Exit(1)
	}
	pid := os.Args[1]

	var mapping strings.Builder
	for i := 2; i < len(os.Args); i += 3 {
		fmt.Fprintf(&mapping, "%s %s %s\n", os.Args[i], os.Args[i+1], os.Args[i+2])
	}

	if err := os.WriteFile(fmt.Sprintf("/proc/%s/gid_map", pid), []byte(mapping.String()), 0); err != nil {
		fmt.Fprintf(os.Stderr, "newgidmap: write to gid_map failed: %v\n", err)
		os.Exit(1)
	}
}

// setupPodmanConfig creates default Podman config files if they don't exist.
func setupPodmanConfig() {
	home := os.Getenv("HOME")
	if home == "" {
		return
	}
	dir := filepath.Join(home, ".config", "containers")
	os.MkdirAll(dir, 0755)

	// policy.json: allow all images (default permissive policy)
	policyPath := filepath.Join(dir, "policy.json")
	if _, err := os.Stat(policyPath); err != nil {
		os.WriteFile(policyPath, []byte(`{"default":[{"type":"insecureAcceptAnything"}]}`+"\n"), 0644)
	}

	// registries.conf: enable short-name resolution via docker.io
	registriesPath := filepath.Join(dir, "registries.conf")
	if _, err := os.Stat(registriesPath); err != nil {
		os.WriteFile(registriesPath, []byte("unqualified-search-registries = [\"docker.io\"]\n"), 0644)
	}
}

// cmdForward sets up port forwarding from the host into the seki sandbox.
func cmdForward() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: seki forward <port>")
		os.Exit(1)
	}

	port, err := strconv.Atoi(os.Args[2])
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintf(os.Stderr, "seki forward: invalid port: %s\n", os.Args[2])
		os.Exit(1)
	}

	sock, err := socket.Connect(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki forward: %v\n", err)
		os.Exit(1)
	}
	defer sock.Close()

	sock.Emit(socket.Event{Type: "forward", Port: port})

	deadline := time.After(5 * time.Second)
	for {
		done := make(chan struct{})
		var e socket.Event
		var ok bool
		go func() {
			ok = sock.Next()
			if ok {
				e, _ = sock.Event()
			}
			close(done)
		}()

		select {
		case <-done:
			if !ok {
				fmt.Fprintln(os.Stderr, "seki forward: connection closed")
				os.Exit(1)
			}
			if e.Type == "forward_done" && e.Port == port {
				fmt.Printf("forwarding guest:%d → localhost:%d\n", port, e.HostPort)
				return
			}
			if e.Type == "forward_error" && e.Port == port {
				fmt.Fprintf(os.Stderr, "seki forward: %s\n", e.Error)
				os.Exit(1)
			}
		case <-deadline:
			fmt.Fprintln(os.Stderr, "seki forward: timeout waiting for response")
			os.Exit(1)
		}
	}
}

func cmdHostPort() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: seki host-port add <port>")
		fmt.Fprintln(os.Stderr, "       seki host-port remove <port>")
		fmt.Fprintln(os.Stderr, "       seki host-port list")
		os.Exit(1)
	}

	switch os.Args[2] {
	case "list":
		rs, err := rules.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki host-port: %v\n", err)
			os.Exit(1)
		}
		if len(rs.HostPorts) == 0 {
			fmt.Println("no host ports configured")
			return
		}
		for _, p := range rs.HostPorts {
			fmt.Println(p)
		}

	case "add":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: seki host-port add <port>")
			os.Exit(1)
		}
		port, err := strconv.Atoi(os.Args[3])
		if err != nil || port < 1 || port > 65535 {
			fmt.Fprintf(os.Stderr, "seki host-port: invalid port: %s\n", os.Args[3])
			os.Exit(1)
		}
		if os.Getenv("SEKI_ACTIVE") == "1" {
			// Inside sandbox: send event to parent (rules.json is read-only here)
			sock, err := socket.Connect(false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "seki host-port: %v\n", err)
				os.Exit(1)
			}
			defer sock.Close()
			sock.Emit(socket.Event{Type: "host_port_add", Port: port})
			fmt.Printf("host port %d added (live)\n", port)
		} else {
			// Outside sandbox: write directly + notify running sessions
			rs, err := rules.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "seki host-port: %v\n", err)
				os.Exit(1)
			}
			for _, p := range rs.HostPorts {
				if p == port {
					fmt.Printf("host port %d already configured\n", port)
					return
				}
			}
			rs.HostPorts = append(rs.HostPorts, port)
			if err := rs.Save(); err != nil {
				fmt.Fprintf(os.Stderr, "seki host-port: %v\n", err)
				os.Exit(1)
			}
			// Notify running sessions
			paths, _ := socket.SockGlob()
			for _, p := range paths {
				if c, err := socket.ConnectPath(p); err == nil {
					c.Emit(socket.Event{Type: "host_port_add", Port: port})
					c.Close()
				}
			}
			fmt.Printf("added host port %d\n", port)
		}

	case "remove":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: seki host-port remove <port>")
			os.Exit(1)
		}
		port, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "seki host-port: invalid port: %s\n", os.Args[3])
			os.Exit(1)
		}
		if os.Getenv("SEKI_ACTIVE") == "1" {
			sock, err := socket.Connect(false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "seki host-port: %v\n", err)
				os.Exit(1)
			}
			defer sock.Close()
			sock.Emit(socket.Event{Type: "host_port_remove", Port: port})
			fmt.Printf("host port %d removed\n", port)
		} else {
			rs, err := rules.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "seki host-port: %v\n", err)
				os.Exit(1)
			}
			found := false
			for i, p := range rs.HostPorts {
				if p == port {
					rs.HostPorts = append(rs.HostPorts[:i], rs.HostPorts[i+1:]...)
					found = true
					break
				}
			}
			if !found {
				fmt.Fprintf(os.Stderr, "seki host-port: port %d not configured\n", port)
				os.Exit(1)
			}
			if err := rs.Save(); err != nil {
				fmt.Fprintf(os.Stderr, "seki host-port: %v\n", err)
				os.Exit(1)
			}
			paths, _ := socket.SockGlob()
			for _, p := range paths {
				if c, err := socket.ConnectPath(p); err == nil {
					c.Emit(socket.Event{Type: "host_port_remove", Port: port})
					c.Close()
				}
			}
			fmt.Printf("removed host port %d\n", port)
		}

	default:
		fmt.Fprintf(os.Stderr, "seki host-port: unknown subcommand %q\n", os.Args[2])
		os.Exit(1)
	}
}

// slirpAPICall sends a JSON request to the slirp4netns API socket and returns the response.
func slirpAPICall(apiSock string, req map[string]interface{}) (map[string]interface{}, error) {
	conn, err := net.Dial("unix", apiSock)
	if err != nil {
		return nil, fmt.Errorf("connect to slirp4netns API: %w", err)
	}
	defer conn.Close()

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	// slirp4netns requires shutdown(SHUT_WR) after sending
	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		desc, _ := errObj["desc"].(string)
		return nil, fmt.Errorf("%s", desc)
	}
	return resp, nil
}

// mountTmpfsPreserving mounts a tmpfs on dir while preserving existing
// entries. It opens file descriptors to the original children before
// mounting tmpfs (which shadows them), then bind-mounts each one back
// via /proc/self/fd/<n>.
func mountTmpfsPreserving(dir string) {
	entries, _ := os.ReadDir(dir)

	// Open fds to each top-level entry BEFORE the tmpfs mount shadows them.
	type preserved struct {
		name  string
		fd    int
		isDir bool
	}
	var keep []preserved
	for _, e := range entries {
		src := filepath.Join(dir, e.Name())
		fd, err := syscall.Open(src, unix.O_PATH|syscall.O_NOFOLLOW, 0)
		if err != nil {
			continue
		}
		keep = append(keep, preserved{name: e.Name(), fd: fd, isDir: e.IsDir()})
	}

	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		fmt.Fprintf(os.Stderr, "seki __ns-exec: mount tmpfs %s: %v\n", dir, err)
		for _, k := range keep {
			syscall.Close(k.fd)
		}
		return
	}

	// Bind-mount each preserved entry back into the fresh tmpfs.
	for _, k := range keep {
		dst := filepath.Join(dir, k.name)
		if k.isDir {
			os.MkdirAll(dst, 0755)
		} else {
			f, err := os.Create(dst)
			if err != nil {
				syscall.Close(k.fd)
				continue
			}
			f.Close()
		}
		src := fmt.Sprintf("/proc/self/fd/%d", k.fd)
		if err := syscall.Mount(src, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			fmt.Fprintf(os.Stderr, "seki __ns-exec: bind-mount %s -> %s: %v\n", src, dst, err)
		}
		syscall.Close(k.fd)
	}
}
