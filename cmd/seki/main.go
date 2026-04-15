package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kr9ly/seki/internal/credential"
	"github.com/kr9ly/seki/internal/logger"
	"github.com/kr9ly/seki/internal/netns"
	"github.com/kr9ly/seki/internal/rules"
	"github.com/kr9ly/seki/internal/socket"
	"golang.org/x/sys/unix"
)

func main() {
	// When bind-mounted over /usr/bin/newuidmap or /usr/bin/newgidmap,
	// argv[0] identifies which helper to run. This replaces the setuid
	// helpers (whose setuid bit is ignored inside user namespaces) with
	// direct writes using ambient CAP_SETUID/CAP_SETGID.
	switch filepath.Base(os.Args[0]) {
	case "newuidmap":
		cmdNewUIDMap()
		return
	case "newgidmap":
		cmdNewGIDMap()
		return
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: seki <command> [args...]")
		fmt.Fprintln(os.Stderr, "commands: exec, log, rules, check, query, watch, mode, credential, forward, host-port")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "exec":
		cmdExec()
	case "__ns-setup":
		cmdNsSetup()
	case "__ns-exec":
		cmdNsExec()
	case "__child":
		cmdChild()
	case "log":
		cmdLog()
	case "rules":
		cmdRules()
	case "check":
		cmdCheck()
	case "query":
		cmdQuery()
	case "watch":
		cmdWatch()
	case "mode":
		cmdMode()
	case "hook":
		cmdHook()
	case "credential":
		cmdCredential()
	case "emit":
		cmdEmit()
	case "forward":
		cmdForward()
	case "host-port":
		cmdHostPort()
	default:
		fmt.Fprintf(os.Stderr, "seki: unknown command %q\n", os.Args[1])
		os.Exit(1)
	}
}

func cmdExec() {
	args := argsAfterSep(os.Args[2:])
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: seki exec [--learning] -- <command> [args...]")
		os.Exit(1)
	}

	sb, err := netns.Exec(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki exec: %v\n", err)
		os.Exit(1)
	}
	defer sb.Close()

	if err := sb.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "seki exec: %v\n", err)
		os.Exit(1)
	}
}

// cmdNsSetup is an intermediate process for setting up multi-entry uid/gid maps.
// It runs in the new user namespace with uid 65534 (no capabilities needed).
// It waits for the parent to call newuidmap/newgidmap, then re-execs as __child.
// The re-exec triggers capability recalculation with uid_map set, giving __child
// full capabilities as uid 0.
//
// fd layout:
//   fd 3 = sync pipe (passed through to __child for slirp4netns readiness)
//   fd 4 = mapReady pipe (read by this process; closed before re-exec)
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

	// Exec user command (ambient caps survive this exec)
	path, err := exec.LookPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki __ns-exec: %v\n", err)
		os.Exit(127)
	}
	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "seki __ns-exec: exec %v: %v\n", args[0], err)
		os.Exit(1)
	}
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
		cmd.SysProcAttr = &syscall.SysProcAttr{
			// CLONE_NEWNS: needed for tmpfs mounts and bind-mounting newuidmap wrapper
			Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
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

		if err := cmd.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			fmt.Fprintf(os.Stderr, "seki: exec %v: %v\n", args[0], err)
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

		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			fmt.Fprintf(os.Stderr, "seki: exec %v: %v\n", args[0], err)
			os.Exit(1)
		}
	}
}

func cmdLog() {
	var domain string
	limit := 100

	// Parse flags: --domain <domain>, --limit <n>
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--domain":
			if i+1 < len(os.Args) {
				domain = os.Args[i+1]
				i++
			}
		case "--limit":
			if i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &limit)
				i++
			}
		}
	}

	log, err := logger.OpenReadOnly()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki log: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	entries, err := log.Query(domain, limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki log: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no log entries found")
		return
	}

	for _, e := range entries {
		switch e.Kind {
		case "dns":
			fmt.Printf("%s  dns  %s (%s)\n", e.Time, e.Domain, e.Extra)
		case "tcp":
			if e.Domain != "" {
				fmt.Printf("%s  tcp  %s (%s)\n", e.Time, e.Dest, e.Domain)
			} else {
				fmt.Printf("%s  tcp  %s\n", e.Time, e.Dest)
			}
		}
	}
}

// tuiState holds the terminal dimensions and derived scroll region boundaries.
type tuiState struct {
	rows      int // total terminal rows
	cols      int // total terminal columns (unused for scroll region but useful)
	logBottom int // last row of log scroll region (1-based)
	queueRows int // number of rows reserved for the queue area (including separator)
}

// termSize queries the terminal size. Falls back to 24x80 if unavailable.
func termSize() (rows, cols int) {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Row == 0 {
		return 24, 80
	}
	return int(ws.Row), int(ws.Col)
}

// buildTUI computes tuiState for the given queue length and terminal size.
// Queue area: 1 (separator) + max(len(queue), 1) + 1 (hint or "no pending") rows.
func buildTUI(rows, cols, queueLen int) tuiState {
	queueItems := queueLen
	if queueItems == 0 {
		queueItems = 1 // "no pending" line
	}
	queueRows := 1 + queueItems + 1 // separator + items + hint line
	logBottom := rows - queueRows
	if logBottom < 3 {
		logBottom = 3
	}
	return tuiState{
		rows:      rows,
		cols:      cols,
		logBottom: logBottom,
		queueRows: rows - logBottom,
	}
}

// applyScrollRegion sets the ANSI scroll region to [1, logBottom] and moves
// the cursor to the bottom of the log region so new lines scroll naturally.
func applyScrollRegion(tui tuiState) {
	// Set scroll region
	fmt.Printf("\033[1;%dr", tui.logBottom)
	// Move cursor to bottom of scroll region
	fmt.Printf("\033[%d;1H", tui.logBottom)
}

// clearQueueArea erases lines from logBottom+1 to rows.
func clearQueueArea(tui tuiState) {
	for r := tui.logBottom + 1; r <= tui.rows; r++ {
		fmt.Printf("\033[%d;1H\033[2K", r)
	}
}

// saveCursor / restoreCursor use ANSI DECSC/DECRC.
func saveCursor()    { fmt.Print("\0337") }
func restoreCursor() { fmt.Print("\0338") }

func cmdWatch() {
	const (
		reset   = "\033[0m"
		green   = "\033[32m"
		yellow  = "\033[33m"
		red     = "\033[31m"
		cyan    = "\033[36m"
		dim     = "\033[2m"
		bold    = "\033[1m"
		inverse = "\033[7m"
	)

	type queueItem struct {
		domain  string
		dest    string
		command string
		cwd     string
		client  *socket.Client // source session for routing approve/deny
	}
	type taggedEvent struct {
		event  socket.Event
		client *socket.Client
	}

	var queue []queueItem
	var queueMu sync.Mutex

	events := make(chan taggedEvent, 100)
	connected := make(map[string]*socket.Client) // path -> client
	var connMu sync.Mutex

	// Connect to a socket and start reading events
	attachSession := func(path string) {
		connMu.Lock()
		if _, ok := connected[path]; ok {
			connMu.Unlock()
			return
		}
		c, err := socket.ConnectPath(path)
		if err != nil {
			connMu.Unlock()
			return
		}
		connected[path] = c
		connMu.Unlock()

		events <- taggedEvent{event: socket.Event{Type: "session_connect", Session: filepath.Base(path)}, client: c}

		go func() {
			for c.Next() {
				e, err := c.Event()
				if err != nil {
					continue
				}
				events <- taggedEvent{event: e, client: c}
			}
			// Disconnected
			connMu.Lock()
			delete(connected, path)
			connMu.Unlock()
			c.Close()
			events <- taggedEvent{event: socket.Event{Type: "session_disconnect"}, client: c}
		}()
	}

	// Scan for sockets and attach
	scanSockets := func() {
		paths, _ := socket.SockGlob()
		for _, p := range paths {
			attachSession(p)
		}
	}

	// Set terminal to raw mode
	oldState, rawErr := enableRawMode()
	if rawErr == nil {
		defer func() {
			// Restore scroll region to full screen before exiting
			rows, _ := termSize()
			fmt.Printf("\033[1;%dr", rows)
			fmt.Printf("\033[%d;1H\n", rows)
			restoreTerminal(oldState)
		}()
	}

	// tui holds current layout; protected by queueMu for simplicity.
	rows, cols := termSize()
	tui := buildTUI(rows, cols, 0)

	// Initialize scroll region
	// Clear screen first, then set up regions.
	fmt.Print("\033[2J\033[H") // clear screen, home
	applyScrollRegion(tui)
	clearQueueArea(tui)

	// logPrint outputs a line into the log scroll region.
	// It saves the cursor, moves into the scroll region, prints, then restores.
	logPrint := func(format string, args ...interface{}) {
		saveCursor()
		// Move to bottom of log region to let scroll region do the scrolling
		fmt.Printf("\033[%d;1H", tui.logBottom)
		fmt.Printf("\r\n"+format, args...)
		restoreCursor()
	}

	// cwdTag returns a short project-name prefix from an event's Cwd field.
	cwdTag := func(cwd string) string {
		if cwd == "" {
			return ""
		}
		return dim + "[" + filepath.Base(cwd) + "]" + reset + " "
	}

	// renderQueueArea redraws the fixed bottom area.
	// Must be called with queueMu held.
	renderQueueArea := func() {
		newTui := buildTUI(tui.rows, tui.cols, len(queue))
		if newTui.logBottom != tui.logBottom {
			// Layout changed: update scroll region
			oldBottom := tui.logBottom
			tui = newTui
			applyScrollRegion(tui)
			if tui.logBottom > oldBottom {
				// Queue shrank: old separator/items now in log region — erase them
				for r := oldBottom + 1; r <= tui.logBottom; r++ {
					fmt.Printf("\033[%d;1H\033[2K", r)
				}
			}
		}
		clearQueueArea(tui)

		row := tui.logBottom + 1

		// Separator line
		fmt.Printf("\033[%d;1H%s%s%s", row, dim, strings.Repeat("─", 40), reset)
		row++

		if len(queue) == 0 {
			fmt.Printf("\033[%d;1H%sno pending approvals%s", row, dim, reset)
		} else {
			fmt.Printf("\033[%d;1H%s── approval queue (%d) ──%s", row, dim, len(queue), reset)
			row++
			for i, item := range queue {
				if row > tui.rows {
					break
				}
				prefix := "  "
				if i == 0 {
					prefix = inverse + "❯ " + reset
				}
				var label string
				if item.command != "" {
					label = "cmd: " + item.command
				} else {
					label = item.domain
					if item.dest != "" && item.dest != item.domain {
						label = item.dest + " (" + item.domain + ")"
					}
				}
				if i == 0 {
					fmt.Printf("\033[%d;1H%s%s — %s[a]%sllow %s[p]%sass %s[d]%seny (^A/^P/^D)%s",
						row, prefix, label, bold, reset, bold, reset, bold, reset, reset)
				} else {
					fmt.Printf("\033[%d;1H%s%s", row, prefix, label)
				}
				row++
			}
		}

		// Return cursor to log region bottom so next logPrint works correctly
		fmt.Printf("\033[%d;1H", tui.logBottom)
	}

	// Keyboard input
	keys := make(chan byte, 10)
	if rawErr == nil {
		go func() {
			buf := make([]byte, 1)
			for {
				n, err := os.Stdin.Read(buf)
				if err != nil || n == 0 {
					return
				}
				keys <- buf[0]
			}
		}()
	}

	// SIGWINCH handler: resize TUI
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			queueMu.Lock()
			r, c := termSize()
			tui = buildTUI(r, c, len(queue))
			fmt.Print("\033[2J\033[H") // clear entire screen on resize
			applyScrollRegion(tui)
			renderQueueArea()
			queueMu.Unlock()
		}
	}()

	// Periodic scanner for new sessions
	go func() {
		for {
			scanSockets()
			time.Sleep(2 * time.Second)
		}
	}()

	logPrint("%sseki watch%s — scanning for sessions...", bold, reset)

	for {
		select {
		case te := <-events:
			e := te.event

			switch e.Type {
			case "session_connect":
				logPrint("%sconnected: %s%s", dim, e.Session, reset)

			case "emit":
				logPrint("%s%s» %s%s", cwdTag(e.Cwd), dim, e.Message, reset)

			case "session_disconnect":
				// Remove queue items from this session
				queueMu.Lock()
				filtered := queue[:0]
				for _, item := range queue {
					if item.client != te.client {
						filtered = append(filtered, item)
					}
				}
				queue = filtered
				logPrint("%ssession disconnected.%s", dim, reset)
				renderQueueArea()
				queueMu.Unlock()

			case "status":
				mode := "enforce"
				if e.LearningMode {
					mode = "learning"
				}
				logPrint("%s%ssession: %s  mode: %s%s", cwdTag(e.Cwd), dim, e.Session, mode, reset)

			case "dns":
				color := green
				suffix := ""
				if e.Learned {
					color = yellow
					suffix = " — would deny"
				} else if e.Action == "deny" {
					color = red
					suffix = " — DENIED"
				}
				tag := ""
				if e.Tag != "" {
					tag = dim + " [" + e.Tag + "]" + reset
				}
				logPrint("%s%sdns%s  %s (%s)%s%s", cwdTag(e.Cwd), color, reset, e.Domain, e.QType, suffix, tag)

			case "tcp":
				color := green
				suffix := ""
				if e.Learned {
					color = yellow
					suffix = " — would deny"
				} else if e.Action == "deny" {
					color = red
					suffix = " — DENIED"
				} else if e.Action == "prompt" {
					color = cyan
					suffix = " — ⏳ pending"
				}
				label := e.Dest
				if e.SNI != "" {
					label = e.Dest + " (" + e.SNI + ")"
				}
				tag := ""
				if e.Tag != "" {
					tag = dim + " [" + e.Tag + "]" + reset
				}
				logPrint("%s%stcp%s  %s%s%s", cwdTag(e.Cwd), color, reset, label, suffix, tag)

			case "approval":
				queueMu.Lock()
				queue = append(queue, queueItem{domain: e.Domain, dest: e.Dest, cwd: e.Cwd, client: te.client})
				renderQueueArea()
				queueMu.Unlock()

			case "approve":
				queueMu.Lock()
				cwd := e.Cwd
				for i, item := range queue {
					if item.domain == e.Domain && item.command == "" {
						cwd = item.cwd
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				logPrint("%s%s✓ approved: %s%s", cwdTag(cwd), green, e.Domain, reset)
				renderQueueArea()
				queueMu.Unlock()

			case "deny":
				queueMu.Lock()
				cwd := e.Cwd
				for i, item := range queue {
					if item.domain == e.Domain && item.command == "" {
						cwd = item.cwd
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				logPrint("%s%s✗ denied: %s%s", cwdTag(cwd), red, e.Domain, reset)
				renderQueueArea()
				queueMu.Unlock()

			case "cmd":
				tag := ""
				if e.Tag != "" {
					tag = dim + " [" + e.Tag + "]" + reset
				}
				logPrint("%s%scmd%s  %s%s", cwdTag(e.Cwd), dim, reset, e.Command, tag)

			case "cmd_approval":
				queueMu.Lock()
				queue = append(queue, queueItem{command: e.Command, cwd: e.Cwd, client: te.client})
				logPrint("%s%scmd%s  %s — %s⏳ pending%s", cwdTag(e.Cwd), cyan, reset, e.Command, cyan, reset)
				renderQueueArea()
				queueMu.Unlock()

			case "cmd_approve":
				queueMu.Lock()
				cwd := e.Cwd
				for i, item := range queue {
					if item.command == e.Command {
						cwd = item.cwd
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				logPrint("%s%s✓ approved cmd: %s%s", cwdTag(cwd), green, e.Command, reset)
				renderQueueArea()
				queueMu.Unlock()

			case "cmd_deny":
				queueMu.Lock()
				cwd := e.Cwd
				for i, item := range queue {
					if item.command == e.Command {
						cwd = item.cwd
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				logPrint("%s%s✗ denied cmd: %s%s", cwdTag(cwd), red, e.Command, reset)
				renderQueueArea()
				queueMu.Unlock()
			}

		case key := <-keys:
			queueMu.Lock()
			hasItems := len(queue) > 0
			var first queueItem
			if hasItems {
				first = queue[0]
			}
			queueMu.Unlock()

			if !hasItems {
				continue
			}

			switch key {
			case 'a', 'A', 0x01: // Ctrl+A: allow (IME-safe)
				if first.command != "" {
					first.client.Emit(socket.Event{Type: "cmd_approve", Command: first.command})
				} else {
					first.client.Emit(socket.Event{Type: "approve", Domain: first.domain})
					saveRule(first.domain, rules.Allow)
				}
			case 'p', 'P', 0x10: // Ctrl+P: pass (IME-safe)
				if first.command != "" {
					first.client.Emit(socket.Event{Type: "cmd_approve", Command: first.command})
				} else {
					first.client.Emit(socket.Event{Type: "approve", Domain: first.domain})
				}
			case 'd', 'D', 0x04: // Ctrl+D: deny (IME-safe)
				if first.command != "" {
					first.client.Emit(socket.Event{Type: "cmd_deny", Command: first.command})
				} else {
					first.client.Emit(socket.Event{Type: "deny", Domain: first.domain})
					saveRule(first.domain, rules.Deny)
				}
			}
		}
	}
}

func cmdEmit() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: seki emit <message>")
		os.Exit(1)
	}
	msg := strings.Join(os.Args[2:], " ")
	const maxLen = 200
	if len(msg) > maxLen {
		msg = msg[:maxLen] + "…"
	}

	cwd, _ := os.Getwd()
	evt := socket.Event{Type: "emit", Message: msg, Cwd: cwd}

	// Inside a sandbox session, send only to our own socket.
	if os.Getenv("SEKI_SOCK") != "" {
		c, err := socket.Connect(false)
		if err != nil {
			return
		}
		c.Emit(evt)
		c.Close()
		return
	}

	// Outside sandbox: broadcast to all sessions (fallback).
	paths, err := socket.SockGlob()
	if err != nil || len(paths) == 0 {
		return
	}
	for _, p := range paths {
		c, err := socket.ConnectPath(p)
		if err != nil {
			continue
		}
		c.Emit(evt)
		c.Close()
	}
}

// saveRule persists an allow/deny decision as a rule.
func saveRule(domain, action string) {
	rs, err := rules.Load()
	if err != nil {
		return
	}
	rs.AddRule(domain, action, "", rules.KindNetwork)
	rs.Save()
}

func cmdRules() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: seki rules <list|add|remove>")
		os.Exit(1)
	}

	rs, err := rules.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki rules: %v\n", err)
		os.Exit(1)
	}

	switch os.Args[2] {
	case "list":
		mode := "enforce"
		if rs.LearningMode {
			mode = "learning"
		}
		fmt.Printf("mode: %s\n\n", mode)
		for _, r := range rs.Rules {
			tag := ""
			if r.Tag != "" {
				tag = " [" + r.Tag + "]"
			}
			kind := ""
			if r.Kind == rules.KindCommand {
				kind = " (command)"
			}
			fmt.Printf("  %-6s %s%s%s\n", r.Action, r.Match, kind, tag)
		}

	case "add":
		// seki rules add "*.github.com" --allow --tag git [--command]
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: seki rules add <match> --allow|--deny|--prompt [--tag <tag>] [--command]")
			os.Exit(1)
		}
		match := os.Args[3]
		action := rules.Allow
		tag := ""
		kind := rules.KindNetwork
		for i := 4; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--allow":
				action = rules.Allow
			case "--deny":
				action = rules.Deny
			case "--prompt":
				action = rules.Prompt
			case "--command":
				kind = rules.KindCommand
			case "--tag":
				if i+1 < len(os.Args) {
					tag = os.Args[i+1]
					i++
				}
			}
		}
		rs.AddRule(match, action, tag, kind)
		if err := rs.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "seki rules: %v\n", err)
			os.Exit(1)
		}
		prefix := ""
		if kind == rules.KindCommand {
			prefix = "[command] "
		}
		fmt.Printf("added: %s%s %s\n", prefix, action, match)

	case "remove":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: seki rules remove <match>")
			os.Exit(1)
		}
		if rs.RemoveRule(os.Args[3]) {
			if err := rs.Save(); err != nil {
				fmt.Fprintf(os.Stderr, "seki rules: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("removed: %s\n", os.Args[3])
		} else {
			fmt.Fprintf(os.Stderr, "rule not found: %s\n", os.Args[3])
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "seki rules: unknown subcommand %q\n", os.Args[2])
		os.Exit(1)
	}
}

func cmdCheck() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: seki check <command>")
		os.Exit(1)
	}
	cmd := strings.Join(os.Args[2:], " ")
	checkCommand(cmd)
}

// checkCommand evaluates a command against rules and blocks if needed.
// Exits with code 2 if blocked, returns normally if allowed.
func checkCommand(cmd string) {
	rs, err := rules.Load()
	if err != nil {
		return // fail open
	}

	res := rs.EvaluateCommand(cmd)
	switch res.Action {
	case rules.Allow:
		return
	case rules.Deny:
		tag := ""
		if res.Rule != nil && res.Rule.Tag != "" {
			tag = " [" + res.Rule.Tag + "]"
		}
		fmt.Fprintf(os.Stderr, "[seki] blocked: %s%s\n", cmd, tag)
		os.Exit(2)
	case rules.Prompt:
		client, err := socket.Connect(false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[seki] blocked (no watch): %s\n", cmd)
			os.Exit(2)
		}
		defer client.Close()

		client.Emit(socket.Event{
			Type:    "cmd_approval",
			Command: cmd,
			Action:  "prompt",
			Cwd:     os.Getenv("SEKI_CWD"),
		})

		approvalTimeout := 30 * time.Second
		if s := os.Getenv("SEKI_APPROVAL_TIMEOUT"); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v > 0 {
				approvalTimeout = time.Duration(v) * time.Second
			}
		}
		timeout := time.After(approvalTimeout)
		events := make(chan socket.Event, 10)
		go func() {
			for client.Next() {
				e, err := client.Event()
				if err != nil {
					continue
				}
				events <- e
			}
			close(events)
		}()

		for {
			select {
			case e, ok := <-events:
				if !ok {
					fmt.Fprintf(os.Stderr, "[seki] blocked (disconnected): %s\n", cmd)
					os.Exit(2)
				}
				if e.Command == cmd {
					switch e.Type {
					case "cmd_approve":
						return
					case "cmd_deny":
						fmt.Fprintf(os.Stderr, "[seki] denied: %s\n", cmd)
						os.Exit(2)
					}
				}
			case <-timeout:
				fmt.Fprintf(os.Stderr, "[seki] blocked (timeout): %s\n", cmd)
				os.Exit(2)
			}
		}
	}
}

func cmdMode() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: seki mode <learning|enforce>")
		os.Exit(1)
	}
	rs, err := rules.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki mode: %v\n", err)
		os.Exit(1)
	}
	switch os.Args[2] {
	case "learning":
		rs.LearningMode = true
	case "enforce":
		rs.LearningMode = false
	default:
		fmt.Fprintf(os.Stderr, "seki mode: unknown mode %q (use learning or enforce)\n", os.Args[2])
		os.Exit(1)
	}
	if err := rs.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "seki mode: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("mode: %s\n", os.Args[2])
}

func cmdQuery() {
	since := 5 * time.Second
	format := "text"

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "--since=") {
			d, err := time.ParseDuration(strings.TrimPrefix(arg, "--since="))
			if err != nil {
				fmt.Fprintf(os.Stderr, "seki query: invalid duration: %v\n", err)
				os.Exit(1)
			}
			since = d
		} else if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
		}
	}

	queryBlocked(since, format)
}

// queryBlocked queries recent blocked events and prints them.
func queryBlocked(since time.Duration, format string) {
	log, err := logger.OpenReadOnly()
	if err != nil {
		return
	}
	defer log.Close()

	entries, err := log.QuerySince(since)
	if err != nil {
		return
	}

	var blocked []logger.Entry
	for _, e := range entries {
		if e.Action != "" && e.Action != rules.Allow {
			blocked = append(blocked, e)
		}
	}

	if len(blocked) == 0 {
		return
	}

	if format == "hook" {
		type key struct{ domain, action string }
		seen := make(map[key]bool)
		var lines []string
		for _, e := range blocked {
			domain := e.Domain
			if domain == "" {
				domain = e.Dest
			}
			k := key{domain, e.Action}
			if seen[k] {
				continue
			}
			seen[k] = true
			switch e.Action {
			case rules.Deny:
				lines = append(lines, fmt.Sprintf("  %s — blocked (denied by rule)", domain))
			case rules.Prompt:
				lines = append(lines, fmt.Sprintf("  %s — blocked (approval required, use seki watch)", domain))
			default:
				lines = append(lines, fmt.Sprintf("  %s — %s", domain, e.Action))
			}
		}
		fmt.Println("[seki] network access was blocked:")
		for _, l := range lines {
			fmt.Println(l)
		}
		return
	}

	for _, e := range blocked {
		domain := e.Domain
		if domain == "" {
			domain = e.Dest
		}
		fmt.Printf("%s  %-4s  %-6s  %s\n", e.Time, e.Kind, e.Action, domain)
	}
}

func cmdHook() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: seki hook <pre-bash|post-bash>")
		os.Exit(1)
	}
	switch os.Args[2] {
	case "pre-bash":
		cmdHookPreBash()
	case "post-bash":
		cmdHookPostBash()
	default:
		fmt.Fprintf(os.Stderr, "seki hook: unknown hook %q\n", os.Args[2])
		os.Exit(1)
	}
}

func cmdHookPreBash() {
	if os.Getenv("SEKI_ACTIVE") == "" {
		return
	}
	var input struct {
		ToolInput struct {
			Command string `json:"command"`
		} `json:"tool_input"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil || input.ToolInput.Command == "" {
		return
	}
	checkCommand(input.ToolInput.Command)
}

func cmdHookPostBash() {
	if os.Getenv("SEKI_ACTIVE") == "" {
		return
	}
	queryBlocked(5*time.Second, "hook")
}

func cmdCredential() {
	// os.Args[2] is the git credential subcommand: get, store, erase
	// Only "get" needs implementation; store/erase are no-ops.
	if len(os.Args) < 3 || os.Args[2] != "get" {
		return
	}

	// Read git credential protocol from stdin (key=value lines, blank line terminates)
	var protocol, host string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			switch k {
			case "protocol":
				protocol = v
			case "host":
				host = v
			}
		}
	}

	if host == "" {
		return
	}

	// Connect to the parent's credential socket server
	sockPath, err := credential.SockPath()
	if err != nil {
		return
	}
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send request
	req := credential.Request{Action: "get", Protocol: protocol, Host: host}
	data, err := json.Marshal(req)
	if err != nil {
		return
	}
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		return
	}

	// Read response
	respScanner := bufio.NewScanner(conn)
	if !respScanner.Scan() {
		return
	}
	var resp credential.Response
	if err := json.Unmarshal(respScanner.Bytes(), &resp); err != nil {
		return
	}
	if resp.Error != "" || resp.Username == "" {
		return
	}

	// Output git credential protocol
	fmt.Printf("protocol=%s\n", protocol)
	fmt.Printf("host=%s\n", host)
	fmt.Printf("username=%s\n", resp.Username)
	fmt.Printf("password=%s\n", resp.Password)
	fmt.Println()
}

// argsAfterSep returns the arguments after "--".
// If no "--" is found, returns all arguments.
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

func argsAfterSep(args []string) []string {
	for i, a := range args {
		if a == "--" {
			return args[i+1:]
		}
	}
	return args
}

// enableRawMode puts the terminal into raw mode for single-character input.
func enableRawMode() (*unix.Termios, error) {
	fd := int(os.Stdin.Fd())
	oldState, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	newState := *oldState
	newState.Lflag &^= unix.ICANON | unix.ECHO
	newState.Cc[unix.VMIN] = 1
	newState.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &newState); err != nil {
		return nil, err
	}
	return oldState, nil
}

// restoreTerminal restores the terminal to its previous state.
func restoreTerminal(state *unix.Termios) {
	unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TCSETS, state)
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
