package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/kr9ly/seki/internal/logger"
	"github.com/kr9ly/seki/internal/netns"
	"github.com/kr9ly/seki/internal/rules"
	"github.com/kr9ly/seki/internal/socket"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: seki <command> [args...]")
		fmt.Fprintln(os.Stderr, "commands: exec, log, rules, check, query, watch, mode")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "exec":
		cmdExec()
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

	// Run user command as subprocess
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "SEKI_ACTIVE=1")

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "seki: exec %v: %v\n", args[0], err)
		os.Exit(1)
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

func cmdWatch() {
	client, err := socket.Connect(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki watch: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

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

	// Approval queue state (local mirror)
	type queueItem struct {
		domain  string
		dest    string
		command string // non-empty for command approvals
	}
	var queue []queueItem
	var queueMu sync.Mutex

	// Set terminal to raw mode for keyboard input
	oldState, rawErr := enableRawMode()
	if rawErr == nil {
		defer restoreTerminal(oldState)
	}

	renderQueue := func() {
		queueMu.Lock()
		defer queueMu.Unlock()
		if len(queue) == 0 {
			return
		}
		fmt.Printf("\r%s── approval queue (%d) ──%s\n", dim, len(queue), reset)
		for i, item := range queue {
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
				fmt.Printf("%s%s — %s[a]%sllow %s[d]%seny%s\n", prefix, label, bold, reset, bold, reset, reset)
			} else {
				fmt.Printf("%s%s\n", prefix, label)
			}
		}
	}

	// Event channel (recreated on reconnect)
	events := make(chan socket.Event, 100)
	startEventReader := func(c *socket.Client) chan socket.Event {
		ch := make(chan socket.Event, 100)
		go func() {
			for c.Next() {
				e, err := c.Event()
				if err != nil {
					continue
				}
				ch <- e
			}
			close(ch)
		}()
		return ch
	}
	events = startEventReader(client)

	// Read keyboard in background
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

	fmt.Printf("%sseki watch%s — connected, waiting for events...\n\n", bold, reset)

	for {
		select {
		case e, ok := <-events:
			if !ok {
				client.Close()
				fmt.Printf("\n%sseki exec disconnected. waiting for reconnect...%s\n", dim, reset)
				queueMu.Lock()
				queue = nil
				queueMu.Unlock()
				client, err = socket.Connect(true)
				if err != nil {
					fmt.Fprintf(os.Stderr, "seki watch: %v\n", err)
					return
				}
				events = startEventReader(client)
				fmt.Printf("%sreconnected.%s\n\n", bold, reset)
				continue
			}

			switch e.Type {
			case "status":
				mode := "enforce"
				if e.LearningMode {
					mode = "learning"
				}
				fmt.Printf("%ssession: %s  mode: %s%s\n", dim, e.Session, mode, reset)

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
				fmt.Printf("%sdns%s  %s (%s)%s%s\n", color, reset, e.Domain, e.QType, suffix, tag)

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
				fmt.Printf("%stcp%s  %s%s%s\n", color, reset, label, suffix, tag)

			case "approval":
				queueMu.Lock()
				queue = append(queue, queueItem{domain: e.Domain, dest: e.Dest})
				queueMu.Unlock()
				renderQueue()

			case "approve":
				queueMu.Lock()
				for i, item := range queue {
					if item.domain == e.Domain && item.command == "" {
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				queueMu.Unlock()
				fmt.Printf("%s✓ approved: %s%s\n", green, e.Domain, reset)
				renderQueue()

			case "deny":
				queueMu.Lock()
				for i, item := range queue {
					if item.domain == e.Domain && item.command == "" {
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				queueMu.Unlock()
				fmt.Printf("%s✗ denied: %s%s\n", red, e.Domain, reset)
				renderQueue()

			case "cmd":
				tag := ""
				if e.Tag != "" {
					tag = dim + " [" + e.Tag + "]" + reset
				}
				fmt.Printf("%scmd%s  %s%s\n", dim, reset, e.Command, tag)

			case "cmd_approval":
				queueMu.Lock()
				queue = append(queue, queueItem{command: e.Command})
				queueMu.Unlock()
				fmt.Printf("%scmd%s  %s — %s⏳ pending%s\n", cyan, reset, e.Command, cyan, reset)
				renderQueue()

			case "cmd_approve":
				queueMu.Lock()
				for i, item := range queue {
					if item.command == e.Command {
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				queueMu.Unlock()
				fmt.Printf("%s✓ approved cmd: %s%s\n", green, e.Command, reset)
				renderQueue()

			case "cmd_deny":
				queueMu.Lock()
				for i, item := range queue {
					if item.command == e.Command {
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				queueMu.Unlock()
				fmt.Printf("%s✗ denied cmd: %s%s\n", red, e.Command, reset)
				renderQueue()
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
			case 'a', 'A':
				if first.command != "" {
					client.Emit(socket.Event{Type: "cmd_approve", Command: first.command})
				} else {
					client.Emit(socket.Event{Type: "approve", Domain: first.domain})
					saveRule(first.domain, rules.Allow)
				}
			case 'd', 'D':
				if first.command != "" {
					client.Emit(socket.Event{Type: "cmd_deny", Command: first.command})
				} else {
					client.Emit(socket.Event{Type: "deny", Domain: first.domain})
					saveRule(first.domain, rules.Deny)
				}
			}
		}
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
		})

		timeout := time.After(30 * time.Second)
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

// argsAfterSep returns the arguments after "--".
// If no "--" is found, returns all arguments.
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
