package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/kr9ly/seki/internal/logger"
	"github.com/kr9ly/seki/internal/netns"
	"github.com/kr9ly/seki/internal/rules"
	"github.com/kr9ly/seki/internal/socket"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: seki <command> [args...]")
		fmt.Fprintln(os.Stderr, "commands: exec, log, rules, query, watch, mode")
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
	case "query":
		fmt.Fprintln(os.Stderr, "seki query: not yet implemented")
		os.Exit(1)
	case "watch":
		cmdWatch()
	case "mode":
		fmt.Fprintln(os.Stderr, "seki mode: not yet implemented")
		os.Exit(1)
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
	cmd.Env = os.Environ()

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
		reset  = "\033[0m"
		green  = "\033[32m"
		yellow = "\033[33m"
		red    = "\033[31m"
		dim    = "\033[2m"
		bold   = "\033[1m"
	)

	fmt.Fprintln(os.Stderr, bold+"seki watch"+reset+" — connected, waiting for events...\n")

	for client.Next() {
		e, err := client.Event()
		if err != nil {
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
		}
	}

	fmt.Fprintln(os.Stderr, "\nseki exec disconnected.")
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
			fmt.Printf("  %-6s %s%s\n", r.Action, r.Match, tag)
		}

	case "add":
		// seki rules add "*.github.com" --allow --tag git
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: seki rules add <match> --allow|--deny [--tag <tag>]")
			os.Exit(1)
		}
		match := os.Args[3]
		action := rules.Allow
		tag := ""
		for i := 4; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--allow":
				action = rules.Allow
			case "--deny":
				action = rules.Deny
			case "--tag":
				if i+1 < len(os.Args) {
					tag = os.Args[i+1]
					i++
				}
			}
		}
		rs.AddRule(match, action, tag)
		if err := rs.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "seki rules: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("added: %s %s\n", action, match)

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
