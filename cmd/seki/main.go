package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/kr9ly/seki/internal/netns"
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
		fmt.Fprintln(os.Stderr, "seki log: not yet implemented")
		os.Exit(1)
	case "rules":
		fmt.Fprintln(os.Stderr, "seki rules: not yet implemented")
		os.Exit(1)
	case "query":
		fmt.Fprintln(os.Stderr, "seki query: not yet implemented")
		os.Exit(1)
	case "watch":
		fmt.Fprintln(os.Stderr, "seki watch: not yet implemented")
		os.Exit(1)
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

	// ChildSetup returns the redirect proxy which must stay alive
	// while the user command runs (so we can't syscall.Exec).
	rp, err := netns.ChildSetup()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki: namespace setup failed: %v\n", err)
		os.Exit(1)
	}
	defer rp.Close()

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
		fmt.Fprintf(os.Stderr, "seki: %v\n", err)
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
