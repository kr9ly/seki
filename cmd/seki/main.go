package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: seki <command> [args...]")
		fmt.Fprintln(os.Stderr, "commands: exec, log, rules, query, watch, mode")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "exec":
		fmt.Fprintln(os.Stderr, "seki exec: not yet implemented")
		os.Exit(1)
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
