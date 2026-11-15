//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/kr9ly/seki/internal/netns"
	"golang.org/x/sys/unix"
)

// cmdIsolate runs a command in a fresh network namespace that has only a
// loopback interface.
//
// The namespace has no netfilter rules, so no hook is registered and
// loopback packets skip conntrack and rule evaluation entirely. That is what
// in-sandbox load tests want: the sandbox's own namespace always carries the
// inspection rules, and they cost cycles on every loopback packet. The
// namespace also has no route out, so nothing in it needs inspecting.
//
// The command keeps its uid and gid (they are mapped to themselves in a new
// user namespace) and runs without capabilities. It works inside a seki
// sandbox and outside one.
func cmdIsolate() {
	args := os.Args[2:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: seki isolate [--] <command> [args...]")
		os.Exit(2)
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki isolate: %v\n", err)
		os.Exit(1)
	}

	// A new namespace starts from the kernel defaults. Carry over the
	// values of the namespace we are leaving (netns_sysctls, when inside a
	// sandbox) so that the load test sees the same tuning.
	inner := []string{"__isolate"}
	for key, value := range netns.CurrentNetnsSysctls() {
		inner = append(inner, key+"="+value)
	}
	inner = append(inner, "--")
	inner = append(inner, args...)

	uid, gid := os.Getuid(), os.Getgid()
	cmd := exec.Command(self, inner...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		// The setup step needs CAP_NET_ADMIN over the new namespace. A
		// non-root uid loses its capabilities on exec unless they are
		// ambient. cmdIsolateInner clears it before running the command.
		AmbientCaps: []uintptr{unix.CAP_NET_ADMIN},
		Pdeathsig:   syscall.SIGKILL,
	}

	// Pdeathsig fires when the creating thread exits, so stay on it.
	runtime.LockOSThread()

	// The terminal delivers SIGINT and SIGQUIT to the whole foreground
	// group, so the command gets them directly. Ignore them here and
	// report the command's status. Signals sent to this process alone are
	// forwarded.
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	fwd := make(chan os.Signal, 4)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "seki isolate: %v\n", err)
		os.Exit(1)
	}
	go func() {
		for sig := range fwd {
			cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Wait()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		os.Exit(0)
	case errors.As(err, &exitErr):
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			os.Exit(128 + int(ws.Signal()))
		}
		os.Exit(exitErr.ExitCode())
	default:
		fmt.Fprintf(os.Stderr, "seki isolate: %v\n", err)
		os.Exit(1)
	}
}

// cmdIsolateInner is the setup step inside the new namespaces: bring lo up,
// apply the sysctls, drop CAP_NET_ADMIN and exec the command.
//
// argv: __isolate [key=value ...] -- <command> [args...]
func cmdIsolateInner() {
	// Capabilities are per thread, and exec takes the calling thread's.
	runtime.LockOSThread()

	args := os.Args[2:]
	sysctls := map[string]string{}
	for len(args) > 0 && args[0] != "--" {
		if key, value, ok := strings.Cut(args[0], "="); ok {
			sysctls[key] = value
		}
		args = args[1:]
	}
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "seki isolate: missing command")
		os.Exit(2)
	}
	args = args[1:]

	if err := loopbackUp(); err != nil {
		fmt.Fprintf(os.Stderr, "seki isolate: lo up: %v\n", err)
		os.Exit(1)
	}
	netns.ApplyNetnsSysctls(sysctls)

	// Without an ambient set, exec leaves a non-root uid with no
	// capabilities, so the command cannot change the namespace.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "seki isolate: drop capabilities: %v\n", err)
		os.Exit(1)
	}

	path, err := exec.LookPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "seki isolate: %v\n", err)
		os.Exit(127)
	}
	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "seki isolate: exec %s: %v\n", path, err)
		os.Exit(126)
	}
}

// loopbackUp sets IFF_UP on lo in the current network namespace. It uses
// the ioctl directly so that isolate does not depend on iproute2.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
