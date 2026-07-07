//go:build darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// enableRawMode puts the terminal into raw mode for single-character input.
// darwin uses the BSD termios ioctls (TIOCGETA/TIOCSETA) instead of
// Linux's TCGETS/TCSETS.
func enableRawMode() (*unix.Termios, error) {
	fd := int(os.Stdin.Fd())
	oldState, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return nil, err
	}
	newState := *oldState
	newState.Lflag &^= unix.ICANON | unix.ECHO
	newState.Cc[unix.VMIN] = 1
	newState.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &newState); err != nil {
		return nil, err
	}
	return oldState, nil
}

// restoreTerminal restores the terminal to its previous state.
func restoreTerminal(state *unix.Termios) {
	unix.IoctlSetTermios(int(os.Stdin.Fd()), unix.TIOCSETA, state)
}
