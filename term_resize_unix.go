//go:build !windows
// +build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
	"golang.org/x/sys/unix"
)

// getTerminalSize returns current terminal width and height
func getTerminalSize() (int, int) {
	ws, err := unix.IoctlGetWinsize(0, unix.TIOCGWINSZ)
	if err != nil {
		return 80, 25 // fallback
	}
	return int(ws.Col), int(ws.Row)
}

// setupResizeHandler sends SIGWINCH signals into resizeChan when terminal is resized
func setupResizeHandler(resizeChan chan os.Signal) {
	signal.Notify(resizeChan, syscall.SIGWINCH)
}
