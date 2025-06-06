//go:build windows
// +build windows

package main

import (
	"log"
	"os"
	"time"

	"golang.org/x/sys/windows" // For Windows API calls
)

// getTerminalSize retrieves the current terminal dimensions on Windows.
// It returns width and height. Errors are logged internally.
func getTerminalSize() (width, height int) {
	var info windows.ConsoleScreenBufferInfo
	handle := windows.Handle(os.Stdout.Fd())
	err := windows.GetConsoleScreenBufferInfo(handle, &info)
	if err != nil {
		log.Printf("Failed to get console screen buffer info: %v. Using default size.", err)
		return 80, 40 // Fallback to default size if an error occurs
	}

	width = int(info.Window.Right - info.Window.Left + 1)
	height = int(info.Window.Bottom - info.Window.Top + 1)
	return width, height
}

// setupResizeHandler for Windows. SIGWINCH is a Unix signal, so this requires a
// different Windows-specific implementation. This function will poll for size changes.
func setupResizeHandler(resizeChan chan os.Signal) {
	// On Windows, there's no direct equivalent to SIGWINCH.
	// We'll simulate a resize signal by polling the console size.
	go func() {
		lastWidth, lastHeight := getTerminalSize()
		for {
			time.Sleep(500 * time.Millisecond) // Poll every 500ms
			currentWidth, currentHeight := getTerminalSize()

			if currentWidth != lastWidth || currentHeight != lastHeight {
				// Send a signal on the channel if size changed
				resizeChan <- os.Interrupt // Using os.Interrupt as a generic signal
				lastWidth, lastHeight = currentWidth, currentHeight
			}
		}
	}()
	log.Println("Note: Terminal resize handling on Windows is simulated by polling console size.")
}
