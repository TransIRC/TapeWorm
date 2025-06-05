//go:build windows
// +build windows

package main

import (
        "fmt"
        "log"
        "os"

        "golang.org/x/sys/windows" // For Windows API calls
)

// getTerminalSize retrieves the current terminal dimensions on Windows.
// It returns width, height, and an error if one occurs.
func getTerminalSize() (width, height int, err error) {
        var info windows.ConsoleScreenBufferInfo
        handle := windows.Handle(os.Stdout.Fd())
        err = windows.GetConsoleScreenBufferInfo(handle, &info)
        if err != nil {
                return 0, 0, fmt.Errorf("failed to get console screen buffer info: %w", err)
        }

        width = int(info.Window.Right - info.Window.Left + 1)
        height = int(info.Window.Bottom - info.Window.Top + 1)
        return width, height, nil
}

// setupResizeHandler for Windows. SIGWINCH is a Unix signal, so this is a no-op or
// would require a different Windows-specific implementation (e.g., ReadConsoleInput).
func setupResizeHandler(resizeChan chan os.Signal) {
        // On Windows, there's no direct equivalent to SIGWINCH.
        // Terminal resizing typically needs to be handled differently,
        // e.g., by polling the console size or using ReadConsoleInput.
        // For now, this is a no-op to allow compilation.
        log.Println("Note: Terminal resize handling (SIGWINCH) is not directly supported on Windows in this manner. No-op.")
        // To prevent the "imported and not used" warning for os/signal if it's the only usage:
        // _ = resizeChan // This line "uses" resizeChan to suppress the warning, but doesn't actually do anything.
        // More robust solution would be to conditionally compile the signal.Notify call based on OS.
        // In this case, we just won't call signal.Notify on Windows.
}
