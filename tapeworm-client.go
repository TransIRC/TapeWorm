// client/main.go
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/TransIRC/cesium-core"
)

const (
	// DnsServerAddress is the address of the DNS tunnel server. Update this with your server's IP and port.
	DnsServerAddress = "0.0.0.0:53"
	// TunnelDomain is the domain used for DNS tunneling. Update this with your server's configured domain.
	TunnelDomain = "sub.domain.tld"
	// TunnelPassword is the password for the DNS tunnel. Ensure this matches your server's password.
	TunnelPassword = "yourpassword123"

	// ReadTimeout is the read timeout for the SSH session.
	ReadTimeout = 10 * time.Second
	// WriteTimeout is the write timeout for the SSH session.
	WriteTimeout = 10 * time.Second
)

// REMOVED: func getTerminalSize() (width, height int, err error)
// REMOVED: func setupResizeHandler(sigChan chan os.Signal)

func main() {
	log.Println("Starting DNS-tunneled SSH client...")

	fmt.Print("SSH Username: ")
	var sshUser string
	_, err := fmt.Scanln(&sshUser)
	if err != nil {
		log.Fatalf("Failed to read username: %v", err)
	}

	var dnsTun *cesiumcore.DnsTunnelConn

	const maxRetries = 5
	for i := 0; i < maxRetries; i++ {
		log.Printf("Attempting to establish DNS tunnel (retry %d/%d)...", i+1, maxRetries)
		// Use the NewDnsTunnelConn from cesium-core, passing the domain and password.
		dnsTun, err = cesiumcore.NewDnsTunnelConn(DnsServerAddress, TunnelDomain, TunnelPassword)
		if err != nil {
			log.Printf("DNS tunnel establishment failed: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		log.Println("DNS tunnel established. Connecting to SSH...")
		config := &ssh.ClientConfig{
			User: sshUser,
			Auth: []ssh.AuthMethod{
				ssh.PasswordCallback(func() (string, error) {
					fmt.Print("SSH Password: ")
					// Use golang.org/x/term for password reading as it's cross-platform
					password, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						return "", err
					}
					return string(password), nil
				}),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         30 * time.Second,
		}

		sshConn, chans, reqs, err := ssh.NewClientConn(dnsTun, "", config)
		if err == nil {
			client := ssh.NewClient(sshConn, chans, reqs)

			session, err := client.NewSession()
			if err != nil {
				log.Printf("Session creation failed: %v", err)
				client.Close()
				dnsTun.Close()
				time.Sleep(1 * time.Second)
				continue
			}

			session.Stdout = os.Stdout
			session.Stderr = os.Stderr
			session.Stdin = os.Stdin

			// Get initial terminal size using the OS-specific function
			var width, height int
			// getTerminalSize now consistently returns an error, even if nil for Unix.
			width, height = getTerminalSize()
			if err != nil {
				log.Printf("Failed to get terminal size: %v, using defaults.", err)
				width, height = 80, 40 // Fallback
			}
			// Ensure valid dimensions, preventing issues if getTerminalSize returns 0 for some reason.
			if width == 0 {
				width = 80
			}
			if height == 0 {
				height = 40
			}

			// Keep raw terminal state setup as it's cross-platform with golang.org/x/term
			oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
			if err != nil {
				log.Printf("Failed to set raw terminal: %v", err)
				session.Close()
				client.Close()
				dnsTun.Close()
				time.Sleep(1 * time.Second)
				continue
			}
			defer term.Restore(int(os.Stdin.Fd()), oldState)

			modes := ssh.TerminalModes{
				ssh.ECHO:          0,     // Disable echoing
				ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
				ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
			}

			// Request PTY with dynamic dimensions and a common terminal type
			if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
				log.Printf("PTY request failed: %v", err)
				session.Close()
				client.Close()
				dnsTun.Close()
				time.Sleep(1 * time.Second)
				continue
			}

			// Handle window resizing
			resizeSig := make(chan os.Signal, 1)
			setupResizeHandler(resizeSig) // Call the OS-specific function

			go func() {
				// The resize handler loop should check for a way to get the size
				// that is appropriate for the OS.
				// Since getTerminalSize now returns an error, we need to handle it.
				for range resizeSig { // Listen on the channel for resize signals
					w, h := getTerminalSize() // Use the OS-specific getTerminalSize
					if err != nil {
						log.Printf("Error getting window size: %v", err)
						continue
					}
					// Only send window change if dimensions are valid (not zero)
					if w > 0 && h > 0 {
						err = session.WindowChange(h, w)
						if err != nil {
							log.Printf("Error sending window change: %v", err)
						}
					}
				}
			}()
			defer signal.Stop(resizeSig) // Stop listening for signals when done
			defer close(resizeSig)       // Close the channel

			if err := session.Shell(); err != nil {
				log.Printf("Shell start failed: %v", err)
				session.Close()
				client.Close()
				dnsTun.Close()
				time.Sleep(1 * time.Second)
				continue
			}

			log.Println("SSH session started. Type 'exit' to quit.")
			if err := session.Wait(); err != nil {
				log.Printf("Session ended: %v", err)
			}

			session.Close()
			client.Close()
			dnsTun.Close()
			return
		}

		log.Printf("SSH connection attempt %d failed: %v", i+1, err)
		dnsTun.Close()
		time.Sleep(1 * time.Second)
	}
	log.Fatalf("SSH connection failed after all retries.")
}
