package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TransIRC/cesiumlib"
)

// Config holds the server configuration.
type Config struct {
	ListenAddr   string
	TunnelDomain string
	Password     string
	Mode         string
	TargetPort   string
}

// loadConfig loads the server configuration from a specified file path.
func loadConfig(path string) (*Config, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "//") {
			continue // Skip empty lines and comments
		}
		// Remove inline comments
		if idx := strings.Index(line, "//"); idx != -1 {
			line = line[:idx]
			line = strings.TrimSpace(line)
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch key {
			case "listen_addr":
				cfg.ListenAddr = value
			case "tunnel_domain":
				cfg.TunnelDomain = value
			case "password":
				cfg.Password = value
			case "mode":
				cfg.Mode = value
			case "target_port":
				cfg.TargetPort = value
			default:
				log.Printf("Warning: Unknown config key '%s' in %s", key, path)
			}
		}
	}
	// Basic validation and fallback for crucial fields
	if cfg.ListenAddr == "" {
		log.Printf("Config: listen_addr not specified, defaulting to 0.0.0.0:5353")
		cfg.ListenAddr = "0.0.0.0:5353"
	}
	if cfg.TunnelDomain == "" {
		return nil, errors.New("config: tunnel_domain is required")
	}
	if cfg.Password == "" {
		return nil, errors.New("config: password is required")
	}
	if cfg.Mode == "" {
		log.Printf("Config: mode not specified, defaulting to tcp_proxy")
		cfg.Mode = "tcp_proxy"
	} else if cfg.Mode != "tcp_proxy" {
		return nil, errors.New("config: only 'tcp_proxy' mode is supported")
	}
	if cfg.TargetPort == "" {
		return nil, errors.New("config: target_port is required for tcp_proxy mode")
	}
	return cfg, nil
}

// createProxyProtocolHeader generates a PROXY protocol header v1 (TCP4).
func createProxyProtocolHeader(clientIP string, targetPort string) string {
	// For PROXY protocol v1, the source port is arbitrary, so we can use a dummy value like 12345.
	// The destination IP for the PROXY header should be the actual IP of the target service,
	// which is 127.0.0.1 in this case as you're connecting to localhost.
	return fmt.Sprintf("PROXY TCP4 %s 127.0.0.1 12345 %s\r\n", clientIP, targetPort)
}

// handleTunnelConnection is the callback function passed to AcceptServerDnsTunnelConns.
// It receives a net.Conn (which is a *ServerSideDnsTunnelConn) for each client session.
func handleTunnelConnection(tunnelConn net.Conn, config *Config) {
	log.Printf("New DNS tunnel connection established from %s", tunnelConn.RemoteAddr())
	defer tunnelConn.Close() // Ensure the tunnel connection is closed when this handler exits

	// Extract client IP from the tunnel connection's remote address
	clientIP := "127.0.0.1" // Default/fallback IP
	if tcpAddr, ok := tunnelConn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = tcpAddr.IP.String()
	} else if udpAddr, ok := tunnelConn.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = udpAddr.IP.String()
	}

	// Establish connection to the actual target SSH server
	targetAddr := net.JoinHostPort("127.0.0.1", config.TargetPort)
	sshConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to target SSH server %s for client %s: %v", targetAddr, tunnelConn.RemoteAddr(), err)
		return // Closing tunnelConn is handled by defer
	}
	defer sshConn.Close() // Ensure the SSH server connection is closed

	// --- START: PROXY Protocol Header Injection ---
	proxyHeader := createProxyProtocolHeader(clientIP, config.TargetPort)
	log.Printf("Attempting to send PROXY header for client %s to %s: %q", clientIP, targetAddr, proxyHeader)
	_, err = sshConn.Write([]byte(proxyHeader))
	if err != nil {
		log.Printf("Failed to send PROXY header to target SSH server %s for client %s: %v", targetAddr, tunnelConn.RemoteAddr(), err)
		return // Closing tunnelConn and sshConn handled by defer
	}
	log.Printf("Successfully sent PROXY header for client %s to %s", clientIP, targetAddr)
	// --- END: PROXY Protocol Header Injection ---

	log.Printf("Proxying traffic between DNS tunnel (%s) and SSH server (%s)", tunnelConn.RemoteAddr(), targetAddr)

	// Use a wait group to ensure both goroutines finish before closing
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy data from DNS tunnel to SSH server
	go func() {
		defer wg.Done()
		// Use io.Copy for efficient byte copying between net.Conn interfaces
		_, err := io.Copy(sshConn, tunnelConn)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Error copying from tunnel to SSH server for %s: %v", tunnelConn.RemoteAddr(), err)
		}
		// Shut down the write half of the SSH connection when the tunnel closes
		if tcpConn, ok := sshConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Copy data from SSH server to DNS tunnel
	go func() {
		defer wg.Done()
		_, err := io.Copy(tunnelConn, sshConn)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Error copying from SSH server to tunnel for %s: %v", tunnelConn.RemoteAddr(), err)
		}
		// The `tunnelConn.Close()` defer above handles full shutdown for the tunnel side.
	}()

	wg.Wait() // Wait for both copy operations to finish
	log.Printf("DNS tunnel and SSH proxy session closed for %s", tunnelConn.RemoteAddr())
}

func main() {
	// Specify the path to your config.conf file
	configFilePath := "config.conf"
	config, err := loadConfig(configFilePath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", configFilePath, err)
	}

	addr, err := net.ResolveUDPAddr("udp", config.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to resolve listen address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP %s: %v", config.ListenAddr, err)
	}
	defer udpConn.Close()

	log.Printf("DNS tunnel server listening on %s for domain %s", config.ListenAddr, config.TunnelDomain)
	log.Printf("Proxying to SSH server on 127.0.0.1:%s", config.TargetPort)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start accepting DNS tunnel connections using cesiumlib's server handler.
	go func() {
		err := cesiumlib.AcceptServerDnsTunnelConns(
			udpConn,
			config.TunnelDomain,
			config.Password,
			func(conn net.Conn) {
				// This anonymous function wraps handleTunnelConnection to pass the config.
				handleTunnelConnection(conn, config)
			},
		)
		if err != nil {
			log.Fatalf("DNS tunnel server stopped unexpectedly: %v", err)
		}
	}()

	<-sigChan // Wait for an interrupt signal to shut down
	log.Println("Shutting down server.")
}
