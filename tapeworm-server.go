// server/main.go
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TransIRC/cesium-core"
)

// Config holds the server configuration.
type Config struct {
	ListenAddr   string
	TunnelDomain string
	Password     string
	Mode         string
	TargetPort   string
}

// ClientSession represents a client's tunnel session on the server.
type ClientSession struct {
	conn            *net.UDPConn
	addr            *net.UDPAddr
	lastActive      time.Time
	proxyConn       net.Conn
	closeChan       chan struct{}
	proxyHeaderSent bool
	queryID         []byte // The original query ID from the client's DNS request

	// Buffered data from SSH server to client
	outboundBuffer      *bytes.Buffer
	outboundBufferMutex sync.Mutex

	// Buffered data from client to SSH server (initial handshake data)
	inboundBuffer      *bytes.Buffer
	inboundBufferMutex sync.Mutex
}

// loadConfig loads the server configuration.
func loadConfig(path string) (*Config, error) {
	// For demonstration, hardcode config. In production, load from file.
	return &Config{
		ListenAddr:   "0.0.0.0:53",       // the host and port we bind dns to
		TunnelDomain: "sub.domain.tld", // update with your tld
		Password:     "yourpassword123",    // this should match your client
		Mode:         "tcp_proxy",          // there are no other modes
		TargetPort:   "22",               // Assuming SSH server runs on 22 on localhost
	}, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: dnstunnel-server config.conf")
		os.Exit(1)
	}

	cfg, err := loadConfig(os.Args[1])
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to resolve UDP addr: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer conn.Close()

	log.Printf("DNS tunnel server started on %s", cfg.ListenAddr)

	sessions := make(map[string]*ClientSession)
	var mu sync.Mutex // Mutex for sessions map

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down server...")
		mu.Lock()
		for _, session := range sessions {
			close(session.closeChan)
			if session.proxyConn != nil {
				session.proxyConn.Close()
			}
		}
		mu.Unlock()
		conn.Close() // Close UDP listener
		os.Exit(0)
	}()

	go cleanupSessions(sessions, &mu)

	buf := make([]byte, cesiumcore.MaxDNSPacketSize)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				// Removed log.Printf("Read error: %v", err) to reduce excessive logging
			}
			continue
		}

		clientKey := addr.String()
		queryID := make([]byte, 2)
		copy(queryID, buf[0:2]) // Extract query ID from DNS request header

		// Use library function
		payload, password, err := cesiumcore.DecodeDNSQuery(buf[:n], cfg.TunnelDomain)
		if err != nil {
			errorResp := cesiumcore.CreateDNSResponse(queryID, nil, false, true) // Send SERVFAIL
			conn.WriteToUDP(errorResp, addr)
			continue
		}

		if password != cfg.Password {
			log.Printf("Authentication failed for client %s", clientKey)
			authFailedResp := cesiumcore.CreateDNSResponse(queryID, nil, false, true) // Send SERVFAIL
			conn.WriteToUDP(authFailedResp, addr)
			continue
		}

		mu.Lock()
		session, exists := sessions[clientKey]
		if !exists {
			session = &ClientSession{
				conn:            conn, // Use the main UDP listener for responses
				addr:            addr,
				lastActive:      time.Now(),
				closeChan:       make(chan struct{}),
				queryID:         make([]byte, 2), // Placeholder, will be updated per query
				outboundBuffer:  bytes.NewBuffer(nil),
				outboundBufferMutex: sync.Mutex{},
				inboundBuffer:      bytes.NewBuffer(nil), // Initialize inbound buffer
				inboundBufferMutex: sync.Mutex{},
			}
			sessions[clientKey] = session
			log.Printf("New client: %s (IP: %s)", clientKey, addr.IP.String())

			// Start connection and piping in a goroutine
			if cfg.Mode == "tcp_proxy" {
				go connectAndPipeTCP(session, cfg.TargetPort, addr.IP.String())
			} else {
				log.Printf("Raw DNS mode not fully implemented for duplex communication.")
			}
		}
		session.lastActive = time.Now()
		copy(session.queryID, queryID) // Update query ID for the current session's response
		mu.Unlock()

		// Handle data from client (payload) to SSH server
		if len(payload) > 0 {
			session.inboundBufferMutex.Lock()
			session.inboundBuffer.Write(payload)
			session.inboundBufferMutex.Unlock()

			// If proxyConn is already established, write directly
			if session.proxyConn != nil {
				session.inboundBufferMutex.Lock()
				if session.inboundBuffer.Len() > 0 {
					dataToFlush := session.inboundBuffer.Bytes()
					written, err := session.proxyConn.Write(dataToFlush)
					if err != nil {
						log.Printf("Failed to write buffered client data to SSH server for %s: %v", clientKey, err)
						session.proxyConn.Close()
						session.proxyConn = nil
					} else {
						session.inboundBuffer.Next(written) // Consume written bytes
					}
				}
				session.inboundBufferMutex.Unlock()
			}
		}

		// Always try to send buffered outbound data if available
		sendBufferedOutboundData(session)
	}
}

func cleanupSessions(sessions map[string]*ClientSession, mu *sync.Mutex) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		mu.Lock()
		for key, session := range sessions {
			if time.Since(session.lastActive) > 5*time.Minute {
				log.Printf("Cleaned up inactive session: %s", key)
				close(session.closeChan)
				if session.proxyConn != nil {
					session.proxyConn.Close()
				}
				delete(sessions, key)
			}
		}
		mu.Unlock()
	}
}

func createProxyProtocolHeader(clientIP string, targetPort string) string {
	// Standard PROXY protocol header v1 (TCP4)
	// Source port is arbitrary for PROXY v1, using 12345
	return fmt.Sprintf("PROXY TCP4 %s 127.0.0.1 12345 %s\r\n", clientIP, targetPort)
}

// connectAndPipeTCP establishes the TCP connection to the target and starts piping data.
func connectAndPipeTCP(session *ClientSession, targetPort string, clientIP string) {
	defer func() {
		log.Printf("Closing TCP proxy connection for %s", session.addr)
		session.outboundBufferMutex.Lock()
		session.outboundBuffer.Reset() // Clear outbound buffer on close
		session.outboundBufferMutex.Unlock()
		session.inboundBufferMutex.Lock()
		session.inboundBuffer.Reset() // Clear inbound buffer on close
		session.inboundBufferMutex.Unlock()

		if session.proxyConn != nil {
			session.proxyConn.Close()
			session.proxyConn = nil // Mark as nil after closing
		}
	}()

	conn, err := net.Dial("tcp", "127.0.0.1:"+targetPort)
	if err != nil {
		log.Printf("Failed to connect to SSH server for %s: %v", session.addr, err)
		errorResp := cesiumcore.CreateDNSResponse(session.queryID, []byte("SSH_CONNECT_FAIL"), true, true)
		session.conn.WriteToUDP(errorResp, session.addr)
		return
	}
	session.proxyConn = conn
	log.Printf("Connected to target SSH server for %s", session.addr)

	proxyHeader := createProxyProtocolHeader(clientIP, targetPort)
	if _, err := conn.Write([]byte(proxyHeader)); err != nil {
		return // Let the defer handle closing
	}
	log.Printf("Sent PROXY header for %s", clientIP)

	// Immediately write any buffered client data (initial SSH handshake)
	session.inboundBufferMutex.Lock()
	if session.inboundBuffer.Len() > 0 {
		initialClientData := session.inboundBuffer.Bytes()
		log.Printf("Flushing %d bytes of initial client data to SSH server for %s.", len(initialClientData), session.addr)
		written, err := conn.Write(initialClientData)
		if err != nil {
			log.Printf("Failed to write initial client data to SSH server for %s: %v", session.addr, err)
			session.inboundBufferMutex.Unlock()
			return
		}
		session.inboundBuffer.Next(written) // Consume the written bytes
		log.Printf("Successfully flushed %d bytes of initial client data.", written)
	}
	session.inboundBufferMutex.Unlock()

	// Start goroutine to read from proxyConn and buffer data for the client
	pipeSSHToServerOutput(session, conn)

	// Start goroutine to continuously read from the inboundBuffer and write to proxyConn
	pipeClientToServerInput(session, conn)
}

// pipeSSHToServerOutput reads from the SSH server and buffers data to be sent to the client.
func pipeSSHToServerOutput(session *ClientSession, proxyConn net.Conn) {
	buf := make([]byte, cesiumcore.MaxRawChunkSize*2) // Read more than one chunk at a time if available
	for {
		select {
		case <-session.closeChan:
			log.Printf("pipeSSHToServerOutput: Session close signal received for %s", session.addr)
			return
		default:
			// Set a short read deadline to allow checking closeChan frequently
			proxyConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := proxyConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if err == io.EOF {
					log.Printf("SSH server closed connection for %s (EOF)", session.addr)
				} else {
					log.Printf("Read error from SSH server for %s: %v", session.addr, err)
				}
				// Break the loop and let the defer in connectAndPipeTCP close resources
				close(session.closeChan) // Signal other goroutines to close
				return
			}

			if n > 0 {
				session.outboundBufferMutex.Lock()
				session.outboundBuffer.Write(buf[:n])
				log.Printf("Buffered %d bytes from SSH server for client %s. Total buffered: %d", n, session.addr, session.outboundBuffer.Len())
				session.outboundBufferMutex.Unlock()
				// Immediately attempt to send buffered data as a response
				sendBufferedOutboundData(session)
			}
		}
	}
}

// pipeClientToServerInput continuously reads from the inbound buffer and writes to the proxy connection.
func pipeClientToServerInput(session *ClientSession, proxyConn net.Conn) {
	for {
		select {
		case <-session.closeChan:
			log.Printf("pipeClientToServerInput: Session close signal received for %s", session.addr)
			return
		case <-time.After(50 * time.Millisecond): // Check buffer periodically
			session.inboundBufferMutex.Lock()
			if session.inboundBuffer.Len() > 0 {
				dataToFlush := session.inboundBuffer.Bytes()
				written, err := proxyConn.Write(dataToFlush)
				if err != nil {
					log.Printf("Failed to write buffered client data to SSH server for %s: %v", session.addr, err)
					session.inboundBufferMutex.Unlock()
					close(session.closeChan) // Signal other goroutines to close
					return
				}
				session.inboundBuffer.Next(written) // Consume written bytes
			}
			session.inboundBufferMutex.Unlock()
		}
	}
}

// sendBufferedOutboundData sends chunks of data from the outbound buffer to the client.
func sendBufferedOutboundData(session *ClientSession) {
	session.outboundBufferMutex.Lock()
	defer session.outboundBufferMutex.Unlock()

	for session.outboundBuffer.Len() > 0 {
		// Take a chunk from the buffered data
		chunkSize := cesiumcore.Min(cesiumcore.MaxRawChunkSize, session.outboundBuffer.Len())
		chunk := session.outboundBuffer.Next(chunkSize) // Get up to chunkSize bytes

		encodedChunk := base64.RawURLEncoding.EncodeToString(chunk)

		// Use library function
		resp := cesiumcore.CreateDNSResponse(session.queryID, []byte(encodedChunk), true, false)
		if _, err := session.conn.WriteToUDP(resp, session.addr); err != nil {
			log.Printf("Failed to send DNS response to client %s: %v", session.addr, err)
			// On write error, assume connection is broken and clear buffer
			session.outboundBuffer.Reset()
			return
		}
		// Introduce a very small delay to avoid overwhelming the network/client, but keep it tight
		time.Sleep(5 * time.Millisecond)
	}
}
