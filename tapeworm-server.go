package main

import (
        "bytes"
        "encoding/base64"
        "encoding/binary"
        "errors"
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
)

const (
        MaxB64SegmentSize = 255 // Max 255 bytes for a single DNS TXT character-string
        MaxRawChunkSize   = 190 // floor(255 * 3 / 4) = 191.25. Using 190 to be safe for B64 encoding.

        HandshakeTimeout  = 30 * time.Second
        KeepaliveInterval = 30 * time.Second // Increased keepalive for tunnel stability
        MaxPacketSize     = 1500
)

type Config struct {
        ListenAddr   string
        TunnelDomain string
        Password     string
        Mode         string
        TargetPort   string
}

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
        // This buffer is written to by the main loop and read from by connectAndPipeTCP
        inboundBuffer      *bytes.Buffer
        inboundBufferMutex sync.Mutex
}

func loadConfig(path string) (*Config, error) {
        // For demonstration, hardcode config. In production, load from file.
        return &Config{
                ListenAddr:   "0.0.0.0:5353", // the host and port we bind dns to
                TunnelDomain: "subdomain.domain.tld", // update with your tld
                Password:     "yourpassword123", // this should match your client
                Mode:         "tcp_proxy", // there are no other modes
                TargetPort:   "2222", // Assuming SSH server runs on 2222 on localhost
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

        buf := make([]byte, MaxPacketSize)
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

                payload, password, err := decodeDNSQuery(buf[:n], cfg.TunnelDomain)
                if err != nil {
                        // log.Printf("Failed to decode query from %s: %v", clientKey, err) // Removed
                        errorResp := createDNSResponse(queryID, nil, false, true) // Send SERVFAIL
                        conn.WriteToUDP(errorResp, addr)
                        continue
                }

                if password != cfg.Password {
                        log.Printf("Authentication failed for client %s", clientKey)
                        authFailedResp := createDNSResponse(queryID, nil, false, true) // Send SERVFAIL
                        conn.WriteToUDP(authFailedResp, addr)
                        continue
                }

                mu.Lock()
                session, exists := sessions[clientKey]
                if !exists {
                        session = &ClientSession{
                                conn:                conn, // Use the main UDP listener for responses
                                addr:                addr,
                                lastActive:          time.Now(),
                                closeChan:           make(chan struct{}),
                                queryID:             make([]byte, 2), // Placeholder, will be updated per query
                                outboundBuffer:      bytes.NewBuffer(nil),
                                outboundBufferMutex: sync.Mutex{},
                                inboundBuffer:       bytes.NewBuffer(nil), // Initialize inbound buffer
                                inboundBufferMutex:  sync.Mutex{},
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
                        // log.Printf("Buffered %d bytes from client %s for SSH server. Total buffered: %d", len(payload), clientKey, session.inboundBuffer.Len()) // Removed
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
                // Signal to client that tunnel is gone via DNS error or no response.
                // The `cleanupSessions` will eventually close the session's closeChan.
        }()

        conn, err := net.Dial("tcp", "127.0.0.1:"+targetPort)
        if err != nil {
                log.Printf("Failed to connect to SSH server for %s: %v", session.addr, err)
                errorResp := createDNSResponse(session.queryID, []byte("SSH_CONNECT_FAIL"), true, true)
                session.conn.WriteToUDP(errorResp, session.addr)
                return
        }
        session.proxyConn = conn
        log.Printf("Connected to target SSH server for %s", session.addr)

        proxyHeader := createProxyProtocolHeader(clientIP, targetPort)
        if _, err := conn.Write([]byte(proxyHeader)); err != nil {
                // log.Printf("Failed to send PROXY header for %s: %v", clientIP, err) // Removed
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
        buf := make([]byte, MaxRawChunkSize*2) // Read more than one chunk at a time if available
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
                                        // Timeout is fine, just means no data currently available. Continue loop.
                                        // Removed log.Printf for timeouts
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
                                //log.Printf("Flushed %d bytes from client buffer to SSH server for %s. Remaining: %d", written, session.addr, session.inboundBuffer.Len()) // Commented out
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
                chunkSize := min(MaxRawChunkSize, session.outboundBuffer.Len())
                chunk := session.outboundBuffer.Next(chunkSize) // Get up to chunkSize bytes

                encodedChunk := base64.RawURLEncoding.EncodeToString(chunk)
                //log.Printf("Server sending B64 chunk (len %d): %s", len(encodedChunk), encodedChunk) // Removed

                resp := createDNSResponse(session.queryID, []byte(encodedChunk), true, false)
                if _, err := session.conn.WriteToUDP(resp, session.addr); err != nil {
                        log.Printf("Failed to send DNS response to client %s: %v", session.addr, err)
                        // On write error, assume connection is broken and clear buffer
                        session.outboundBuffer.Reset()
                        return
                }
                // Introduce a very small delay to avoid overwhelming the network/client, but keep it tight
                time.Sleep(5 * time.Millisecond) // Reduced from 10ms for better handshake performance
        }
}

func decodeDNSQuery(data []byte, tunnelDomain string) ([]byte, string, error) {
        if len(data) < 12 {
                return nil, "", errors.New("DNS query too short")
        }

        offset := 12
        var labels []string
        for {
                if offset >= len(data) {
                        return nil, "", errors.New("malformed QNAME")
                }
                labelLen := int(data[offset])
                if labelLen == 0 {
                        offset++
                        break
                }
                offset++
                if offset+labelLen > len(data) {
                        return nil, "", errors.New("malformed QNAME label")
                }
                labels = append(labels, string(data[offset:offset+labelLen]))
                offset += labelLen
        }

        fullQuery := strings.Join(labels, ".")
        tunnelDomain = strings.TrimSuffix(tunnelDomain, ".") // Ensure no trailing dot for comparison
        expectedSuffix := ".tunnel." + tunnelDomain
        if !strings.HasSuffix(strings.ToLower(fullQuery), strings.ToLower(expectedSuffix)) {
                return nil, "", fmt.Errorf("invalid tunnel domain suffix: %q (expected suffix: %q)", fullQuery, expectedSuffix)
        }

        prefix := strings.TrimSuffix(fullQuery, expectedSuffix)
        parts := strings.Split(prefix, ".")

        if len(parts) < 2 { // Expect at least queryID.password
                return nil, "", errors.New("malformed tunnel query: not enough parts (queryID.password.tunnel.domain or data.queryID.password.tunnel.domain)")
        }

        // Based on the client's new ordering: ...data.idXXXX.b64Password.tunnel.domain
        b64Password := parts[len(parts)-1] // This is now the actual base64 encoded password

        queryIDLabelWithPrefix := parts[len(parts)-2] // This is now the query ID label
        if !strings.HasPrefix(queryIDLabelWithPrefix, "id") {
                return nil, "", fmt.Errorf("malformed tunnel query: query ID label missing 'id' prefix")
        }

        passwordBytes, err := base64.RawURLEncoding.DecodeString(b64Password)
        if err != nil {
                return nil, "", fmt.Errorf("failed to decode password: %w", err)
        }

        var rawPayloadChunks []byte
        // Iterate through the parts that are payload chunks (all except the last two)
        for i := 0; i < len(parts)-2; i++ { // Iterate up to len(parts)-2
                b64ChunkWithPrefix := parts[i]
                if !strings.HasPrefix(b64ChunkWithPrefix, "d") {
                        // If a label without 'd' prefix is found in the data section, it's malformed
                        return nil, "", fmt.Errorf("malformed tunnel query: payload label missing 'd' prefix: %s", b64ChunkWithPrefix)
                }
                b64Chunk := b64ChunkWithPrefix[len("d"):] // Strip "d" prefix

                if b64Chunk == "" {
                        // This might happen if the client sends an empty data label, which is valid for keepalives
                        continue
                }

                decodedChunk, err := base64.RawURLEncoding.DecodeString(b64Chunk)
                if err != nil {
                        return nil, "", fmt.Errorf("failed to decode payload chunk '%s': %w", b64Chunk, err)
                }
                rawPayloadChunks = append(rawPayloadChunks, decodedChunk...)
        }

        return rawPayloadChunks, string(passwordBytes), nil
}

// createDNSResponse generates a DNS response packet.
// The `data` will be put into a TXT record. If `isError` is true, SERVFAIL will be set.
func createDNSResponse(queryID []byte, data []byte, isDataTunnel bool, isError bool) []byte {
        var buffer bytes.Buffer

        // DNS Header
        buffer.Write(queryID)
        flags := uint16(0x8000) // QR=1 (Response)
        if isError {
                flags |= 0x0002 // SERVFAIL (RCODE 2)
        } else {
                flags |= 0x0100 // AA (Authoritative Answer, for simplicity)
                // RD (Recursion Desired) and RA (Recursion Available) are usually set if server supports it.
                // We set RD from query for robustness, but here we keep it fixed for simplicity of response.
        }
        binary.Write(&buffer, binary.BigEndian, flags)
        binary.Write(&buffer, binary.BigEndian, uint16(0)) // QDCOUNT (no questions in response for now)
        binary.Write(&buffer, binary.BigEndian, uint16(0)) // ANCOUNT (updated later if data)
        binary.Write(&buffer, binary.BigEndian, uint16(0)) // NSCOUNT
        binary.Write(&buffer, binary.BigEndian, uint16(0)) // ARCOUNT

        if isDataTunnel && data != nil && len(data) > 0 { // Only add answer if there's data to send
                // Update ANCOUNT to 1
                // This needs to be set after the initial header write.
                headerBytes := buffer.Bytes()
                binary.BigEndian.PutUint16(headerBytes[6:8], 1) // Set ANCOUNT to 1

                // Answer section
                // NAME: Use a simple root label (0x00) as the QNAME is not echoed and irrelevant for data.
                buffer.WriteByte(0x00) // Root label, ending the name field (used for empty name in response)

                binary.Write(&buffer, binary.BigEndian, uint16(16)) // TYPE: TXT (16)
                binary.Write(&buffer, binary.BigEndian, uint16(1))  // CLASS: IN (1)
                binary.Write(&buffer, binary.BigEndian, uint32(60)) // TTL: 60 seconds

                // RDATA for TXT record - composed of length-prefixed strings
                var txtDataBytes bytes.Buffer
                currentData := data
                for len(currentData) > 0 {
                        // This limits the individual TXT character-string to MaxB64SegmentSize (255)
                        chunkLen := min(MaxB64SegmentSize, len(currentData))
                        txtDataBytes.WriteByte(byte(chunkLen))      // Length of the current string
                        txtDataBytes.Write(currentData[:chunkLen])  // The string data
                        currentData = currentData[chunkLen:]        // Advance remaining data
                }

                binary.Write(&buffer, binary.BigEndian, uint16(txtDataBytes.Len())) // RDLENGTH: total length of all length-prefixed strings
                buffer.Write(txtDataBytes.Bytes())                                   // The actual TXT data
        }

        return buffer.Bytes()
}

func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}
