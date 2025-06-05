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
        "time"

        "golang.org/x/crypto/ssh"
        "golang.org/x/term"
)

const (
        DnsServerAddress  = "your_dns_server_ip:5353" //update with ip of server
        TunnelDomain      = "subdomain.domain.tld" // update with your servers domain
        TunnelPassword    = "yourpassword123" // ensure your password matches the server
        MaxDNSPacketSize  = 1500
        MaxDNSLabelSize   = 63 // Maximum length for a DNS label (RFC 1035)
        RawChunkSize      = 46 // 46 raw bytes -> 62 base64 chars + 'd' prefix = 63 chars.
        ReadTimeout       = 10 * time.Second // Increased read timeout for SSH session stability
        WriteTimeout      = 10 * time.Second // Increased write timeout
        KeepaliveInterval = 5 * time.Second  // More frequent keepalives
)

type DnsTunnelConn struct {
        udpConn      *net.UDPConn
        remoteAddr   *net.UDPAddr
        readBuffer   bytes.Buffer
        readReady    chan struct{} // Signaled when new data is written to readBuffer
        lastActive   time.Time
        readDeadline time.Time
        stopChan     chan struct{}
        queryID      uint16
        mutex        sync.Mutex // Protects readBuffer, readReady, lastActive, queryID, readDeadline
        once         sync.Once  // Added for safe channel closing
        closed       bool       // Flag to indicate the connection is logically closed
}

func NewDnsTunnelConn(dnsServerAddr string) (*DnsTunnelConn, error) {
        remoteAddr, err := net.ResolveUDPAddr("udp", dnsServerAddr)
        if err != nil {
                return nil, fmt.Errorf("resolve error: %w", err)
        }

        udpConn, err := net.ListenUDP("udp", nil)
        if err != nil {
                return nil, fmt.Errorf("listen error: %w", err)
        }

        conn := &DnsTunnelConn{
                udpConn:    udpConn,
                remoteAddr: remoteAddr,
                lastActive: time.Now(),
                readReady:  make(chan struct{}, 1),
                stopChan:   make(chan struct{}),
                queryID:    uint16(time.Now().UnixNano()),
                closed:     false,
        }

        go conn.reader()
        go conn.keepalive()

        return conn, nil
}

func (c *DnsTunnelConn) Read(b []byte) (int, error) {
        c.mutex.Lock()
        defer c.mutex.Unlock()

        for {
                if c.readBuffer.Len() > 0 {
                        n, err := c.readBuffer.Read(b)
                        c.lastActive = time.Now()
                        //log.Printf("DnsTunnelConn.Read: Read %d bytes from internal buffer. Remaining: %d", n, c.readBuffer.Len()) // Commented out
                        return n, err
                }

                if c.closed {
                        log.Println("DnsTunnelConn.Read: Connection is closed, returning EOF.")
                        return 0, io.EOF
                }

                var waitTime time.Duration
                if !c.readDeadline.IsZero() {
                        waitTime = time.Until(c.readDeadline)
                        if waitTime <= 0 {
                                log.Println("DnsTunnelConn.Read: Read deadline exceeded.")
                                return 0, os.ErrDeadlineExceeded
                        }
                } else {
                        waitTime = ReadTimeout
                        //log.Printf("DnsTunnelConn.Read: No explicit deadline, using default %v.", waitTime) // Commented out
                }

                c.mutex.Unlock()
                select {
                case <-c.readReady:
                        c.mutex.Lock()
                        //log.Println("DnsTunnelConn.Read: Data ready signal received, re-checking buffer.") // Commented out
                        continue
                case <-time.After(waitTime):
                        c.mutex.Lock()
                        if c.readBuffer.Len() > 0 {
                                n, err := c.readBuffer.Read(b)
                                c.lastActive = time.Now()
                                //log.Printf("DnsTunnelConn.Read: Data arrived during timeout, read %d bytes. Remaining: %d", n, c.readBuffer.Len()) // Commented out
                                return n, err
                        }
                        log.Println("DnsTunnelConn.Read: Read timeout, no data available.")
                        return 0, os.ErrDeadlineExceeded
                case <-c.stopChan:
                        c.mutex.Lock()
                        log.Println("DnsTunnelConn.Read: Stop signal received, returning EOF.")
                        return 0, io.EOF
                }
        }
}

func (c *DnsTunnelConn) Write(b []byte) (int, error) {
        c.mutex.Lock()
        defer c.mutex.Unlock()

        if c.closed {
                log.Println("DnsTunnelConn.Write: Connection is closed, returning EOF.")
                return 0, io.EOF
        }

        //log.Printf("DnsTunnelConn.Write: Attempting to write %d bytes to tunnel.", len(b)) // Commented out

        totalWritten := 0
        dataToSend := b

        for len(dataToSend) > 0 {
                var currentQueryPayloads [][]byte
                currentQueryTotalRawSize := 0

                // Keep total raw payload per DNS query under 500 bytes for safety,
                // while respecting MaxDNSLabelSize for each chunk.
                for len(dataToSend) > 0 {
                        chunkSize := min(RawChunkSize, len(dataToSend))
                        encodedLen := base64.RawURLEncoding.EncodedLen(chunkSize)
                        if encodedLen+1 > MaxDNSLabelSize { // +1 for the 'd' prefix
                                // This case should ideally not be hit if RawChunkSize is calculated correctly,
                                // but as a safeguard.
                                log.Printf("Calculated encoded chunk (len %d) plus prefix would exceed MaxDNSLabelSize. Adjusting chunk size.", encodedLen+1)
                                // Re-calculate chunkSize to fit into MaxDNSLabelSize
                                maxRaw := (MaxDNSLabelSize - 1) * 4 / 3 // MaxRaw based on MaxDNSLabelSize and 'd' prefix
                                chunkSize = min(maxRaw, len(dataToSend))
                                if chunkSize == 0 {
                                        break // Cannot encode any more data into a label
                                }
                        }

                        // Check if adding this chunk would exceed the 500 byte total raw size limit
                        if currentQueryTotalRawSize+chunkSize > 500 && len(currentQueryPayloads) > 0 {
                                break // Stop adding chunks to this query if it exceeds total raw size
                        }

                        chunk := dataToSend[:chunkSize]
                        currentQueryPayloads = append(currentQueryPayloads, chunk)
                        currentQueryTotalRawSize += chunkSize
                        dataToSend = dataToSend[chunkSize:]
                }

                if len(currentQueryPayloads) == 0 {
                        break
                }

                var dnsLabels []string
                for _, p := range currentQueryPayloads {
                        encoded := base64.RawURLEncoding.EncodeToString(p)
                        if len(encoded) > MaxDNSLabelSize-1 { // -1 for the 'd' prefix
                                log.Fatalf("Internal error: Encoded chunk (%d chars) too long for DNS label (max %d) after 'd' prefix", len(encoded), MaxDNSLabelSize-1)
                        }
                        dnsLabels = append(dnsLabels, "d"+encoded) // Prefix with 'd' for data
                }

                c.queryID++
                query, err := c.createDNSQuery(dnsLabels)
                if err != nil {
                        log.Printf("DnsTunnelConn.Write: Query creation failed for chunk(s): %v", err)
                        return totalWritten, fmt.Errorf("query creation failed: %w", err)
                }

                c.udpConn.SetWriteDeadline(time.Now().Add(WriteTimeout))
                _, err = c.udpConn.WriteToUDP(query, c.remoteAddr)
                if err != nil {
                        log.Printf("DnsTunnelConn.Write: UDP write failed for chunk(s) (raw len %d): %v", currentQueryTotalRawSize, err)
                        return totalWritten, fmt.Errorf("write failed: %w", err)
                }
                //log.Printf("DnsTunnelConn.Write: Sent %d raw bytes in one DNS query. Total sent so far: %d", currentQueryTotalRawSize, totalWritten+currentQueryTotalRawSize) // Commented out

                totalWritten += currentQueryTotalRawSize
                c.lastActive = time.Now()
                time.Sleep(1 * time.Millisecond) // Small delay to avoid overwhelming the server
        }

        //log.Printf("DnsTunnelConn.Write: Successfully wrote total %d bytes.", totalWritten) // Commented out
        return totalWritten, nil
}

func (c *DnsTunnelConn) createDNSQuery(payloadLabels []string) ([]byte, error) {
        var buf bytes.Buffer

        // DNS Header
        binary.Write(&buf, binary.BigEndian, c.queryID)
        binary.Write(&buf, binary.BigEndian, uint16(0x0100))
        binary.Write(&buf, binary.BigEndian, uint16(1))
        binary.Write(&buf, binary.BigEndian, uint16(0))
        binary.Write(&buf, binary.BigEndian, uint16(0))
        binary.Write(&buf, binary.BigEndian, uint16(0))

        b64Password := base64.RawURLEncoding.EncodeToString([]byte(TunnelPassword))
        queryIDLabel := fmt.Sprintf("id%d", c.queryID%65535)

        var fullQueryParts []string
        fullQueryParts = append(fullQueryParts, payloadLabels...)
        fullQueryParts = append(fullQueryParts, queryIDLabel, b64Password, "tunnel", TunnelDomain) // Order: ...data.idXXXX.b64Password.tunnel.domain

        fullQuery := strings.Join(fullQueryParts, ".")

        for _, part := range strings.Split(fullQuery, ".") {
                if len(part) == 0 {
                        continue
                }
                if len(part) > MaxDNSLabelSize {
                        return nil, fmt.Errorf("label too long: %q (max %d characters)", part, MaxDNSLabelSize)
                }
                buf.WriteByte(byte(len(part)))
                buf.WriteString(part)
        }
        buf.WriteByte(0) // End of QNAME

        binary.Write(&buf, binary.BigEndian, uint16(16)) // QTYPE: TXT
        binary.Write(&buf, binary.BigEndian, uint16(1))  // QCLASS: IN

        return buf.Bytes(), nil
}

func (c *DnsTunnelConn) reader() {
        buf := make([]byte, MaxDNSPacketSize)
        for {
                select {
                case <-c.stopChan:
                        log.Println("DNS tunnel reader goroutine stopped.")
                        return
                default:
                        c.udpConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) // Short deadline to allow stopChan to be checked
                        n, _, err := c.udpConn.ReadFromUDP(buf)
                        if err != nil {
                                if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                                        continue // Timeout is normal, keep checking for data or stop signal
                                }
                                if strings.Contains(err.Error(), "use of closed network connection") {
                                        log.Println("UDP connection closed, DNS tunnel reader exiting.")
                                        return
                                }
                                log.Printf("UDP ReadFromUDP error (critical): %v", err)
                                c.Close() // Close the tunnel connection on critical error
                                return
                        }

                        payload, err := parseDNSResponse(buf[:n])
                        if err != nil {
                                if err.Error() == "no decodable payload found in DNS response" {
                                        // This might be a keepalive response or a response with no data
                                        // It's not necessarily an error that should cause client to close.
                                        // log.Println("DNS response contains no data payload.") // Commented out
                                } else {
                                        log.Printf("DNS response parsing error: %v", err)
                                }
                                continue
                        }

                        if len(payload) > 0 {
                                c.mutex.Lock()
                                c.readBuffer.Write(payload)
                                //log.Printf("DnsTunnelConn.reader: Received %d bytes from server, buffered %d. Total buffered: %d", len(payload), len(payload), c.readBuffer.Len()) // Commented out
                                select {
                                case c.readReady <- struct{}{}:
                                        // Successfully signaled
                                        // log.Println("DnsTunnelConn.reader: Signaled readReady.") // Commented out
                                default:
                                        // Channel is full, meaning reader is not keeping up, or
                                        // a signal is already pending. This is fine.
                                        // log.Println("DnsTunnelConn.reader: readReady channel full, skipping signal.") // Commented out
                                }
                                c.mutex.Unlock()
                        }
                }
        }
}

func (c *DnsTunnelConn) keepalive() {
        ticker := time.NewTicker(KeepaliveInterval)
        defer ticker.Stop()

        for {
                select {
                case <-c.stopChan:
                        log.Println("DNS tunnel keepalive goroutine stopped.")
                        return
                case <-ticker.C:
                        c.mutex.Lock()
                        if c.closed {
                                c.mutex.Unlock()
                                return
                        }
                        // Only send keepalive if there hasn't been recent activity.
                        // This prevents spamming if data is flowing constantly.
                        if time.Since(c.lastActive) > KeepaliveInterval {
                                c.queryID++
                                emptyPayloads := []string{"k"} // 'k' for keepalive
                                query, err := c.createDNSQuery(emptyPayloads)
                                if err != nil {
                                        log.Printf("Keepalive query creation failed: %v", err)
                                        c.mutex.Unlock()
                                        continue
                                }
                                if _, err := c.udpConn.WriteToUDP(query, c.remoteAddr); err != nil {
                                        log.Printf("Keepalive write failed: %v", err)
                                } else {
                                        //log.Println("Sent DNS tunnel keepalive.") // Commented out
                                }
                        }
                        c.mutex.Unlock()
                }
        }
}

func parseDNSResponse(data []byte) ([]byte, error) {
        if len(data) < 12 {
                return nil, errors.New("DNS response too short")
        }

        flags := binary.BigEndian.Uint16(data[2:4])
        qdcount := binary.BigEndian.Uint16(data[4:6])
        ancount := binary.BigEndian.Uint16(data[6:8])

        rcode := flags & 0x000F
        if rcode != 0 {
                return nil, fmt.Errorf("DNS error RCODE: %d (flags: 0x%X)", rcode, flags)
        }

        if ancount == 0 {
                return nil, errors.New("no answer records in DNS response")
        }

        offset := 12 // Start of Question section

        // Skip Question section
        for q := 0; q < int(qdcount); q++ {
                for {
                        if offset >= len(data) {
                                return nil, fmt.Errorf("malformed QNAME in DNS response (truncated)")
                        }
                        labelLen := int(data[offset])
                        if (labelLen & 0xC0) == 0xC0 { // Pointer
                                offset += 2
                                break
                        }
                        offset++
                        if labelLen == 0 { // End of QNAME
                                break
                        }
                        offset += labelLen
                }
                if offset+4 > len(data) { // QTYPE and QCLASS (2 bytes each)
                        return nil, fmt.Errorf("DNS response truncated at QTYPE/QCLASS")
                }
                offset += 4
        }

        if offset >= len(data) {
                return nil, fmt.Errorf("DNS response truncated before Answer section")
        }

        var fullPayload bytes.Buffer
        for i := 0; i < int(ancount); i++ {
                // Answer Record Name (can be a pointer or sequence of labels)
                if offset >= len(data) {
                        return nil, fmt.Errorf("malformed answer record NAME in DNS response (truncated, RR %d)", i+1)
                }
                if (data[offset] & 0xC0) == 0xC0 { // Pointer
                        offset += 2
                } else { // Labels
                        for {
                                if offset >= len(data) {
                                        return nil, fmt.Errorf("malformed answer record NAME in DNS response (truncated label, RR %d)", i+1)
                                }
                                labelLen := int(data[offset])
                                offset++
                                if labelLen == 0 {
                                        break
                                }
                                offset += labelLen
                        }
                }

                if offset+10 > len(data) { // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2)
                        return nil, fmt.Errorf("DNS response truncated at RR header (RR %d)", i+1)
                }
                rrType := binary.BigEndian.Uint16(data[offset : offset+2])
                // rrClass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
                // rrTTL := binary.BigEndian.Uint32(data[offset+4 : offset+8])
                rdLength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
                offset += 10 // Move past RR header to RDATA

                if offset+int(rdLength) > len(data) {
                        return nil, fmt.Errorf("RDLENGTH (%d) out of bounds when reading RDATA (packet size: %d, current offset: %d, RR %d)", rdLength, len(data), offset, i+1)
                }

                if rrType == 16 { // TXT record
                        txtData := data[offset : offset+int(rdLength)]
                        txtOffset := 0
                        var combinedEncodedChunk bytes.Buffer
                        for txtOffset < len(txtData) {
                                if txtOffset+1 > len(txtData) {
                                        return nil, errors.New("TXT record string length byte missing")
                                }
                                chunkLen := int(txtData[txtOffset])
                                txtOffset++

                                if txtOffset+chunkLen > len(txtData) {
                                        return nil, fmt.Errorf("TXT record string data out of bounds (chunkLen: %d, remaining txtData: %d)", chunkLen, len(txtData)-txtOffset)
                                }
                                combinedEncodedChunk.Write(txtData[txtOffset : txtOffset+chunkLen])
                                txtOffset += chunkLen
                        }

                        encoded := combinedEncodedChunk.String()
                        decodedChunk, err := base64.RawURLEncoding.DecodeString(encoded)
                        if err != nil {
                                return nil, fmt.Errorf("failed to base64 decode TXT data '%s': %w", encoded, err)
                        } else {
                                fullPayload.Write(decodedChunk)
                        }
                }
                offset += int(rdLength) // Move to the next Answer Record
        }

        if fullPayload.Len() == 0 {
                return nil, errors.New("no decodable payload found in DNS response")
        }

        return fullPayload.Bytes(), nil
}

func (c *DnsTunnelConn) Close() error {
        c.once.Do(func() {
                c.mutex.Lock()
                c.closed = true
                close(c.stopChan)
                // Close readReady to unblock any waiting Read calls
                select {
                case <-c.readReady: // Drain if a signal is pending
                default:
                }
                close(c.readReady)
                c.mutex.Unlock()
                log.Println("DnsTunnelConn.Close: Marked as closed and sent stop signals.")
        })
        err := c.udpConn.Close()
        if err != nil {
                log.Printf("DnsTunnelConn.Close: Error closing UDP connection: %v", err)
        } else {
                log.Println("DnsTunnelConn.Close: UDP connection closed successfully.")
        }
        return err
}

func (c *DnsTunnelConn) LocalAddr() net.Addr {
        return c.udpConn.LocalAddr()
}

func (c *DnsTunnelConn) RemoteAddr() net.Addr {
        return c.remoteAddr
}

func (c *DnsTunnelConn) SetDeadline(t time.Time) error {
        c.mutex.Lock()
        defer c.mutex.Unlock()
        c.readDeadline = t
        //log.Printf("DnsTunnelConn.SetDeadline: Read deadline set to %v", t) // Commented out
        return nil
}

func (c *DnsTunnelConn) SetReadDeadline(t time.Time) error {
        return c.SetDeadline(t)
}

func (c *DnsTunnelConn) SetWriteDeadline(t time.Time) error {
        // For UDP, write deadlines are typically handled per-write by the underlying WriteToUDP
        // but the net.Conn interface requires this. We'll log it but not use it.
        // log.Printf("DnsTunnelConn.SetWriteDeadline: (Ignoring for UDP, handled internally per write) %v", t) // Commented out
        return nil
}

func main() {
        log.Println("Starting DNS-tunneled SSH client...")

        fmt.Print("SSH Username: ")
        var sshUser string
        _, err := fmt.Scanln(&sshUser)
        if err != nil {
                log.Fatalf("Failed to read username: %v", err)
        }

        var dnsTun *DnsTunnelConn

        const maxRetries = 5
        for i := 0; i < maxRetries; i++ {
                log.Printf("Attempting to establish DNS tunnel (retry %d/%d)...", i+1, maxRetries)
                dnsTun, err = NewDnsTunnelConn(DnsServerAddress)
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
                        // Removed Ciphers, MACs, KexAlgorithms, HostKeyAlgorithms as they are not
                        // available in older versions of golang.org/x/crypto/ssh.
                        // The SSH client will use its default algorithm negotiation.
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

                        // Get initial terminal size
                        var width, height int
                        width, height = getTerminalSize() // Call the OS-specific function
                        if err != nil {
                                log.Printf("Failed to get terminal size: %v, using defaults.", err)
                                width, height = 80, 40 // Fallback
                        }

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
                        if err := session.RequestPty("xterm-256color", height, width, modes); err != nil { // Changed "xterm" to "xterm-256color"
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
                                for range resizeSig { // Listen on the channel for resize signals
                                        w, h, err := term.GetSize(int(os.Stdin.Fd()))
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

func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}
