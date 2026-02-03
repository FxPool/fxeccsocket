package fxeccsocket

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net/http"
	"strings"
	"sync"
)

// WebSocketObfuscator encapsulates data in WebSocket frames.
// This makes traffic appear as legitimate WebSocket communication.
type WebSocketObfuscator struct {
	host        string
	path        string
	userAgent   string
	isClient    bool
	frameBuffer *sync.Pool

	// handshakeComplete tracks if WebSocket handshake has been performed
	handshakeComplete bool
}

// userAgentPool contains realistic browser User-Agent strings
var userAgentPool = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
}

// newWebSocketObfuscator creates a new WebSocket obfuscator
func newWebSocketObfuscator(config *ObfuscationConfig, isClient bool) *WebSocketObfuscator {
	host := config.Domain
	if host == "" {
		host = "cdn.example.com"
	}

	path := config.CoverPath
	if path == "" {
		path = "/ws"
	}

	return &WebSocketObfuscator{
		host:      host,
		path:      path,
		userAgent: userAgentPool[mrand.Intn(len(userAgentPool))],
		isClient:  isClient,
		frameBuffer: &sync.Pool{
			New: func() interface{} { return make([]byte, 0, 4096) },
		},
	}
}

// obfuscate wraps data in a WebSocket binary frame
func (w *WebSocketObfuscator) obfuscate(data []byte) ([]byte, error) {
	return w.encodeFrame(data)
}

// deobfuscate extracts data from a WebSocket frame
func (w *WebSocketObfuscator) deobfuscate(data []byte) ([]byte, error) {
	return w.decodeFrame(data)
}

// encodeFrame creates a WebSocket binary frame
// Frame format (RFC 6455):
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
func (w *WebSocketObfuscator) encodeFrame(payload []byte) ([]byte, error) {
	var buf bytes.Buffer

	// FIN bit (1) + RSV (000) + Opcode (0010 = binary)
	buf.WriteByte(0x82)

	// Payload length with mask bit
	payloadLen := len(payload)
	maskBit := byte(0x00)
	if w.isClient {
		// Clients MUST mask data
		maskBit = 0x80
	}

	if payloadLen < 126 {
		buf.WriteByte(byte(payloadLen) | maskBit)
	} else if payloadLen < 65536 {
		buf.WriteByte(126 | maskBit)
		binary.Write(&buf, binary.BigEndian, uint16(payloadLen))
	} else {
		buf.WriteByte(127 | maskBit)
		binary.Write(&buf, binary.BigEndian, uint64(payloadLen))
	}

	// Masking key (for client only)
	if w.isClient {
		maskKey := make([]byte, 4)
		rand.Read(maskKey)
		buf.Write(maskKey)

		// Mask the payload
		maskedPayload := make([]byte, payloadLen)
		for i := 0; i < payloadLen; i++ {
			maskedPayload[i] = payload[i] ^ maskKey[i%4]
		}
		buf.Write(maskedPayload)
	} else {
		buf.Write(payload)
	}

	return buf.Bytes(), nil
}

// decodeFrame parses a WebSocket frame and extracts payload
func (w *WebSocketObfuscator) decodeFrame(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("frame too short")
	}

	// Check opcode (should be 0x02 for binary)
	opcode := data[0] & 0x0F
	if opcode != 0x02 && opcode != 0x01 {
		return nil, fmt.Errorf("unexpected opcode: %d", opcode)
	}

	// Parse payload length
	masked := (data[1] & 0x80) != 0
	payloadLen := int(data[1] & 0x7F)
	headerLen := 2

	if payloadLen == 126 {
		if len(data) < 4 {
			return nil, fmt.Errorf("frame too short for extended length")
		}
		payloadLen = int(binary.BigEndian.Uint16(data[2:4]))
		headerLen = 4
	} else if payloadLen == 127 {
		if len(data) < 10 {
			return nil, fmt.Errorf("frame too short for extended length")
		}
		payloadLen = int(binary.BigEndian.Uint64(data[2:10]))
		headerLen = 10
	}

	// Handle masking
	var maskKey []byte
	if masked {
		if len(data) < headerLen+4 {
			return nil, fmt.Errorf("frame too short for mask key")
		}
		maskKey = data[headerLen : headerLen+4]
		headerLen += 4
	}

	// Extract payload
	if len(data) < headerLen+payloadLen {
		return nil, fmt.Errorf("frame too short for payload")
	}
	payload := make([]byte, payloadLen)
	copy(payload, data[headerLen:headerLen+payloadLen])

	// Unmask if needed
	if masked {
		for i := 0; i < payloadLen; i++ {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, nil
}

// GenerateHandshakeRequest creates a WebSocket upgrade request
func (w *WebSocketObfuscator) GenerateHandshakeRequest() ([]byte, string) {
	// Generate random WebSocket key
	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", w.path))
	buf.WriteString(fmt.Sprintf("Host: %s\r\n", w.host))
	buf.WriteString("Upgrade: websocket\r\n")
	buf.WriteString("Connection: Upgrade\r\n")
	buf.WriteString(fmt.Sprintf("Sec-WebSocket-Key: %s\r\n", wsKey))
	buf.WriteString("Sec-WebSocket-Version: 13\r\n")
	buf.WriteString(fmt.Sprintf("User-Agent: %s\r\n", w.userAgent))
	buf.WriteString("Origin: https://" + w.host + "\r\n")
	buf.WriteString("\r\n")

	return buf.Bytes(), wsKey
}

// GenerateHandshakeResponse creates a WebSocket upgrade response
func (w *WebSocketObfuscator) GenerateHandshakeResponse(clientKey string) []byte {
	// Calculate accept key per RFC 6455
	acceptKey := computeAcceptKey(clientKey)

	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	buf.WriteString("Upgrade: websocket\r\n")
	buf.WriteString("Connection: Upgrade\r\n")
	buf.WriteString(fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", acceptKey))
	buf.WriteString("\r\n")

	return buf.Bytes()
}

// ValidateHandshakeResponse validates the server's WebSocket response
func (w *WebSocketObfuscator) ValidateHandshakeResponse(response []byte, originalKey string) error {
	// Check for 101 status
	if !bytes.Contains(response, []byte("101")) {
		return fmt.Errorf("expected HTTP 101 response")
	}

	// Check for upgrade headers
	if !bytes.Contains(bytes.ToLower(response), []byte("upgrade: websocket")) {
		return fmt.Errorf("missing Upgrade header")
	}

	// Validate accept key
	expectedAccept := computeAcceptKey(originalKey)
	if !bytes.Contains(response, []byte(expectedAccept)) {
		return fmt.Errorf("invalid Sec-WebSocket-Accept key")
	}

	return nil
}

// ParseHandshakeRequest parses a WebSocket upgrade request and extracts the key
func (w *WebSocketObfuscator) ParseHandshakeRequest(request []byte) (string, error) {
	// Find Sec-WebSocket-Key header
	lines := strings.Split(string(request), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return "", fmt.Errorf("Sec-WebSocket-Key not found")
}

// computeAcceptKey calculates the WebSocket accept key per RFC 6455
func computeAcceptKey(clientKey string) string {
	const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(clientKey + magicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// CreateCoverResponse generates a realistic HTTP response for cover website
// This is used when non-WebSocket requests hit the server (e.g., DPI active probing)
func CreateCoverResponse(statusCode int) []byte {
	var buf bytes.Buffer

	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Unknown"
	}

	buf.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText))
	buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	buf.WriteString("Server: nginx/1.24.0\r\n")
	buf.WriteString("Connection: keep-alive\r\n")

	body := ""
	switch statusCode {
	case 200:
		body = `<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body><h1>Welcome to our website</h1><p>Under construction.</p></body>
</html>`
	case 404:
		body = `<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body>
</html>`
	case 403:
		body = `<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body><h1>403 Forbidden</h1><p>Access denied.</p></body>
</html>`
	}

	buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	buf.WriteString("\r\n")
	buf.WriteString(body)

	return buf.Bytes()
}
