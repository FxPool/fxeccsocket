package fxeccsocket

import (
	"bytes"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ObfuscationMode defines the type of traffic obfuscation to use
type ObfuscationMode int

const (
	ObfuscationNone   ObfuscationMode = iota // No obfuscation
	ObfuscationHTTP                          // HTTP traffic obfuscation
	ObfuscationHTTPS                         // HTTPS traffic obfuscation
	ObfuscationRandom                        // Random padding obfuscation
)

// ObfuscationConfig holds configuration for traffic obfuscation
type ObfuscationConfig struct {
	Enabled       bool            // Whether obfuscation is enabled
	Mode          ObfuscationMode // Obfuscation mode to use
	Domain        string          // Domain for HTTP/HTTPS obfuscation
	MinDelayMs    int             // Minimum delay in milliseconds
	MaxDelayMs    int             // Maximum delay in milliseconds
	MinPacketSize int             // Minimum packet size for padding
	MaxPacketSize int             // Maximum packet size for padding
}

// obfuscator interface defines the methods for different obfuscation strategies
type obfuscator interface {
	obfuscate(data []byte) ([]byte, error)
	deobfuscate(data []byte) ([]byte, error)
}

// HTTPObfuscator implements HTTP traffic obfuscation
type HTTPObfuscator struct {
	headers      []string
	isClient     bool
	minDelay     time.Duration
	maxDelay     time.Duration
	headerBuffer *bytes.Buffer
	chunkPool    *sync.Pool
}

// RandomObfuscator implements random padding obfuscation
type RandomObfuscator struct {
	minSize     int
	maxSize     int
	paddingPool *sync.Pool
}

// createObfuscator creates an appropriate obfuscator based on the mode
func createObfuscator(mode ObfuscationMode, config *ObfuscationConfig, isClient bool) obfuscator {
	if config == nil {
		config = defaultObfuscationConfig()
	}

	switch mode {
	case ObfuscationHTTP, ObfuscationHTTPS:
		return newHTTPObfuscator(config, isClient)
	case ObfuscationRandom:
		return newRandomObfuscator(config)
	default:
		return &noopObfuscator{}
	}
}

// newHTTPObfuscator creates a new HTTP obfuscator
func newHTTPObfuscator(config *ObfuscationConfig, isClient bool) *HTTPObfuscator {
	obf := &HTTPObfuscator{
		isClient:     isClient,
		headerBuffer: bytes.NewBuffer(nil),
		chunkPool: &sync.Pool{
			New: func() interface{} { return make([]byte, 0, 128) },
		},
	}

	// Set delays
	obf.minDelay = time.Duration(config.MinDelayMs) * time.Millisecond
	obf.maxDelay = time.Duration(config.MaxDelayMs) * time.Millisecond

	// Generate appropriate headers
	domain := config.Domain
	if domain == "" {
		domain = "cdn.google.com"
	}

	if isClient {
		obf.headers = []string{
			fmt.Sprintf("POST /v1/data HTTP/1.1\r\n"),
			fmt.Sprintf("Host: %s\r\n", domain),
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
			"Content-Type: application/octet-stream\r\n",
			"Accept: */*\r\n",
			"Connection: keep-alive\r\n",
		}
	} else {
		obf.headers = []string{
			"HTTP/1.1 200 OK\r\n",
			"Content-Type: application/octet-stream\r\n",
			"Cache-Control: no-cache\r\n",
			"Connection: keep-alive\r\n",
			"Transfer-Encoding: chunked\r\n",
		}
	}

	return obf
}

// obfuscate implements HTTP traffic obfuscation for outgoing data
func (h *HTTPObfuscator) obfuscate(data []byte) ([]byte, error) {
	h.headerBuffer.Reset()

	// Write headers
	for _, header := range h.headers {
		h.headerBuffer.WriteString(header)
	}

	// Add Content-Length for client requests
	if h.isClient && strings.HasPrefix(h.headers[0], "POST") {
		h.headerBuffer.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(data)))
	}

	h.headerBuffer.WriteString("\r\n")

	// Use chunked encoding for better obfuscation
	chunked := h.httpChunkEncode(data)
	result := make([]byte, h.headerBuffer.Len()+len(chunked))
	copy(result, h.headerBuffer.Bytes())
	copy(result[h.headerBuffer.Len():], chunked)

	// Add random delay to simulate real HTTP traffic
	if h.maxDelay > 0 {
		delayMs := h.minDelay + time.Duration(rand.Int63n(int64(h.maxDelay-h.minDelay+1)))
		time.Sleep(delayMs)
	}

	return result, nil
}

// deobfuscate extracts data from HTTP-obfuscated traffic
func (h *HTTPObfuscator) deobfuscate(data []byte) ([]byte, error) {
	// Skip HTTP headers by finding the first empty line
	doubleCRLF := []byte("\r\n\r\n")
	headerEnd := bytes.Index(data, doubleCRLF)
	if headerEnd == -1 {
		return nil, fmt.Errorf("invalid HTTP format")
	}

	bodyStart := headerEnd + len(doubleCRLF)
	body := data[bodyStart:]

	// Handle chunked encoding
	if strings.Contains(strings.ToLower(string(data)), "transfer-encoding: chunked") {
		return h.httpChunkDecode(body)
	}

	return body, nil
}

// httpChunkEncode encodes data using HTTP chunked transfer encoding
func (h *HTTPObfuscator) httpChunkEncode(data []byte) []byte {
	chunkSize := len(data)
	chunkHeader := fmt.Sprintf("%x\r\n", chunkSize)

	// Get buffer from pool
	chunkBuf := h.chunkPool.Get().([]byte)
	defer h.chunkPool.Put(chunkBuf)

	// Ensure sufficient capacity
	if cap(chunkBuf) < len(chunkHeader)+chunkSize+4 {
		chunkBuf = make([]byte, 0, len(chunkHeader)+chunkSize+4)
	} else {
		chunkBuf = chunkBuf[:0]
	}

	chunkBuf = append(chunkBuf, chunkHeader...)
	chunkBuf = append(chunkBuf, data...)
	chunkBuf = append(chunkBuf, "\r\n0\r\n\r\n"...)

	return chunkBuf
}

// httpChunkDecode decodes HTTP chunked transfer encoding
func (h *HTTPObfuscator) httpChunkDecode(data []byte) ([]byte, error) {
	var result bytes.Buffer
	remaining := data

	for len(remaining) > 0 {
		// Find chunk size line
		lineEnd := bytes.Index(remaining, []byte("\r\n"))
		if lineEnd == -1 {
			break
		}

		chunkSizeStr := string(remaining[:lineEnd])
		chunkSize, err := strconv.ParseInt(chunkSizeStr, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk size: %v", err)
		}

		if chunkSize == 0 {
			break // Last chunk
		}

		chunkStart := lineEnd + 2
		chunkEnd := chunkStart + int(chunkSize)
		if chunkEnd > len(remaining) {
			return nil, fmt.Errorf("incomplete chunk")
		}

		// Extract chunk data
		chunkData := remaining[chunkStart:chunkEnd]
		result.Write(chunkData)

		// Move to next chunk
		nextChunk := chunkEnd + 2 // Skip \r\n after chunk data
		if nextChunk >= len(remaining) {
			break
		}
		remaining = remaining[nextChunk:]
	}

	return result.Bytes(), nil
}

// newRandomObfuscator creates a new random padding obfuscator
func newRandomObfuscator(config *ObfuscationConfig) *RandomObfuscator {
	minSize, maxSize := config.MinPacketSize, config.MaxPacketSize
	if minSize <= 0 {
		minSize = 128
	}
	if maxSize <= minSize {
		maxSize = minSize + 1024
	}

	return &RandomObfuscator{
		minSize: minSize,
		maxSize: maxSize,
		paddingPool: &sync.Pool{
			New: func() interface{} { return make([]byte, maxSize) },
		},
	}
}

// obfuscate adds random padding to data
func (r *RandomObfuscator) obfuscate(data []byte) ([]byte, error) {
	targetSize := r.minSize
	if r.maxSize > r.minSize {
		targetSize = r.minSize + rand.Intn(r.maxSize-r.minSize+1)
	}

	if len(data) >= targetSize {
		return data, nil
	}

	paddingSize := targetSize - len(data)

	// Get padding buffer from pool
	padding := r.paddingPool.Get().([]byte)
	defer r.paddingPool.Put(padding)

	if len(padding) < paddingSize {
		padding = make([]byte, paddingSize)
	} else {
		padding = padding[:paddingSize]
	}

	rand.Read(padding)

	// Insert padding at random position for better obfuscation
	insertPos := rand.Intn(len(data) + 1)
	result := make([]byte, 0, targetSize)
	result = append(result, data[:insertPos]...)
	result = append(result, padding...)
	result = append(result, data[insertPos:]...)

	return result, nil
}

// deobfuscate removes random padding from data
func (r *RandomObfuscator) deobfuscate(data []byte) ([]byte, error) {
	// Simple approach: assume original data is at the beginning
	// In practice, you might want to use a more sophisticated approach
	if len(data) <= maxMessageSize {
		return data, nil
	}
	// Return first maxMessageSize bytes (simplified)
	return data[:maxMessageSize], nil
}

// noopObfuscator provides a no-operation obfuscator for when obfuscation is disabled
type noopObfuscator struct{}

func (n *noopObfuscator) obfuscate(data []byte) ([]byte, error) {
	return data, nil
}

func (n *noopObfuscator) deobfuscate(data []byte) ([]byte, error) {
	return data, nil
}

// defaultObfuscationConfig returns a default obfuscation configuration
func defaultObfuscationConfig() *ObfuscationConfig {
	return &ObfuscationConfig{
		Enabled:       true,
		Mode:          ObfuscationHTTPS,
		Domain:        "cdn.google.com",
		MinDelayMs:    5,
		MaxDelayMs:    50,
		MinPacketSize: 128,
		MaxPacketSize: 1460,
	}
}
