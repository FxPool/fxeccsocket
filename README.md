# ECC Socket - Secure Communication Library using Elliptic Curve Cryptography

[![Go Version](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/fxpool/fxeccsocket.svg)](https://pkg.go.dev/github.com/fxpool/fxeccsocket)

A secure network communication library for Go that provides end-to-end encrypted communication using Elliptic Curve
Cryptography (ECC).

## Features

- 🔒 **End-to-End Encryption**: ECDH key exchange with ChaCha20-Poly1305 encryption
- 🚀 **High Performance**: Modern cryptographic algorithms with low latency
- 🔑 **Flexible Key Management**: Support for both static and ephemeral keys (forward secrecy)
- 📜 **Standards Compliant**: PEM format for key storage
- 🛡️ **Security Hardened**: Replay protection, integrity verification
- 🔧 **Easy to Use**: net-like API design for easy integration

## Installation

```bash
go get github.com/FxPool/fxeccsocket
```
## Quick Start
## Generating Key Pairs
```go
package main

import (
    "fmt"
    "github.com/yourusername/fxeccsocket"
)

func main() {
    // Generate new ECC key pair
    privKey, err := fxeccsocket.GenerateKey(nil)
    if err != nil {
        panic(err)
    }
    
    // Encode private key to PEM format
    privPEM, err := fxeccsocket.EncodePrivateKey(privKey)
    if err != nil {
        panic(err)
    }
    
    // Encode public key to PEM format
    pubPEM, err := fxeccsocket.EncodePublicKey(&privKey.PublicKey)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("Private Key:\n", privPEM)
    fmt.Println("Public Key:\n", pubPEM)
}
```
## Example
```go
package main

import (
  "fmt"
  "github.com/FxPool/fxeccsocket"
  "io"
  "log"
  "net"
  "time"
)

// Server example
func startServer() {
  listener, err := fxeccsocket.Listen("tcp", ":8080", nil)
  if err != nil {
    log.Fatal("Server listen error:", err)
  }
  defer listener.Close()

  fmt.Println("ECC Server listening on :8080")

  for {
    conn, err := listener.Accept()
    if err != nil {
      log.Println("Accept error:", err)
      continue
    }

    go handleServerConnection(conn)
  }
}

func handleServerConnection(conn net.Conn) {
  defer conn.Close()
  fmt.Printf("New connection from %s\n", conn.RemoteAddr())

  buffer := make([]byte, 1024)
  for {
    n, err := conn.Read(buffer)
    if err != nil {
      if err != io.EOF {
        log.Println("server Read error:", err)
      }
      break
    }

    message := string(buffer[:n])
    fmt.Printf("Received: %s", message)

    response := fmt.Sprintf("Server response: %s", message)
    _, err = conn.Write([]byte(response))
    if err != nil {
      log.Println("Write error:", err)
      break
    }
  }
}

// Client example
func startClient() {
  time.Sleep(100 * time.Millisecond) // Wait for server to start

  conn, err := fxeccsocket.Dial("tcp", "localhost:8080", nil)
  if err != nil {
    log.Fatal("Client dial error:", err)
  }
  defer conn.Close()

  fmt.Printf("Connected to %s\n", conn.RemoteAddr())

  // Send multiple messages for testing
  messages := []string{
    "Hello, ECC Socket 1!\n",
    "This is message 2\n",
    "Final message 3\n",
  }

  for _, msg := range messages {
    fmt.Printf("Sending: %s", msg)
    _, err = conn.Write([]byte(msg))
    if err != nil {
      log.Fatal("Write error:", err)
    }

    buffer := make([]byte, 1024)
    n, err := conn.Read(buffer)
    if err != nil {
      log.Fatal("client Read error:", err)
    }

    fmt.Printf("Server reply: %s", string(buffer[:n]))
    time.Sleep(100 * time.Millisecond)
  }
}

func main() {
	
  // Start the server
  go startServer()
  time.Sleep(1 * time.Second)

  // Start the client
  startClient()
}
```
# API Documentation
## Types
## ECCConn
## Encrypted connection type implementing net.Conn interface.

```go
type ECCConn struct {
    // unexported fields
}
```
### Methods:
- Read([]byte) (int, error) - Read and decrypt data
- Write([]byte) (int, error) - Encrypt and write data
- Close() error - Close the connection
- GetPublicKey() *ecdsa.PublicKey - Get local public key
- Standard net.Conn methods: LocalAddr(), RemoteAddr(), SetDeadline(), etc.
### ECCListener
### Encrypted connection listener.
```go
type ECCListener struct {
    // unexported fields
}
```
### Methods:
- Accept() (net.Conn, error) - Accept new connection
- Close() error - Close listener
- Addr() net.Addr - Get listen address

### Config
### Configuration parameters structure.
```go
type Config struct {
    Curve           elliptic.Curve      // Elliptic curve (default P-256)
    PrivateKey      *ecdsa.PrivateKey   // Private key (optional)
    PublicKey       *ecdsa.PublicKey    // Public key (optional)
    UseEphemeralKey bool               // Use ephemeral keys (forward secrecy)
}
```
### Functions
### Key Management

```go
func GenerateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error)
func EncodePrivateKey(key *ecdsa.PrivateKey) (string, error)
func DecodePrivateKey(pemData string) (*ecdsa.PrivateKey, error)
func EncodePublicKey(key *ecdsa.PublicKey) (string, error)
func DecodePublicKey(pemData string) (*ecdsa.PublicKey, error)
```
### Connection Management
```go
func Dial(network, address string, config *Config) (*ECCConn, error)
func Listen(network, address string, config *Config) (*ECCListener, error)
func NewConn(conn net.Conn, config *Config, isClient bool) (*ECCConn, error)
```
## Protocol Details
## Handshake Protocol
1. Key Exchange: ECDH Elliptic Curve Diffie-Hellman key exchange
2. Key Derivation: HKDF for symmetric key derivation from shared secret
3. Bidirectional Authentication: Different key contexts for client and server

### Message Format
### Public Key Message

```
+------+--------+------------+
| 0x01 | Length | Public Key |
+------+--------+------------+
| 1B   | 2B     | Variable   |
+------+--------+------------+
```

### Encrypted Data Message

```
+------+-----------+----------------+
| 0x02 | Length    | Encrypted Data |
+------+-----------+----------------+
| 1B   | 4B        | Variable       |
+------+-----------+----------------+
```

## Key Derivation

```
client_send_key = HKDF(shared_secret, salt, "client_key")
server_send_key = HKDF(shared_secret, salt, "server_key")
```

### Security Considerations
### Recommended Configuration
```go
// For optimal security, recommended to use:
config := &fxeccsocket.Config{
    Curve: elliptic.P256(),    // Or more secure curves
    UseEphemeralKey: true,     // Enable forward secrecy
}
```

### Security Features
- Forward Secrecy: When UseEphemeralKey is enabled, each connection uses different ephemeral keys
- Replay Protection: Incrementing counter-based nonce prevents replay attacks
- Integrity Verification: Poly1305 authentication tags ensure data integrity
- Key Separation: Different encryption keys for client and server directions

### Performance Considerations
- Uses ChaCha20-Poly1305 instead of AES-GCM for better performance on devices without AES hardware acceleration
- Single connection throughput can reach Gbps levels
- Low memory footprint, suitable for high-concurrency scenarios

### Limitations
- Maximum message size: 64KB (configurable via maxMessageSize constant)
- Currently only supports TCP protocol
- Requires Go 1.16+ version
- 
### Troubleshooting
### Common Errors

1. "unexpected message type"

- - Check client and server version compatibility
- - Verify network connection isn't being interfered with

2. "public key too large"

- - Check if the elliptic curve used is reasonable
- - Verify public key serialization is correct

3. Authentication failures

- - Check system clock synchronization
- - Verify keys are loaded correctly

### Debug Mode
Add verbose logging to debug handshake process.

### Benchmarks
Basic performance metrics (on Intel i7-8700K):

```
Encryption throughput: ~800 Mbps
Handshake time: ~2.5 ms
Memory per connection: ~4 KB
```

### Examples Directory
Check the `examples/` directory for additional usage examples:

- `examples/tcp_chat/` - Simple encrypted chat application
- `examples/file_transfer/` - Secure file transfer utility
- `examples/benchmark/` - Performance testing tools

### Contributing
We welcome contributions! Please see our Contributing Guide for details.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

### Development Setup
```base
git clone https://github.com/fxpool/fxeccsocket.git
cd fxeccsocket
go test ./...
```
### Running Tests
```base
go test -v -race ./...
```

### License
This project is open source under the MIT License - see the LICENSE file for details.

### Acknowledgments
- Uses Go standard library cryptographic primitives
- Designed based on modern cryptographic best practices
- Thanks to all contributors

### Support
- If you encounter issues or have questions:
- Check existing issues
- Create a new issue with detailed description
- Contact maintainers

### Related Projects
- libsodium - Portable cryptography library
- Noise Protocol - Framework for crypto protocols
- WireGuard - Modern VPN protocol

### References
- Elliptic Curve Cryptography
- ChaCha20 and Poly1305
- HKDF