// Package umbra provides encrypted TCP connections using Elliptic Curve Cryptography
// for key exchange and ChaCha20-Poly1305 for authenticated encryption.
//
// The package enables secure communication over TCP with forward secrecy support
// through ephemeral key exchange. It includes advanced traffic obfuscation capabilities
// designed to bypass Deep Packet Inspection (DPI) systems.
//
// # Features
//
//   - End-to-end encryption using ECDH key exchange and ChaCha20-Poly1305
//   - Forward secrecy with ephemeral keys
//   - Traffic obfuscation to evade DPI detection
//   - Real TLS wrapper for advanced stealth
//   - WebSocket frame encapsulation
//   - Self-signed certificate generation
//
// # Basic Usage
//
//	// Server side
//	listener, _ := umbra.Listen("tcp", ":8080", nil)
//	conn, _ := listener.Accept()
//
//	// Client side
//	conn, _ := umbra.Dial("tcp", "localhost:8080", nil)
//
// # Advanced Usage with DPI Bypass
//
// For environments with Deep Packet Inspection (such as some ISPs in China),
// use the advanced obfuscation mode:
//
//	// Generate self-signed certificate
//	certPEM, keyPEM, _ := umbra.GenerateSelfSignedCert([]string{"pool.yoursite.com"})
//
//	// Server config
//	serverConfig := &umbra.Config{
//	    TLS: &umbra.TLSConfig{
//	        CertPEM: certPEM,
//	        KeyPEM:  keyPEM,
//	    },
//	    Obfuscation: &umbra.ObfuscationConfig{
//	        Enabled:   true,
//	        Level:     umbra.ObfuscationLevelAdvanced,
//	        Mode:      umbra.ObfuscationWebSocket,
//	        Domain:    "pool.yoursite.com",
//	        CoverPath: "/ws",
//	    },
//	}
//
//	// Client config
//	clientConfig := &umbra.Config{
//	    TLS: &umbra.TLSConfig{
//	        ServerName: "pool.yoursite.com",
//	        SkipVerify: true,
//	    },
//	    Obfuscation: &umbra.ObfuscationConfig{
//	        Enabled:   true,
//	        Level:     umbra.ObfuscationLevelAdvanced,
//	        Mode:      umbra.ObfuscationWebSocket,
//	        Domain:    "pool.yoursite.com",
//	    },
//	}
//
// # Obfuscation Levels
//
//   - ObfuscationLevelBasic: Padding and header obfuscation (no extra config needed)
//   - ObfuscationLevelAdvanced: TLS + WebSocket encapsulation (requires Domain and TLS cert)
//
// # Obfuscation Modes
//
//   - ObfuscationNone: No obfuscation
//   - ObfuscationHTTP: HTTP traffic obfuscation
//   - ObfuscationRandom: Random padding obfuscation
//   - ObfuscationWebSocket: WebSocket frame encapsulation (recommended for DPI bypass)
//
// # Security Considerations
//
//   - Uses P256 curve by default (configurable to P384, P521)
//   - Implements HKDF for key derivation
//   - Includes replay protection through monotonic counters
//   - TLS 1.2/1.3 for advanced obfuscation mode
//   - Do NOT use google.com or similar domains for SNI spoofing (will be detected)
//
// # Important Notes for Advanced Mode
//
// When using ObfuscationLevelAdvanced, you MUST:
//  1. Use a domain you control (e.g., "pool.yoursite.com")
//  2. Configure TLS certificates (self-signed or Let's Encrypt)
//  3. Optionally set up Nginx as reverse proxy for cover website
//
// Using domains like google.com or cloudflare.com will be detected by active probing
// and may result in IP blocking.
package umbra
