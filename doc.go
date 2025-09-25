// doc.go
// Package fxeccsocket provides encrypted TCP connections using Elliptic Curve Cryptography
// for key exchange and ChaCha20-Poly1305 for authenticated encryption.
//
// The package enables secure communication over TCP with forward secrecy support
// through ephemeral key exchange. It implements a handshake protocol similar to TLS
// but with a simpler API designed for specific use cases.
//
// Basic usage:
//
//	// Server side
//	privKey, _ := fxeccsocket.GenerateKey(nil)
//	listener, _ := fxeccsocket.Listen("tcp", ":8080", &fxeccsocket.Config{PrivateKey: privKey})
//
//	// Client side
//	conn, _ := fxeccsocket.Dial("tcp", "localhost:8080", &fxeccsocket.Config{UseEphemeralKey: true})
//
// Security considerations:
// - Uses P256 curve by default (configurable to P384, P521)
// - Implements HKDF for key derivation
// - Includes replay protection through monotonic counters
package fxeccsocket
