// Package fxeccsocket provides encrypted TCP connections using ECC for key exchange
// and ChaCha20-Poly1305 for symmetric encryption.
//
// Features:
// - Elliptic Curve Cryptography for key exchange
// - Forward secrecy with ephemeral keys
// - Authenticated encryption with ChaCha20-Poly1305
// - Simple API similar to net.Conn
package fxeccsocket
