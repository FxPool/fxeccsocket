# ECC Socket - Secure Communication Library using Elliptic Curve Cryptography

[![Go Version](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/FxPool/fxeccsocket.svg)](https://pkg.go.dev/github.com/FxPool/fxeccsocket)

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

