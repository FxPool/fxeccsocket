package fxeccsocket

import (
	"crypto/elliptic"
	"net"
)

// Dial establishes an encrypted connection to the specified network address.
// It performs a handshake to exchange public keys and derive symmetric encryption keys.
func Dial(network, address string, config *Config) (*ECCConn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, config, true)
}

// Listen creates a listener for encrypted connections on the specified network address.
func Listen(network, address string, config *Config) (*ECCListener, error) {
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = &Config{Curve: elliptic.P256()}
	}

	return &ECCListener{
		listener: listener,
		config:   config,
	}, nil
}
