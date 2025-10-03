package fxeccsocket

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"net"
	"sync"
	"time"
)

// Constants
const (
	nonceSize        = 12
	keySize          = 32
	maxMessageSize   = 64 * 1024
	handshakeTimeout = 10 * time.Second
)

// Message types
const (
	msgTypePublicKey = 0x01
	msgTypeEncrypted = 0x02
)

// ECCConn represents an encrypted connection using ECC for key exchange
// and symmetric encryption for data transfer.
type ECCConn struct {
	conn    net.Conn
	privKey *ecdsa.PrivateKey
	pubKey  *ecdsa.PublicKey

	// Symmetric encryption components
	sendAEAD    cipher.AEAD
	recvAEAD    cipher.AEAD
	sendNonce   []byte
	recvNonce   []byte
	sendCounter uint64
	recvCounter uint64

	// Obfuscation components (lazy initialized for performance)
	obfuscationEnabled bool
	obfuscationMode    ObfuscationMode
	obfuscationConfig  *ObfuscationConfig
	obfuscator         obfuscator // Interface for different obfuscation strategies
	obfuscatorInit     sync.Once

	// Buffers for performance optimization
	readBuffer  *sync.Pool
	writeBuffer *sync.Pool
	headerPool  *sync.Pool

	readMu  sync.Mutex
	writeMu sync.Mutex
}

// NewConn creates a new ECCConn from an existing network connection.
// It handles the key exchange handshake and sets up the symmetric encryption.
// isClient indicates whether this connection is acting as a client (true) or server (false).
func NewConn(conn net.Conn, config *Config, isClient bool) (*ECCConn, error) {
	if config == nil {
		config = &Config{Curve: elliptic.P256()}
	}
	if config.Curve == nil {
		config.Curve = elliptic.P256()
	}

	eccConn := &ECCConn{
		conn: conn,
		// Initialize object pools for performance
		readBuffer: &sync.Pool{
			New: func() interface{} { return make([]byte, 0, 4096) },
		},
		writeBuffer: &sync.Pool{
			New: func() interface{} { return make([]byte, 0, 4096) },
		},
		headerPool: &sync.Pool{
			New: func() interface{} { return make([]byte, 5) },
		},
	}

	// Setup obfuscation configuration (lazy initialization for performance)
	if config.Obfuscation != nil && config.Obfuscation.Enabled {
		eccConn.obfuscationEnabled = true
		eccConn.obfuscationMode = config.Obfuscation.Mode
		eccConn.obfuscationConfig = config.Obfuscation
	}

	// Key management: use provided private key or generate ephemeral key
	if config.PrivateKey != nil && !config.UseEphemeralKey {
		eccConn.privKey = config.PrivateKey
	} else {
		privKey, err := ecdsa.GenerateKey(config.Curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		eccConn.privKey = privKey
	}

	// Set handshake timeout
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	var handshakeErr error
	if isClient {
		handshakeErr = eccConn.clientHandshake()
	} else {
		handshakeErr = eccConn.serverHandshake()
	}

	if handshakeErr != nil {
		conn.Close()
		return nil, handshakeErr
	}

	return eccConn, nil
}

// clientHandshake performs the client-side handshake protocol:
// 1. Send client's public key to server
// 2. Receive server's public key
// 3. Generate shared secret and derive encryption keys
func (ec *ECCConn) clientHandshake() error {
	// Send public key
	if err := ec.sendPublicKey(); err != nil {
		return err
	}
	// Receive server's public key
	if err := ec.receivePublicKey(); err != nil {
		return err
	}
	// Generate shared secret
	return ec.generateSharedSecret(true)
}

// serverHandshake performs the server-side handshake protocol:
// 1. Receive client's public key
// 2. Send server's public key to client
// 3. Generate shared secret and derive encryption keys
func (ec *ECCConn) serverHandshake() error {
	// Receive client's public key
	if err := ec.receivePublicKey(); err != nil {
		return err
	}
	// Send public key
	if err := ec.sendPublicKey(); err != nil {
		return err
	}
	// Generate shared secret
	return ec.generateSharedSecret(false)
}

// sendPublicKey sends the public key over the connection in a formatted message.
// Message format: [1 byte type][2 byte length][variable length public key bytes]
func (ec *ECCConn) sendPublicKey() error {
	pubKeyBytes := elliptic.Marshal(ec.privKey.Curve, ec.privKey.PublicKey.X, ec.privKey.PublicKey.Y)

	msg := make([]byte, 3+len(pubKeyBytes))
	msg[0] = msgTypePublicKey
	binary.BigEndian.PutUint16(msg[1:3], uint16(len(pubKeyBytes)))
	copy(msg[3:], pubKeyBytes)

	_, err := ec.conn.Write(msg)
	return err
}

// receivePublicKey receives and parses a public key from the connection.
// It validates the message type and size before unmarshaling the public key.
func (ec *ECCConn) receivePublicKey() error {
	header := make([]byte, 3)
	if _, err := io.ReadFull(ec.conn, header); err != nil {
		return err
	}

	if header[0] != msgTypePublicKey {
		return errors.New("unexpected message type")
	}

	length := binary.BigEndian.Uint16(header[1:3])
	if length > 1024 {
		return errors.New("public key too large")
	}

	pubKeyBytes := make([]byte, length)
	if _, err := io.ReadFull(ec.conn, pubKeyBytes); err != nil {
		return err
	}

	x, y := elliptic.Unmarshal(ec.privKey.Curve, pubKeyBytes)
	if x == nil {
		return errors.New("invalid public key")
	}

	ec.pubKey = &ecdsa.PublicKey{
		Curve: ec.privKey.Curve,
		X:     x,
		Y:     y,
	}
	return nil
}

// generateSharedSecret computes the ECDH shared secret using the local private key
// and remote public key. The shared secret is then used to derive symmetric encryption keys.
// isClient parameter determines the key derivation context for differentiating client/server keys.
func (ec *ECCConn) generateSharedSecret(isClient bool) error {
	if ec.pubKey == nil {
		return errors.New("no public key available")
	}

	// Compute ECDH shared secret (X coordinate)
	sharedX, _ := ec.privKey.Curve.ScalarMult(ec.pubKey.X, ec.pubKey.Y, ec.privKey.D.Bytes())
	if sharedX == nil {
		return errors.New("failed to compute shared secret")
	}

	// Convert X coordinate to bytes
	sharedSecret := sharedX.Bytes()

	// Pad to appropriate length
	curveSize := (ec.privKey.Curve.Params().BitSize + 7) / 8
	if len(sharedSecret) < curveSize {
		padded := make([]byte, curveSize)
		copy(padded[curveSize-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}

	return ec.deriveKeys(sharedSecret, isClient)
}

// deriveKeys uses HKDF to derive symmetric encryption keys from the shared secret.
// Different keys are derived for sending and receiving directions to prevent replay attacks.
// The isClient parameter determines which key derivation context to use.
func (ec *ECCConn) deriveKeys(sharedSecret []byte, isClient bool) error {
	// Use HKDF for key derivation
	salt := []byte("ecc-socket-salt")

	var sendKey, recvKey []byte

	if isClient {
		// Client: use "client_key" for sending, "server_key" for receiving
		sendKey = deriveKey(sharedSecret, salt, []byte("client_key"))
		recvKey = deriveKey(sharedSecret, salt, []byte("server_key"))
	} else {
		// Server: use "server_key" for sending, "client_key" for receiving
		sendKey = deriveKey(sharedSecret, salt, []byte("server_key"))
		recvKey = deriveKey(sharedSecret, salt, []byte("client_key"))
	}

	// Initialize AEAD ciphers
	sendAEAD, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return err
	}

	recvAEAD, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return err
	}

	ec.sendAEAD = sendAEAD
	ec.recvAEAD = recvAEAD

	// Initialize nonces (start from all zeros)
	ec.sendNonce = make([]byte, nonceSize)
	ec.recvNonce = make([]byte, nonceSize)
	ec.sendCounter = 0
	ec.recvCounter = 0

	return nil
}

// Read reads encrypted data from the connection, decrypts it, and returns the plaintext.
// It handles the message framing and decryption using the receiving AEAD cipher.
// The nonce is updated for each message to ensure uniqueness.
func (ec *ECCConn) Read(b []byte) (int, error) {
	// Get header from pool and defer return
	header := ec.headerPool.Get().([]byte)
	defer ec.headerPool.Put(header)

	// Read message header
	if _, err := io.ReadFull(ec.conn, header[:5]); err != nil {
		return 0, err
	}

	if header[0] != msgTypeEncrypted {
		return 0, errors.New("unexpected message type")
	}

	length := binary.BigEndian.Uint32(header[1:5])
	if length > maxMessageSize*2 { // Allow larger size for obfuscation
		return 0, errors.New("message too large")
	}

	// Read encrypted data
	encryptedData := make([]byte, length)
	if _, err := io.ReadFull(ec.conn, encryptedData); err != nil {
		return 0, err
	}

	// Initialize obfuscator if needed (lazy initialization for performance)
	if ec.obfuscationEnabled {
		ec.obfuscatorInit.Do(func() {
			ec.obfuscator = createObfuscator(ec.obfuscationMode, ec.obfuscationConfig, false)
		})

		var err error
		encryptedData, err = ec.obfuscator.deobfuscate(encryptedData)
		if err != nil {
			return 0, err
		}
	}

	ec.readMu.Lock()
	// Update nonce and decrypt
	binary.BigEndian.PutUint64(ec.recvNonce[4:], ec.recvCounter)
	plaintext, err := ec.recvAEAD.Open(nil, ec.recvNonce, encryptedData, nil)
	if err != nil {
		return 0, err
	}
	ec.recvCounter++

	if len(plaintext) > len(b) {
		return 0, io.ErrShortBuffer
	}
	copy(b, plaintext)
	ec.readMu.Unlock()
	return len(plaintext), nil
}

// Write encrypts the plaintext data and writes it to the connection.
// It handles message framing and encryption using the sending AEAD cipher.
// The nonce is updated for each message to ensure uniqueness.
func (ec *ECCConn) Write(b []byte) (int, error) {
	if len(b) > maxMessageSize {
		return 0, errors.New("message too large")
	}

	ec.writeMu.Lock()
	// Update nonce and encrypt
	binary.BigEndian.PutUint64(ec.sendNonce[4:], ec.sendCounter)
	encrypted := ec.sendAEAD.Seal(nil, ec.sendNonce, b, nil)
	ec.sendCounter++

	// Initialize obfuscator if needed (lazy initialization for performance)
	if ec.obfuscationEnabled {
		ec.obfuscatorInit.Do(func() {
			ec.obfuscator = createObfuscator(ec.obfuscationMode, ec.obfuscationConfig, true)
		})

		var err error
		encrypted, err = ec.obfuscator.obfuscate(encrypted)
		if err != nil {
			return 0, err
		}
	}

	// Get buffer from pool for performance
	msgBuf := ec.writeBuffer.Get().([]byte)
	defer ec.writeBuffer.Put(msgBuf)

	// Ensure buffer has enough capacity
	if cap(msgBuf) < 5+len(encrypted) {
		msgBuf = make([]byte, 5+len(encrypted))
	} else {
		msgBuf = msgBuf[:5+len(encrypted)]
	}

	// Construct message
	msgBuf[0] = msgTypeEncrypted
	binary.BigEndian.PutUint32(msgBuf[1:5], uint32(len(encrypted)))
	copy(msgBuf[5:], encrypted)
	ec.writeMu.Unlock()

	_, err := ec.conn.Write(msgBuf)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close closes the underlying network connection.
func (ec *ECCConn) Close() error {
	return ec.conn.Close()
}

// LocalAddr returns the local network address.
func (ec *ECCConn) LocalAddr() net.Addr {
	return ec.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (ec *ECCConn) RemoteAddr() net.Addr {
	return ec.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
func (ec *ECCConn) SetDeadline(t time.Time) error {
	return ec.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (ec *ECCConn) SetReadDeadline(t time.Time) error {
	return ec.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
func (ec *ECCConn) SetWriteDeadline(t time.Time) error {
	return ec.conn.SetWriteDeadline(t)
}

// GetPublicKey returns the public key of the local endpoint.
func (ec *ECCConn) GetPublicKey() *ecdsa.PublicKey {
	return &ec.privKey.PublicKey
}
