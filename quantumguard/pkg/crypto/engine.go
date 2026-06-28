package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/hybrid"
)

// QuantumGuard uses Kyber-768 concatenated with X25519 for a 128-bit quantum security level
// and classical security.
var scheme = hybrid.Kyber768X25519()

// Keys represents a hybrid key pair.
type Keys struct {
	PublicKey  kem.PublicKey
	PrivateKey kem.PrivateKey
}

// GenerateKeys creates a new hybrid PQC key pair.
func GenerateKeys() (*Keys, error) {
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return &Keys{PublicKey: pk, PrivateKey: sk}, nil
}

// EncapsulatePackage creates a shared secret and its encapsulation (ciphertext) for a recipient.
func EncapsulatePackage(recipientPubKey kem.PublicKey) (ct, ss []byte, err error) {
	return scheme.Encapsulate(recipientPubKey)
}

// DecapsulatePackage recovers a shared secret from its encapsulation using a private key.
func DecapsulatePackage(sk kem.PrivateKey, ct []byte) (ss []byte, err error) {
	return scheme.Decapsulate(sk, ct)
}

// Encrypt encrypts data using AES-256-GCM with a key derived from the hybrid shared secret.
func Encrypt(plaintext []byte, sharedSecret []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedSecret[:32]) // Use first 32 bytes for AES-256
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends the ciphertext to the nonce.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using AES-256-GCM.
func Decrypt(ciphertext []byte, sharedSecret []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, encryptedData, nil)
}

// MarshalPublicKey serializes a public key to bytes.
func MarshalPublicKey(pk kem.PublicKey) ([]byte, error) {
	return pk.MarshalBinary()
}

// UnmarshalPublicKey deserializes a public key from bytes.
func UnmarshalPublicKey(data []byte) (kem.PublicKey, error) {
	return scheme.UnmarshalBinaryPublicKey(data)
}

// MarshalPrivateKey serializes a private key to bytes.
func MarshalPrivateKey(sk kem.PrivateKey) ([]byte, error) {
	return sk.MarshalBinary()
}

// UnmarshalPrivateKey deserializes a private key from bytes.
func UnmarshalPrivateKey(data []byte) (kem.PrivateKey, error) {
	return scheme.UnmarshalBinaryPrivateKey(data)
}
