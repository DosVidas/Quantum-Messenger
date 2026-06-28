package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/sha3"
)

var scheme = kyber1024.Scheme()

// Keys33LR represents the post-quantum key pair for 33LR.
type Keys33LR struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GenerateKeys33LR generates a Kyber-1024 key pair.
func GenerateKeys33LR() (*Keys33LR, error) {
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	pkBytes, _ := pk.MarshalBinary()
	skBytes, _ := sk.MarshalBinary()
	return &Keys33LR{PublicKey: pkBytes, PrivateKey: skBytes}, nil
}

// DeriveEphemeralKey implements the Real-time Polymorphism.
// It derives a unique 32-byte key for each packet using SHA3-512 and BLAKE3.
func DeriveEphemeralKey(sharedSecret []byte, salt []byte) []byte {
	// Step 1: SHA3-512 hash of (sharedSecret + salt)
	h := sha3.New512()
	h.Write(sharedSecret)
	h.Write(salt)
	sha3Hash := h.Sum(nil)

	// Step 2: BLAKE3 hash of the SHA3-512 output to get a 32-byte AES key
	b3 := blake3.New()
	b3.Write(sha3Hash)
	return b3.Sum(nil)[:32]
}

// Encrypt33LR encrypts data using the 33LR suite (Polymorphic AES-256-GCM).
func Encrypt33LR(plaintext []byte, sharedSecret []byte) ([]byte, []byte, error) {
	// Generate a random salt for this packet
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}

	// Derive the ephemeral key for this specific packet
	ephemeralKey := DeriveEphemeralKey(sharedSecret, salt)

	block, err := aes.NewCipher(ephemeralKey)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Result is nonce + ciphertext
	payload := append(nonce, ciphertext...)

	return payload, salt, nil
}

// Decrypt33LR decrypts data using the 33LR suite.
func Decrypt33LR(payload []byte, salt []byte, sharedSecret []byte) ([]byte, error) {
	ephemeralKey := DeriveEphemeralKey(sharedSecret, salt)

	block, err := aes.NewCipher(ephemeralKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return nil, fmt.Errorf("payload too short")
	}

	nonce, ciphertext := payload[:nonceSize], payload[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Encapsulate Kyber-1024
func Encapsulate(pkBytes []byte) (ct, ss []byte, err error) {
	pk, err := scheme.UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, nil, err
	}
	return scheme.Encapsulate(pk)
}

// Decapsulate Kyber-1024
func Decapsulate(skBytes []byte, ct []byte) (ss []byte, err error) {
	sk, err := scheme.UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		return nil, err
	}
	return scheme.Decapsulate(sk, ct)
}
