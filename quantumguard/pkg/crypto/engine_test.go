package crypto

import (
	"bytes"
	"testing"
)

func TestHybridEncryption(t *testing.T) {
	// 1. Generate keys for recipient
	recipientKeys, err := GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// 2. Sender wants to send a secret message
	message := []byte("This is a highly confidential message protected by QuantumGuard.")

	// 3. Sender encapsulates a shared secret for the recipient
	ct, ssSender, err := EncapsulatePackage(recipientKeys.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encapsulate: %v", err)
	}

	// 4. Sender encrypts the message with the shared secret
	ciphertext, err := Encrypt(message, ssSender)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// --- Simulation of transit ---

	// 5. Recipient decapsulates the shared secret using their private key
	ssRecipient, err := DecapsulatePackage(recipientKeys.PrivateKey, ct)
	if err != nil {
		t.Fatalf("Failed to decapsulate: %v", err)
	}

	// 6. Verify shared secrets match
	if !bytes.Equal(ssSender, ssRecipient) {
		t.Fatal("Shared secrets do not match!")
	}

	// 7. Recipient decrypts the message
	plaintext, err := Decrypt(ciphertext, ssRecipient)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// 8. Verify the original message
	if !bytes.Equal(message, plaintext) {
		t.Errorf("Decrypted message does not match original. Got: %s", string(plaintext))
	}
}

func TestSerialization(t *testing.T) {
	keys, _ := GenerateKeys()

	// Public Key serialization
	pkBytes, err := MarshalPublicKey(keys.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	pkUnmarshaled, err := UnmarshalPublicKey(pkBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal public key: %v", err)
	}

	if !keys.PublicKey.Equal(pkUnmarshaled) {
		t.Error("Unmarshaled public key is not equal to original")
	}

	// Private Key serialization
	skBytes, err := MarshalPrivateKey(keys.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	skUnmarshaled, err := UnmarshalPrivateKey(skBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal private key: %v", err)
	}

	if !keys.PrivateKey.Equal(skUnmarshaled) {
		t.Error("Unmarshaled private key is not equal to original")
	}
}
