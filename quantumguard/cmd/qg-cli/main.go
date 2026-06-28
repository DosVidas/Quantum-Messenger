package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/user/quantumguard/pkg/api"
	"github.com/user/quantumguard/pkg/crypto"
)

const (
	configDir = ".quantumguard"
	serverURL = "http://localhost:8080"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]
	switch command {
	case "keygen":
		handleKeygen()
	case "register":
		handleRegister()
	case "encrypt":
		handleEncrypt()
	case "decrypt":
		handleDecrypt()
	case "send":
		handleSend()
	case "get-messages":
		handleGetMessages()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
	}
}

func printUsage() {
	fmt.Println("QuantumGuard CLI - Post-Quantum Secure Messaging")
	fmt.Println("Usage:")
	fmt.Println("  qg-cli keygen                       Generate hybrid keys")
	fmt.Println("  qg-cli register <user_id>           Register public key with server")
	fmt.Println("  qg-cli encrypt <user_id> <msg>      Encrypt a message for a user")
	fmt.Println("  qg-cli decrypt <ciphertext>         Decrypt a message using local key")
	fmt.Println("  qg-cli send <from_id> <to_id> <msg> Send an encrypted message to a user")
	fmt.Println("  qg-cli get-messages <user_id>       Fetch and decrypt messages from server")
}

func handleKeygen() {
	keys, err := crypto.GenerateKeys()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	home, _ := os.UserHomeDir()
	path := filepath.Join(home, configDir)
	_ = os.MkdirAll(path, 0700)

	pkBytes, _ := crypto.MarshalPublicKey(keys.PublicKey)
	skBytes, _ := crypto.MarshalPrivateKey(keys.PrivateKey)

	_ = os.WriteFile(filepath.Join(path, "public.key"), pkBytes, 0644)
	_ = os.WriteFile(filepath.Join(path, "private.key"), skBytes, 0600)

	fmt.Println("Keys generated and saved in", path)
}

func handleRegister() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: qg-cli register <user_id>")
		return
	}
	userID := os.Args[2]

	home, _ := os.UserHomeDir()
	pkBytes, err := os.ReadFile(filepath.Join(home, configDir, "public.key"))
	if err != nil {
		fmt.Println("Error: Key not found. Run keygen first.")
		return
	}

	req := api.RegisterKeyRequest{
		UserID:    userID,
		PublicKey: pkBytes,
	}
	body, _ := json.Marshal(req)

	resp, err := http.Post(serverURL+"/keys/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("Error connecting to server: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		fmt.Printf("Successfully registered as %s\n", userID)
	} else {
		fmt.Println("Failed to register key.")
	}
}

func handleEncrypt() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: qg-cli encrypt <user_id> <message>")
		return
	}
	targetID := os.Args[2]
	message := os.Args[3]

	// 1. Get recipient public key
	resp, err := http.Get(serverURL + "/keys/get?user_id=" + targetID)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: User %s not found or server offline\n", targetID)
		return
	}
	defer resp.Body.Close()

	var record api.KeyRecord
	json.NewDecoder(resp.Body).Decode(&record)

	pubKey, err := crypto.UnmarshalPublicKey(record.PublicKey)
	if err != nil {
		fmt.Println("Error: Invalid recipient public key")
		return
	}

	// 2. Encapsulate and Encrypt
	ct, ss, err := crypto.EncapsulatePackage(pubKey)
	if err != nil {
		fmt.Println("Error during encapsulation")
		return
	}

	encrypted, err := crypto.Encrypt([]byte(message), ss)
	if err != nil {
		fmt.Println("Error during encryption")
		return
	}

	// 3. Output the bundle (CT + Encrypted Data)
	bundle := append(ct, encrypted...)
	fmt.Printf("%x\n", bundle)
}

func handleDecrypt() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: qg-cli decrypt <ciphertext_hex>")
		return
	}
	bundleHex := os.Args[2]
	var bundle []byte
	fmt.Sscanf(bundleHex, "%x", &bundle)

	home, _ := os.UserHomeDir()
	skBytes, err := os.ReadFile(filepath.Join(home, configDir, "private.key"))
	if err != nil {
		fmt.Println("Error: Private key not found")
		return
	}

	privKey, _ := crypto.UnmarshalPrivateKey(skBytes)

	// Kyber768+X25519 ciphertext size is fixed.
	// We need to know the size. Let's get it from the scheme.
	// For Kyber768 (1088) + X25519 (32) = 1120 bytes.
	// But let's be safe and use a dummy encryption to find out or check docs.
	// From circl: Kyber768 CT = 1088, X25519 CT = 32. Total = 1120.
	ctSize := 1120 

	if len(bundle) < ctSize {
		fmt.Println("Error: Ciphertext too short")
		return
	}

	ct := bundle[:ctSize]
	encryptedData := bundle[ctSize:]

	ss, err := crypto.DecapsulatePackage(privKey, ct)
	if err != nil {
		fmt.Printf("Error: Decapsulation failed: %v\n", err)
		return
	}

	plaintext, err := crypto.Decrypt(encryptedData, ss)
	if err != nil {
		fmt.Println("Error: Decryption failed (wrong key or corrupted data)")
		return
	}

	fmt.Printf("Decrypted message: %s\n", string(plaintext))
}

func handleSend() {
	if len(os.Args) < 5 {
		fmt.Println("Usage: qg-cli send <from_id> <to_id> <message>")
		return
	}
	fromID := os.Args[2]
	toID := os.Args[3]
	message := os.Args[4]

	// 1. Get recipient public key
	resp, err := http.Get(serverURL + "/keys/get?user_id=" + toID)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: User %s not found or server offline\n", toID)
		return
	}
	defer resp.Body.Close()

	var record api.KeyRecord
	json.NewDecoder(resp.Body).Decode(&record)

	pubKey, err := crypto.UnmarshalPublicKey(record.PublicKey)
	if err != nil {
		fmt.Println("Error: Invalid recipient public key")
		return
	}

	// 2. Encapsulate and Encrypt
	ct, ss, err := crypto.EncapsulatePackage(pubKey)
	if err != nil {
		fmt.Println("Error during encapsulation")
		return
	}

	encrypted, err := crypto.Encrypt([]byte(message), ss)
	if err != nil {
		fmt.Println("Error during encryption")
		return
	}
	bundle := append(ct, encrypted...)

	// 3. Send to server
	req := api.SendMessageRequest{
		From:   fromID,
		To:     toID,
		Bundle: bundle,
	}
	body, _ := json.Marshal(req)
	resp, err = http.Post(serverURL+"/messages/send", "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("Error sending message: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		fmt.Println("Message sent successfully!")
	} else {
		fmt.Println("Failed to send message.")
	}
}

func handleGetMessages() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: qg-cli get-messages <user_id>")
		return
	}
	userID := os.Args[2]

	// 1. Fetch messages
	resp, err := http.Get(serverURL + "/messages/get?user_id=" + userID)
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println("Error fetching messages")
		return
	}
	defer resp.Body.Close()

	var msgs []api.Message
	json.NewDecoder(resp.Body).Decode(&msgs)

	if len(msgs) == 0 {
		fmt.Println("No messages found.")
		return
	}

	// 2. Load private key
	home, _ := os.UserHomeDir()
	skBytes, err := os.ReadFile(filepath.Join(home, configDir, "private.key"))
	if err != nil {
		fmt.Println("Error: Private key not found")
		return
	}
	privKey, _ := crypto.UnmarshalPrivateKey(skBytes)
	ctSize := 1120

	// 3. Decrypt and print
	fmt.Printf("Found %d messages:\n", len(msgs))
	for _, msg := range msgs {
		if len(msg.Bundle) < ctSize {
			fmt.Printf("[%s] Error: Message too short\n", msg.From)
			continue
		}

		ct := msg.Bundle[:ctSize]
		encryptedData := msg.Bundle[ctSize:]

		ss, err := crypto.DecapsulatePackage(privKey, ct)
		if err != nil {
			fmt.Printf("[%s] Error: Decapsulation failed\n", msg.From)
			continue
		}

		plaintext, err := crypto.Decrypt(encryptedData, ss)
		if err != nil {
			fmt.Printf("[%s] Error: Decryption failed\n", msg.From)
			continue
		}

		fmt.Printf("[%s]: %s\n", msg.From, string(plaintext))
	}
}
