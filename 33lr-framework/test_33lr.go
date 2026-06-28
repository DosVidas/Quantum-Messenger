package main

import (
	"fmt"
	"log"

	"33lr-framework/pkg/crypto"
	"33lr-framework/pkg/dga"
	"time"
)

func main() {
	fmt.Println("--- 33LR Protocol Test ---")

	// 1. Generar llaves Post-Cuánticas (Kyber-1024)
	fmt.Println("[1] Generando llaves Kyber-1024...")
	keys, err := crypto.GenerateKeys33LR()
	if err != nil {
		log.Fatalf("Error generando llaves: %v", err)
	}
	fmt.Printf("Llave Pública (primeros 16 bytes): %x...\n", keys.PublicKey[:16])

	// 2. Simular el intercambio de llaves (Encapsulación)
	// El "cliente" usa la llave pública del servidor para generar un secreto compartido
	fmt.Println("[2] Encapsulando secreto compartido...")
	ciphertext, sharedSecretClient, err := crypto.Encapsulate(keys.PublicKey)
	if err != nil {
		log.Fatalf("Error en encapsulación: %v", err)
	}

	// 3. El "servidor" decapsula el ciphertext con su llave privada
	fmt.Println("[3] Decapsulando en el servidor...")
	sharedSecretServer, err := crypto.Decapsulate(keys.PrivateKey, ciphertext)
	if err != nil {
		log.Fatalf("Error en decapsulación: %v", err)
	}

	// Verificar que los secretos coinciden
	fmt.Printf("Secreto Cliente: %x\n", sharedSecretClient[:16])
	fmt.Printf("Secreto Servidor: %x\n", sharedSecretServer[:16])

	// 4. Cifrado Polimórfico de un mensaje
	message := "MENSAJE SECRETO: La luna está en fase " + dga.GetLunaPhase(time.Now()).String()
	fmt.Printf("\n[4] Cifrando mensaje: \"%s\"\n", message)
	
	payload, salt, err := crypto.Encrypt33LR([]byte(message), sharedSecretClient)
	if err != nil {
		log.Fatalf("Error en cifrado: %v", err)
	}
	fmt.Printf("Payload cifrado (hex): %x\n", payload[:24])
	fmt.Printf("Salt usado: %x\n", salt)

	// 5. Descifrado
	fmt.Println("\n[5] Descifrando mensaje en el destino...")
	decrypted, err := crypto.Decrypt33LR(payload, salt, sharedSecretServer)
	if err != nil {
		log.Fatalf("Error en descifrado: %v", err)
	}

	fmt.Printf("MENSAJE RECUPERADO: %s\n", string(decrypted))
	fmt.Println("\n--- Test Completado con Éxito ---")
}
