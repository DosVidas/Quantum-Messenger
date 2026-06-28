package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"33lr-framework/pkg/crypto"
	"33lr-framework/pkg/dga"
	"33lr-framework/pkg/c2"
	"quantumguard/pkg/ai"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type User struct {
	PublicKey string `json:"publicKey"` // Hex encoded SPKI
	Alias     string `json:"alias"`
}

type ChatMessage struct {
	ID        int    `json:"id"`
	From      string `json:"from"` // Alias
	PublicKey string `json:"publicKey"`
	Text      string `json:"text"`
	Timestamp string `json:"timestamp"`
	IsSystem  bool   `json:"isSystem"`
	WireData  string `json:"wireData,omitempty"`
}

type Store struct {
	Users    map[string]User `json:"users"`
	Messages []ChatMessage   `json:"messages"`
	mu       sync.RWMutex
}

func NewStore() *Store {
	s := &Store{
		Users:    make(map[string]User),
		Messages: []ChatMessage{},
	}
	s.load()
	return s
}

func (s *Store) load() {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile("quantum_data.json")
	if err == nil {
		if err := json.Unmarshal(data, s); err != nil {
			log.Printf("[STORE] Error loading data: %v", err)
		}
	}
}

func (s *Store) save() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile("quantum_data.json", data, 0644)
}

type MessengerServer struct {
	c2Server     *c2.C2Server
	store        *Store
	userSecrets  map[string][]byte
	serverKeys   *crypto.Keys33LR
	seed         string
	clients      map[*websocket.Conn]bool
	broadcast    chan ChatMessage
	challenges   map[string]string
	detector     *ai.AnomalyDetector
	mu           sync.RWMutex
}

func NewMessengerServer(seed string) *MessengerServer {
	keys, err := crypto.GenerateKeys33LR()
	if err != nil {
		log.Fatalf("[CORE] Failed to generate Kyber keys: %v", err)
	}
	s := &MessengerServer{
		c2Server:    c2.NewC2Server(keys.PrivateKey),
		store:       NewStore(),
		userSecrets: make(map[string][]byte),
		serverKeys:  keys,
		seed:        seed,
		clients:     make(map[*websocket.Conn]bool),
		broadcast:   make(chan ChatMessage, 100),
		challenges:  make(map[string]string),
		detector:    ai.NewAnomalyDetector(),
	}
	go s.run()
	return s
}

func (s *MessengerServer) run() {
	for msg := range s.broadcast {
		s.mu.RLock()
		for client := range s.clients {
			err := client.WriteJSON(msg)
			if err != nil {
				log.Printf("[WS] Broadcast error: %v", err)
				client.Close()
				s.mu.RUnlock()
				s.mu.Lock()
				delete(s.clients, client)
				s.mu.Unlock()
				s.mu.RLock()
			}
		}
		s.mu.RUnlock()
	}
}

func (s *MessengerServer) jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *MessengerServer) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func (s *MessengerServer) handleWS(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] Upgrade Error: %v", err)
		return
	}
	defer ws.Close()

	s.mu.Lock()
	s.clients[ws] = true
	s.mu.Unlock()

	log.Println("[WS] New client connected")

	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			s.mu.Lock()
			delete(s.clients, ws)
			s.mu.Unlock()
			log.Println("[WS] Client disconnected")
			break
		}
	}
}

func (s *MessengerServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	phase := dga.GetLunaPhase(now)
	domain := dga.GenerateDomain(s.seed, now, "onion")

	s.jsonResponse(w, map[string]interface{}{
		"status":      "OPERATIONAL",
		"protocol":    "33LR-v1.0-AUTH",
		"luna_phase":  phase.String(),
		"active_node": domain,
		"encryption":  "Kyber-1024 + AES-256-GCM-Polymorphic",
		"time":        now.Format(time.RFC3339),
	}, http.StatusOK)
}

func safeTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *MessengerServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req User
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.store.mu.Lock()
	s.store.Users[req.PublicKey] = req
	s.store.mu.Unlock()
	s.store.save()

	log.Printf("[AUTH] User registered: %s (%s...)", req.Alias, safeTruncate(req.PublicKey, 10))
	s.jsonResponse(w, map[string]string{"status": "REGISTERED"}, http.StatusCreated)
}

func (s *MessengerServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	nonceBytes := make([]byte, 32)
	rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	s.mu.Lock()
	s.challenges[req.PublicKey] = nonce
	s.mu.Unlock()

	s.jsonResponse(w, map[string]string{"nonce": nonce}, http.StatusOK)
}

func (s *MessengerServer) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string `json:"publicKey"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	nonce, ok := s.challenges[req.PublicKey]
	if ok {
		delete(s.challenges, req.PublicKey)
	}
	s.mu.Unlock()

	if !ok {
		http.Error(w, "No challenge found", http.StatusForbidden)
		return
	}

	pkBytes, _ := hex.DecodeString(req.PublicKey)
	pubInterface, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		http.Error(w, "Invalid Public Key format", http.StatusBadRequest)
		return
	}
	pub, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		http.Error(w, "Not an ECDSA public key", http.StatusBadRequest)
		return
	}

	sigBytes, _ := hex.DecodeString(req.Signature)
	if len(sigBytes) != 64 {
		http.Error(w, "Invalid signature length", http.StatusBadRequest)
		return
	}

	r_sig := new(big.Int).SetBytes(sigBytes[:32])
	s_sig := new(big.Int).SetBytes(sigBytes[32:])

	digest := sha256.Sum256([]byte(nonce))
	if ecdsa.Verify(pub, digest[:], r_sig, s_sig) {
		log.Printf("[AUTH] Authentication successful: %s...", safeTruncate(req.PublicKey, 10))
		s.jsonResponse(w, map[string]string{"status": "AUTHENTICATED"}, http.StatusOK)
	} else {
		log.Printf("[AUTH] Authentication failed: %s...", safeTruncate(req.PublicKey, 10))
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
	}
}

func (s *MessengerServer) handleHandshake(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User       string `json:"user"`
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ss, err := s.c2Server.ProcessInitialKEM(req.Ciphertext)
	if err != nil {
		log.Printf("[CRYPTO] KEM Decapsulation Failed: %v", err)
		http.Error(w, "KEM Decapsulation Failed", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.userSecrets[req.User] = ss
	s.mu.Unlock()

	s.jsonResponse(w, map[string]string{"status": "SECURE_CHANNEL_ESTABLISHED"}, http.StatusOK)
}

func (s *MessengerServer) handleGetPK(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, map[string][]byte{"pubkey": s.serverKeys.PublicKey}, http.StatusOK)
}

func (s *MessengerServer) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User string `json:"user"`
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// AI Anomaly Detection
	analysis, _ := s.detector.AnalyzeTraffic(len(req.Text), 1.0, r.UserAgent())
	log.Printf("[AI] Analysis for %s: %s", safeTruncate(req.User, 8), analysis)

	s.mu.RLock()
	sharedSecret, ok := s.userSecrets[req.User]
	s.mu.RUnlock()

	if !ok {
		http.Error(w, "Secure handshake required", http.StatusForbidden)
		return
	}

	// Simulation of processing and broadcasting
	payload, salt, err := crypto.Encrypt33LR([]byte(req.Text), sharedSecret)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}
	
	wirePacket := append(salt, payload...)
	wireHex := hex.EncodeToString(wirePacket)

	decryptedText, err := s.c2Server.ProcessPolymorphicMessage(wirePacket, sharedSecret)
	if err != nil {
		http.Error(w, "Decryption failed at C2", http.StatusInternalServerError)
		return
	}

	s.store.mu.Lock()
	user, exists := s.store.Users[req.User]
	alias := "Unknown"
	if exists {
		alias = user.Alias
	}

	msg := ChatMessage{
		ID:        len(s.store.Messages) + 1,
		From:      alias,
		PublicKey: req.User,
		Text:      decryptedText,
		Timestamp: time.Now().Format("15:04:05"),
		WireData:  wireHex[:32] + "...",
	}

	s.store.Messages = append(s.store.Messages, msg)
	s.store.mu.Unlock()
	s.store.save()

	s.broadcast <- msg
	s.jsonResponse(w, msg, http.StatusAccepted)
}

func (s *MessengerServer) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	s.jsonResponse(w, s.store.Messages, http.StatusOK)
}

func main() {
	server := NewMessengerServer("33LR-MESSENGER-ALPHA-v2")

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", server.handleWS)
	mux.HandleFunc("/api/status", server.cors(server.handleStatus))
	mux.HandleFunc("/api/pk", server.cors(server.handleGetPK))
	mux.HandleFunc("/api/handshake", server.cors(server.handleHandshake))
	
	mux.HandleFunc("/api/auth/register", server.cors(server.handleRegister))
	mux.HandleFunc("/api/auth/challenge", server.cors(server.handleChallenge))
	mux.HandleFunc("/api/auth/verify", server.cors(server.handleVerify))

	mux.HandleFunc("/api/messages/send", server.cors(server.handleSendMessage))
	mux.HandleFunc("/api/messages/get", server.cors(server.handleGetMessages))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8086"
	}

	log.Printf("[CORE] Quantum-Messenger Backend starting on :%s...", port)
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[CORE] Server failed: %v", err)
	}
}

