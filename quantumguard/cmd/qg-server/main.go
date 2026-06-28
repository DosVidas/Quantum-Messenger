package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"github.com/user/quantumguard/pkg/api"
)

var jwtKey = []byte(os.Getenv("ADMIN_JWT_SECRET"))

func init() {
	if len(jwtKey) == 0 {
		jwtKey = []byte("super-secret-quantum-key-change-this-in-production")
	}
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type Server struct {
	db          *sql.DB
	useFallback bool
	mu          sync.RWMutex
	memLogs     []api.AuditLog
	memKeys     map[string]api.KeyRecord
	memMsgs     map[string][]api.Message
}

func NewServer(connStr string) *Server {
	s := &Server{
		memKeys: make(map[string]api.KeyRecord),
		memMsgs: make(map[string][]api.Message),
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("DB Open Error: %v. Using in-memory fallback.", err)
		s.useFallback = true
	} else {
		db.SetConnMaxLifetime(time.Second * 5)
		if err := db.Ping(); err != nil {
			log.Printf("Database offline: %v. Using in-memory fallback.", err)
			s.useFallback = true
		} else {
			s.db = db
			s.initDB()
			log.Println("Connected to PostgreSQL successfully.")
		}
	}

	return s
}

func (s *Server) initDB() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS keys (user_id TEXT PRIMARY KEY, public_key BYTEA, created_at BIGINT)`,
		`CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, "from" TEXT, "to" TEXT, bundle BYTEA, created_at BIGINT)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (id TEXT PRIMARY KEY, event TEXT, user_id TEXT, ip TEXT, timestamp BIGINT, metadata TEXT)`,
	}
	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			log.Printf("Table init error: %v", err)
		}
	}
}

func (s *Server) logEvent(event, userID, ip, metadata string) {
	log.Printf("[AUDIT] %s | User: %s | IP: %s | %s", event, userID, ip, metadata)
	
	entry := api.AuditLog{
		ID:        uuid.New().String(),
		Event:     event,
		UserID:    userID,
		IP:        ip,
		Timestamp: time.Now().Unix(),
		Metadata:  metadata,
	}

	s.mu.Lock()
	s.memLogs = append([]api.AuditLog{entry}, s.memLogs...)
	if len(s.memLogs) > 100 {
		s.memLogs = s.memLogs[:100]
	}
	s.mu.Unlock()

	if !s.useFallback && s.db != nil {
		_, _ = s.db.Exec(
			"INSERT INTO audit_logs (id, event, user_id, ip, timestamp, metadata) VALUES ($1, $2, $3, $4, $5, $6)",
			entry.ID, entry.Event, entry.UserID, entry.IP, entry.Timestamp, entry.Metadata,
		)
	}
}

func (s *Server) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func (s *Server) adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString := authHeader[7:]
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	adminUser := os.Getenv("ADMIN_USER")
	adminPass := os.Getenv("ADMIN_PASS")
	if adminUser == "" { adminUser = "admin" }
	if adminPass == "" { adminPass = "quantum2026" }

	if creds.Username != adminUser || creds.Password != adminPass {
		s.logEvent("ADMIN_LOGIN_FAIL", creds.Username, r.RemoteAddr, "")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	s.logEvent("ADMIN_LOGIN_SUCCESS", creds.Username, r.RemoteAddr, "")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }
	var req api.KeyRecord
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { return }

	if !s.useFallback {
		_, err := s.db.Exec("INSERT INTO keys (user_id, public_key, created_at) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO UPDATE SET public_key = $2", req.UserID, req.PublicKey, time.Now().Unix())
		if err == nil {
			s.logEvent("KEY_REGISTER", req.UserID, r.RemoteAddr, "")
			w.WriteHeader(http.StatusCreated)
			return
		}
	}

	s.mu.Lock()
	s.memKeys[req.UserID] = req
	s.mu.Unlock()
	s.logEvent("KEY_REGISTER_MEM", req.UserID, r.RemoteAddr, "")
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleGetKey(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if !s.useFallback {
		var pk []byte
		err := s.db.QueryRow("SELECT public_key FROM keys WHERE user_id = $1", userID).Scan(&pk)
		if err == nil {
			s.logEvent("KEY_LOOKUP", userID, r.RemoteAddr, "")
			json.NewEncoder(w).Encode(map[string]interface{}{"user_id": userID, "public_key": pk})
			return
		}
	}

	s.mu.RLock()
	record, ok := s.memKeys[userID]
	s.mu.RUnlock()
	if ok {
		s.logEvent("KEY_LOOKUP_MEM", userID, r.RemoteAddr, "")
		json.NewEncoder(w).Encode(record)
	} else {
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var req api.Message
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { return }
	req.ID = uuid.New().String()
	req.CreatedAt = time.Now().Unix()

	if !s.useFallback {
		_, err := s.db.Exec("INSERT INTO messages (id, \"from\", \"to\", bundle, created_at) VALUES ($1, $2, $3, $4, $5)", req.ID, req.From, req.To, req.Bundle, req.CreatedAt)
		if err == nil {
			s.logEvent("MSG_SENT", req.From, r.RemoteAddr, "to:"+req.To)
			w.WriteHeader(http.StatusCreated)
			return
		}
	}

	s.mu.Lock()
	s.memMsgs[req.To] = append(s.memMsgs[req.To], req)
	s.mu.Unlock()
	s.logEvent("MSG_SENT_MEM", req.From, r.RemoteAddr, "to:"+req.To)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if !s.useFallback {
		rows, err := s.db.Query("SELECT id, \"from\", \"to\", bundle, created_at FROM messages WHERE \"to\" = $1", userID)
		if err == nil {
			defer rows.Close()
			var msgs []api.Message
			for rows.Next() {
				var m api.Message
				rows.Scan(&m.ID, &m.From, &m.To, &m.Bundle, &m.CreatedAt)
				msgs = append(msgs, m)
			}
			s.logEvent("MSG_FETCH", userID, r.RemoteAddr, "")
			json.NewEncoder(w).Encode(msgs)
			return
		}
	}

	s.mu.RLock()
	msgs := s.memMsgs[userID]
	s.mu.RUnlock()
	s.logEvent("MSG_FETCH_MEM", userID, r.RemoteAddr, "")
	if msgs == nil { msgs = []api.Message{} }
	json.NewEncoder(w).Encode(msgs)
}

func (s *Server) handleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	logs := s.memLogs
	s.mu.RUnlock()
	json.NewEncoder(w).Encode(logs)
}

func main() {
	server := NewServer(os.Getenv("DATABASE_URL"))
	
	http.HandleFunc("/keys/register", server.cors(server.handleRegister))
	http.HandleFunc("/keys/get", server.cors(server.handleGetKey))
	http.HandleFunc("/messages/send", server.cors(server.handleSendMessage))
	http.HandleFunc("/messages/get", server.cors(server.handleGetMessages))
	http.HandleFunc("/admin/login", server.cors(server.handleAdminLogin))
	http.HandleFunc("/admin/logs", server.cors(server.adminMiddleware(server.handleGetAuditLogs)))

	port := ":8080"
	fmt.Printf("QuantumGuard Server starting on %s...\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
