package api

// KeyRecord represents a public key stored on the server.
type KeyRecord struct {
	UserID    string `json:"user_id"`
	PublicKey []byte `json:"public_key"` // Marshaled hybrid public key
	CreatedAt int64  `json:"created_at"`
}

// AuditLog represents a security event on the server.
type AuditLog struct {
	ID        string `json:"id"`
	Event     string `json:"event"`
	UserID    string `json:"user_id"`
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
	Metadata  string `json:"metadata"`
}

// Message represents a post-quantum encrypted message bundle.
type Message struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Bundle    []byte `json:"bundle"` // Ciphertext + Encrypted Data
	CreatedAt int64  `json:"created_at"`
}
