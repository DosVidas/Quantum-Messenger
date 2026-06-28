module quantum-messenger-backend

go 1.26.3

replace 33lr-framework => ../33lr-framework
replace quantumguard => ../quantumguard

require (
	33lr-framework v0.0.0-00010101000000-000000000000
	quantumguard v0.0.0-00010101000000-000000000000
	github.com/gorilla/websocket v1.5.3
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)
