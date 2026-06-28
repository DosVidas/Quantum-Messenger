# ⚛️ QuantumGuard

**QuantumGuard** is a high-performance, hybrid post-quantum secure messaging system. It combines state-of-the-art lattice-based cryptography with classical elliptic curve algorithms to ensure your messages remain private today and resistant to future quantum computer attacks.

## 🚀 Key Features

- **Hybrid Cryptography**: Uses **Kyber-768** (ML-KEM) for quantum resistance and **X25519** for classical security.
- **True End-to-End Encryption**: Key encapsulation and message decryption happen entirely on the client side (Browser or CLI).
- **Multi-Platform**: Includes a robust **Go Backend**, a powerful **CLI tool**, and a sleek **Next.js Dashboard**.
- **Responsive Design**: Modern "Cyberpunk" UI that works perfectly on desktop and mobile devices.
- **Zero Trust Architecture**: Private keys never leave your device.

## 🏗️ Architecture

1.  **Backend (`qg-server`)**: A lightweight Go service that acts as a public key directory and an encrypted message relay.
2.  **CLI (`qg-cli`)**: A Go-based command-line tool for power users.
3.  **Dashboard**: A React application (Next.js 15+) using `@noble` libraries for browser-native PQC operations.

## 🛠️ Tech Stack

- **Languages**: Go 1.22+, TypeScript.
- **Encryption**: AES-256-GCM.
- **PQC Libraries**: `cloudflare/circl` (Go), `@noble/post-quantum` (JS).
- **Frontend**: Next.js 15, Tailwind CSS, Lucide Icons.

---

## 🚦 Getting Started

### 1. Prerequisites
- Go 1.22 or higher
- Node.js 18 or higher
- npm or yarn

### 2. Backend Setup
```bash
cd quantumguard
go mod tidy
go build -o qg-server ./cmd/qg-server
./qg-server
```
The server will start on `http://localhost:8080`.

### 3. Dashboard Setup
```bash
cd quantumguard/dashboard
npm install
npm run dev
```
Open `http://localhost:3000` to access the web interface.

### 4. CLI Usage
```bash
cd quantumguard
go build -o qg-cli ./cmd/qg-cli

# Generate your keys
./qg-cli keygen

# Register your identity
./qg-cli register your_nickname

# Send a message
./qg-cli send your_nickname recipient_nickname "Your secret message"

# Check your messages
./qg-cli get-messages your_nickname
```

## 🔒 Security Implementation Details

QuantumGuard implements a **KEM-DEM** (Key Encapsulation Mechanism - Data Encapsulation Mechanism) hybrid construction:
- **KEM**: Concatenation of `Kyber768` and `X25519` public keys.
- **Secret Derivation**: A 64-byte shared secret is generated; the first 32 bytes are used as the AES-256 key.
- **DEM**: AES-256 in GCM mode for authenticated encryption of the message payload.

## 🤝 Contributing

This is an experimental project! Opinions, bug reports, and pull requests are welcome.
1. Fork the repo.
2. Create your feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'Add amazing feature'`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a Pull Request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---
*Developed with ❤️ for a safer quantum future.*
