# Quantum-Messenger

Quantum-Messenger is a post-quantum secure, terminal-themed web chat application built under the **33LR Protocol**. It is designed to safeguard real-time communications against future decryption threats (Store Now, Decrypt Later) and network censorship using modern cryptographic primitives.

🔒 **Live Demo:** [https://quantummessenger.xyz](https://quantummessenger.xyz)

---

## Key Features

- **Post-Quantum Cryptography (PQC):** Integrates **Kyber-1024** key encapsulation (KEM) to establish a secure symmetric encryption channel resilient to future quantum computing decryption attacks.
- **End-to-End Encrypted (E2EE) File Sharing:** Select and send files up to 50MB. Files are encrypted natively in the browser with **AES-GCM-256** before upload. The server only sees encrypted blobs, while the key and initialization vector (IV) are shared securely within the chat room.
- **Passwordless ECDSA Authentication:** Users register and authenticate using local **ECDSA (P-256)** key pairs generated natively via the Web Crypto API. Access is granted through a cryptographic challenge-response signature.
- **Moon-Phase DGA (Domain Generation Algorithm):** Dynamically calculates active onion/domain nodes based on a server seed and the physical moon phase to simulate network-level censorship evasion.
- **AI Anomaly Detection:** An embedded Go engine monitors metadata traffic patterns to warn about anomalies or intrusion attempts.
- **Modern Terminal UI:** Fluid retro hacker theme, native emoji picker, drag-and-drop file upload, file transfer progress bar, and mobile responsive menu.

---

## Project Structure

```text
quantum-messenger/
├── 33lr-framework/         # Cryptography and Moon-Phase DGA modules
├── backend/                # Go server (WebSockets, API, and file uploads)
├── frontend/               # Flat HTML5/JS/CSS client
├── quantumguard/           # AI Anomaly Detection engine
├── Dockerfile              # Multi-stage build script for Render/Self-hosting
├── LICENSE                 # GNU Affero General Public License v3.0 (AGPL-3.0)
└── README.md               # You are here
```

---

## Self-Hosting with Docker

You can easily host your own instance of Quantum-Messenger using the provided multi-stage Dockerfile.

### 1. Build the Docker Image
From the root directory:
```bash
docker build -t quantum-messenger .
```

### 2. Run the Container
```bash
docker run -d -p 8086:8080 --name qm-node quantum-messenger
```
The backend server will run on port `8086`.

### 3. Connect your Frontend
Serve the `frontend/index.html` static file using any web server (Nginx, Caddy, or local serve) and direct it to your backend host:
```text
http://localhost:8086
```

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See the [LICENSE](LICENSE) file for details. This copyleft license allows free personal and educational use but legally obligates anyone hosting modified versions as a service (SaaS) to release their full source code.
