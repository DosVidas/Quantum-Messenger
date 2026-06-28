package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

type AnomalyDetector struct {
	OllamaEndpoint string
	Model          string
}

func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		OllamaEndpoint: "http://localhost:11434/api/generate",
		Model:          "qwen:0.5b", // Using a light model for fast local inference
	}
}

// AnalyzeTraffic takes metadata about a secure connection and asks the AI to evaluate risk
func (ad *AnomalyDetector) AnalyzeTraffic(payloadSize int, frequency float64, userAgent string) (string, error) {
	prompt := fmt.Sprintf(`Analyze the following network metadata for potential security anomalies:
- Payload Size: %d bytes
- Frequency: %.2f requests/sec
- User Agent: %s

Is this typical behavior for a secure financial transaction or does it look like a potential attack (e.g., brute force, exfiltration)? Respond with "SAFE" or "SUSPICIOUS" and a short reason.`, payloadSize, frequency, userAgent)

	reqBody := OllamaRequest{
		Model:  ad.Model,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(ad.OllamaEndpoint, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "DETECTION_OFFLINE", nil
	}
	defer resp.Body.Close()

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", err
	}

	return ollamaResp.Response, nil
}
