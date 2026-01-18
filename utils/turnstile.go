package utils

import (
	"encoding/json"
	"fmt"
	"hrt-tracker-service/config"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TurnstileVerifyRequest represents the request to Cloudflare Turnstile API
type TurnstileVerifyRequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
	RemoteIP string `json:"remoteip,omitempty"`
}

// TurnstileVerifyResponse represents the response from Cloudflare Turnstile API
type TurnstileVerifyResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
	Action      string   `json:"action"`
	CData       string   `json:"cdata"`
}

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// Reusable HTTP client for better performance
var turnstileHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

// VerifyTurnstileToken verifies a Cloudflare Turnstile token
// Returns (isInternalError bool, error)
// - If error is nil, verification succeeded
// - If error is not nil and isInternalError is true, it's a server-side issue (500)
// - If error is not nil and isInternalError is false, it's a client issue (400/401)
func VerifyTurnstileToken(token string, remoteIP string, expectedAction string) (bool, error) {
	// If Turnstile is disabled, skip verification
	if !config.AppConfig.TurnstileEnabled {
		return false, nil
	}

	// If Turnstile is enabled but secret key is missing, this is a configuration error
	if config.AppConfig.TurnstileSecretKey == "" {
		log.Println("ERROR: Turnstile is enabled but TURNSTILE_SECRET_KEY is not set")
		return true, fmt.Errorf("turnstile configuration error")
	}

	// Validate token is not empty
	if token == "" {
		return false, fmt.Errorf("turnstile token is required")
	}

	// Prepare form-encoded request payload (required by Cloudflare Turnstile API)
	formData := url.Values{}
	formData.Set("secret", config.AppConfig.TurnstileSecretKey)
	formData.Set("response", token)
	if remoteIP != "" {
		formData.Set("remoteip", remoteIP)
	}

	// Send POST request to Turnstile API
	req, err := http.NewRequest("POST", turnstileVerifyURL, strings.NewReader(formData.Encode()))
	if err != nil {
		log.Printf("ERROR: Failed to create Turnstile request: %v", err)
		return true, fmt.Errorf("failed to create verification request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := turnstileHTTPClient.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send Turnstile request: %v", err)
		return true, fmt.Errorf("failed to connect to verification service")
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: Turnstile API returned non-200 status: %d", resp.StatusCode)
		return true, fmt.Errorf("verification service returned error status")
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR: Failed to read Turnstile response: %v", err)
		return true, fmt.Errorf("failed to read verification response")
	}

	// Parse response
	var result TurnstileVerifyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("ERROR: Failed to parse Turnstile response: %v", err)
		return true, fmt.Errorf("failed to parse verification response")
	}

	// Check if verification was successful
	if !result.Success {
		// Log error codes for debugging, but don't expose them to client
		log.Printf("WARNING: Turnstile verification failed: %v", result.ErrorCodes)
		return false, fmt.Errorf("captcha verification failed")
	}

	// Validate action if expected action is provided
	if expectedAction != "" && result.Action != expectedAction {
		log.Printf("WARNING: Turnstile action mismatch: expected=%s, got=%s", expectedAction, result.Action)
		return false, fmt.Errorf("captcha verification failed: invalid action")
	}

	// Validate hostname if configured (case-insensitive)
	if config.AppConfig.TurnstileAllowedHostname != "" {
		expectedHostname := strings.ToLower(config.AppConfig.TurnstileAllowedHostname)
		actualHostname := strings.ToLower(result.Hostname)
		if actualHostname != expectedHostname {
			log.Printf("WARNING: Turnstile hostname mismatch: expected=%s, got=%s", expectedHostname, actualHostname)
			return false, fmt.Errorf("captcha verification failed: invalid hostname")
		}
	}

	return false, nil
}
