// Package main demonstrates ID-JAG with human-to-agent delegation.
//
// This example shows how an agent can act on behalf of a human user
// using the "act" (actor) claim per RFC 8693.
//
// The assertion structure with delegation:
//
//	{
//	  "iss": "https://issuer.example.com",
//	  "sub": "user:alice",           // Human identity
//	  "act": {
//	    "sub": "agent:calendar-bot"  // Acting agent
//	  }
//	}
//
// # EXPERIMENTAL
//
// This example implements draft-ietf-oauth-identity-assertion-authz-grant
// which is subject to change.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grokify/agent-protocols/idjag"
)

const (
	serverAddr = "localhost:18081"
	keyID      = "demo-key-1"
	issuer     = "https://issuer.example.com"
	audience   = "http://localhost:18081"
)

func main() {
	// Generate RSA key pair for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Create JWKS from public key
	jwks := &idjag.JWKS{
		Keys: []idjag.JWK{
			idjag.NewJWKFromRSAPublicKey(publicKey, keyID, idjag.AlgorithmRS256),
		},
	}

	// Create verifier for the authorization server
	verifier := idjag.NewStaticKeyVerifier(publicKey, keyID, idjag.VerifierOptions{
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
	})

	// Create authorization server
	authServer := idjag.NewAuthorizationServer(
		verifier,
		jwt.SigningMethodRS256,
		privateKey,
		keyID,
		audience,
	)
	authServer.TokenTTL = 1 * time.Hour

	// Create verifier for the resource server
	resourceVerifier := idjag.NewStaticKeyVerifier(publicKey, keyID, idjag.VerifierOptions{
		ExpectedIssuer: audience,
	})
	resourceServer := idjag.NewResourceServer(resourceVerifier)

	// Set up HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", idjag.NewJWKSHandler(jwks).ServeHTTP)
	mux.HandleFunc("POST /token", authServer.ServeHTTP)
	mux.HandleFunc("GET /calendar", resourceServer.Middleware(http.HandlerFunc(handleCalendar)).ServeHTTP)

	// Start server in background
	server := &http.Server{
		Addr:    serverAddr,
		Handler: mux,
	}

	go func() {
		log.Printf("Server starting on %s", serverAddr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Run the demo
	if err := runDemo(privateKey); err != nil {
		log.Fatalf("Demo failed: %v", err)
	}

	log.Println("\nDemo completed successfully!")
}

func runDemo(privateKey *rsa.PrivateKey) error {
	ctx := context.Background()

	log.Println("\n=== ID-JAG Delegation Demo ===")
	log.Println("This demo shows an agent acting on behalf of a human user.")

	// Step 1: Create delegated assertion
	log.Println("\n1. Creating delegated assertion...")
	assertion := idjag.NewDelegatedAssertion(
		issuer,
		"user:alice",         // Human user
		"agent:calendar-bot", // Acting agent
		[]string{audience},
		5*time.Minute,
	)

	// Sign the assertion
	signedAssertion, err := assertion.Sign(jwt.SigningMethodRS256, privateKey, keyID)
	if err != nil {
		return fmt.Errorf("failed to sign assertion: %w", err)
	}
	log.Printf("   Subject (human): %s", assertion.Subject)
	log.Printf("   Actor (agent):   %s", assertion.Actor.Subject)
	log.Printf("   Assertion created (JWT length: %d)", len(signedAssertion))

	// Step 2: Exchange assertion for access token
	log.Println("\n2. Exchanging delegated assertion for access token...")
	client := idjag.NewTokenExchangeClient(fmt.Sprintf("http://%s/token", serverAddr))
	tokenResp, err := client.ExchangeAssertion(ctx, signedAssertion, "calendar:read")
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}
	log.Printf("   Access token received (length: %d)", len(tokenResp.AccessToken))
	log.Printf("   Scope: %s", tokenResp.Scope)

	// Step 3: Call protected resource
	log.Println("\n3. Agent calling calendar API on behalf of user...")
	data, err := callCalendarAPI(tokenResp.AccessToken)
	if err != nil {
		return fmt.Errorf("calendar API call failed: %w", err)
	}
	log.Printf("   Response: %s", data)

	// Demonstrate nested delegation
	log.Println("\n4. Demonstrating nested delegation (User -> Agent1 -> Agent2)...")
	if err := demoNestedDelegation(privateKey); err != nil {
		return fmt.Errorf("nested delegation demo failed: %w", err)
	}

	return nil
}

func demoNestedDelegation(privateKey *rsa.PrivateKey) error {
	ctx := context.Background()

	// Create assertion with nested delegation chain
	assertion := idjag.NewAssertion(
		issuer,
		"user:bob",
		[]string{audience},
		5*time.Minute,
	)
	assertion.Actor = &idjag.Actor{
		Subject: "agent:orchestrator",
		Actor: &idjag.Actor{
			Subject: "agent:calendar-worker",
		},
	}

	signedAssertion, err := assertion.Sign(jwt.SigningMethodRS256, privateKey, keyID)
	if err != nil {
		return fmt.Errorf("failed to sign assertion: %w", err)
	}

	log.Printf("   Subject (human):      %s", assertion.Subject)
	log.Printf("   Actor 1 (orchestrator): %s", assertion.Actor.Subject)
	log.Printf("   Actor 2 (worker):       %s", assertion.Actor.Actor.Subject)

	// Parse it back to verify the chain
	parsed, err := idjag.ParseAssertion(signedAssertion)
	if err != nil {
		return fmt.Errorf("failed to parse assertion: %w", err)
	}

	chain := parsed.DelegationChain()
	log.Printf("   Delegation chain depth: %d", len(chain))
	for i, actor := range chain {
		log.Printf("   Level %d: %s", i+1, actor.Subject)
	}

	// Exchange and call API
	client := idjag.NewTokenExchangeClient(fmt.Sprintf("http://%s/token", serverAddr))
	tokenResp, err := client.ExchangeAssertion(ctx, signedAssertion, "calendar:read")
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}

	data, err := callCalendarAPI(tokenResp.AccessToken)
	if err != nil {
		return fmt.Errorf("calendar API call failed: %w", err)
	}
	log.Printf("   Response: %s", data)

	return nil
}

func callCalendarAPI(accessToken string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/calendar", serverAddr), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func handleCalendar(w http.ResponseWriter, r *http.Request) {
	assertion := idjag.AssertionFromContext(r.Context())
	if assertion == nil {
		http.Error(w, "no assertion in context", http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"message":   "Calendar access granted",
		"user":      assertion.Subject,
		"delegated": assertion.IsDelegated(),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	// Include delegation chain if present
	if assertion.IsDelegated() {
		chain := assertion.DelegationChain()
		actors := make([]string, len(chain))
		for i, actor := range chain {
			actors[i] = actor.Subject
		}
		response["acting_as"] = actors
	}

	// Mock calendar events
	response["events"] = []map[string]string{
		{"title": "Team Standup", "time": "09:00"},
		{"title": "Project Review", "time": "14:00"},
		{"title": "1:1 Meeting", "time": "16:00"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
