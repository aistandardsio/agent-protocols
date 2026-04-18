// Package main demonstrates a simple ID-JAG token exchange flow without delegation.
//
// This example runs three services in a single binary:
//   - Authorization Server: /token endpoint for token exchange
//   - Resource Server: /data endpoint requiring valid access token
//   - JWKS: /.well-known/jwks.json for key distribution
//
// Flow:
//  1. Agent creates and signs a JWT assertion
//  2. Agent exchanges assertion for access token at /token
//  3. Agent calls /data with Bearer token
//  4. Resource server validates and returns protected data
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
	serverAddr = "localhost:18080"
	keyID      = "demo-key-1"
	issuer     = "https://issuer.example.com"
	audience   = "http://localhost:18080"
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
		audience, // Issuer for access tokens
	)
	authServer.TokenTTL = 1 * time.Hour

	// Create verifier for the resource server (verifies access tokens)
	resourceVerifier := idjag.NewStaticKeyVerifier(publicKey, keyID, idjag.VerifierOptions{
		ExpectedIssuer: audience,
	})
	resourceServer := idjag.NewResourceServer(resourceVerifier)

	// Set up HTTP handlers
	mux := http.NewServeMux()

	// JWKS endpoint
	mux.HandleFunc("GET /.well-known/jwks.json", idjag.NewJWKSHandler(jwks).ServeHTTP)

	// Token endpoint (POST only for token exchange)
	mux.HandleFunc("POST /token", authServer.ServeHTTP)

	// Protected resource endpoint
	mux.HandleFunc("GET /data", resourceServer.Middleware(http.HandlerFunc(handleData)).ServeHTTP)

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

	log.Println("Demo completed successfully!")
}

func runDemo(privateKey *rsa.PrivateKey) error {
	ctx := context.Background()

	log.Println("\n=== ID-JAG Simple Demo ===")
	log.Println("This demo shows an agent authenticating without human delegation.")

	// Step 1: Create assertion
	log.Println("\n1. Creating assertion for agent...")
	assertion := idjag.NewAssertion(
		issuer,
		"agent:demo-client", // Agent's own identity
		[]string{audience},
		5*time.Minute,
	)

	// Sign the assertion
	signedAssertion, err := assertion.Sign(jwt.SigningMethodRS256, privateKey, keyID)
	if err != nil {
		return fmt.Errorf("failed to sign assertion: %w", err)
	}
	log.Printf("   Subject: %s", assertion.Subject)
	log.Printf("   Assertion created (JWT length: %d)", len(signedAssertion))

	// Step 2: Exchange assertion for access token
	log.Println("\n2. Exchanging assertion for access token...")
	client := idjag.NewTokenExchangeClient(fmt.Sprintf("http://%s/token", serverAddr))
	tokenResp, err := client.ExchangeAssertion(ctx, signedAssertion, "read:data")
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}
	log.Printf("   Access token received (length: %d)", len(tokenResp.AccessToken))
	log.Printf("   Token type: %s", tokenResp.TokenType)
	log.Printf("   Expires in: %d seconds", tokenResp.ExpiresIn)

	// Step 3: Call protected resource
	log.Println("\n3. Calling protected resource with access token...")
	data, err := callProtectedResource(tokenResp.AccessToken)
	if err != nil {
		return fmt.Errorf("resource call failed: %w", err)
	}
	log.Printf("   Response: %s", data)

	return nil
}

func callProtectedResource(accessToken string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/data", serverAddr), nil)
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

func handleData(w http.ResponseWriter, r *http.Request) {
	assertion := idjag.AssertionFromContext(r.Context())
	if assertion == nil {
		http.Error(w, "no assertion in context", http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"message":   "Hello from protected resource!",
		"subject":   assertion.Subject,
		"delegated": assertion.IsDelegated(),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
