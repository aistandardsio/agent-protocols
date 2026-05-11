// Package main demonstrates AAuth agent authentication with Zitadel.
//
// This example shows how to:
//  1. Create an AAuth agent with a key pair
//  2. Generate agent tokens
//  3. Verify agent tokens using Zitadel's JWKS infrastructure
//  4. Use HTTP middleware for agent token validation
//
// Run with: go run ./adapters/zitadel/examples/aauth
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/adapters/zitadel"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// Generate a key pair for the agent
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	keyID := "agent-key-1"

	// Create a mock Zitadel server
	mockServer := createMockZitadelServer(privateKey, keyID)
	defer mockServer.Close()

	fmt.Println("=== AAuth Agent Authentication with Zitadel Demo ===")
	fmt.Println()

	// Step 1: Create an AAuth agent
	fmt.Println("Step 1: Creating AAuth agent...")
	agent, err := aauth.NewAgent(
		&aauth.AAuthID{
			Local:  "calendar-bot",
			Domain: "example.com",
		},
		privateKey,
		aauth.WithAgentProviderURL(mockServer.URL),
		aauth.WithTokenTTL(5*time.Minute),
		aauth.WithSigningMethod(jwt.SigningMethodRS256),
	)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	fmt.Printf("  Agent ID: %s\n", agent.ID().String())
	fmt.Printf("  Key ID: %s\n", agent.KeyPair().KeyID)
	fmt.Println()

	// Step 2: Generate an agent token
	fmt.Println("Step 2: Generating agent token...")
	agentTokenStr, err := agent.SignAgentToken("https://api.example.com")
	if err != nil {
		log.Fatalf("Failed to sign agent token: %v", err)
	}

	fmt.Printf("  Agent token: %s...\n", agentTokenStr[:50])
	fmt.Println()

	// Step 3: Create a token that mimics Zitadel's issued token
	// (In practice, this would come from Zitadel after token exchange)
	fmt.Println("Step 3: Creating Zitadel-style agent token...")
	zitadelToken := createZitadelAgentToken(mockServer.URL, agent, privateKey, keyID)
	fmt.Printf("  Zitadel token: %s...\n", zitadelToken[:50])
	fmt.Println()

	// Step 4: Verify the token using Zitadel verifier
	fmt.Println("Step 4: Verifying agent token...")
	verifier, err := zitadel.NewVerifier(
		mockServer.URL,
		zitadel.WithStaticJWKSURL(mockServer.URL+"/jwks"),
	)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	ctx := context.Background()
	verifiedToken, err := verifier.VerifyAAuthAgentToken(ctx, zitadelToken)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("  Verified subject: %s\n", verifiedToken.Subject)
	fmt.Printf("  Verified issuer: %s\n", verifiedToken.Issuer)
	if verifiedToken.CNF != nil {
		fmt.Printf("  CNF present: yes\n")
	}
	fmt.Println()

	// Step 5: Demonstrate middleware usage
	fmt.Println("Step 5: Demonstrating middleware usage...")

	// Create middleware that requires AAuth tokens
	middleware := zitadel.RequireAAuth(verifier, zitadel.MiddlewareOptions{})

	// Create a test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := zitadel.AAuthTokenFromContext(r.Context())
		if !ok {
			http.Error(w, "No agent token in context", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Authenticated agent: %s", token.Subject)
	})

	// Create a test request with the agent token
	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+zitadelToken)

	rr := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(rr, req)

	fmt.Printf("  Response status: %d\n", rr.Code)
	fmt.Printf("  Response body: %s\n", rr.Body.String())
	fmt.Println()

	fmt.Println("=== Demo completed successfully ===")
}

// createZitadelAgentToken creates an agent token as if issued by Zitadel.
func createZitadelAgentToken(issuer string, agent *aauth.Agent, privateKey *rsa.PrivateKey, keyID string) string {
	// Create CNF claim with the agent's public key
	cnfJWK := map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
	}

	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": agent.ID().String(),
		"aud": "https://api.example.com",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]interface{}{
			"jwk": cnfJWK,
		},
		"dwk": issuer + "/.well-known/aauth-agent.json",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = aauth.TokenTypeAgentJWT

	signed, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("Failed to sign agent token: %v", err)
	}
	return signed
}

// createMockZitadelServer creates a mock Zitadel server for the demo.
func createMockZitadelServer(privateKey *rsa.PrivateKey, keyID string) *httptest.Server {
	mux := http.NewServeMux()

	// OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]string{
			"issuer":         "http://" + r.Host,
			"token_endpoint": "http://" + r.Host + "/token",
			"jwks_uri":       "http://" + r.Host + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]interface{}{
			"keys": []map[string]string{
				{
					"kty": "RSA",
					"kid": keyID,
					"alg": "RS256",
					"use": "sig",
					"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	// AAuth agent metadata endpoint
	mux.HandleFunc("/.well-known/aauth-agent.json", func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]interface{}{
			"issuer":               "http://" + r.Host,
			"jwks_uri":             "http://" + r.Host + "/jwks",
			"supported_algorithms": []string{"RS256", "ES256"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	})

	return httptest.NewServer(mux)
}
