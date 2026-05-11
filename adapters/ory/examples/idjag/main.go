// Package main demonstrates ID-JAG integration with Ory Hydra.
//
// This example shows:
// 1. Creating ID-JAG assertions
// 2. Exchanging assertions for access tokens via Hydra
// 3. Using delegation with actor tokens
//
// Run: go run ./adapters/ory/examples/idjag
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

	"github.com/aistandardsio/agent-protocols/adapters/ory/hydra"
	"github.com/golang-jwt/jwt/v5"
)

// TokenTypeIDJAG is the ID-JAG assertion token type for the typ header.
//
//nolint:gosec // G101: This is a token type identifier, not a credential.
const TokenTypeIDJAG = "id-jag+jwt"

func main() {
	fmt.Println("=== ID-JAG + Ory Hydra Integration Demo ===")
	fmt.Println()

	// Generate key pair for signing assertions
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	keyID := "signing-key-1"

	// Create mock Hydra server
	mockHydra := createMockHydraServer(privateKey, keyID)
	defer mockHydra.Close()

	// Create Hydra client
	client, err := hydra.NewClient(mockHydra.URL,
		hydra.WithAdminURL(mockHydra.URL),
		hydra.WithClientCredentials("demo-client", "demo-secret"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// Step 1: Create an ID-JAG assertion
	fmt.Println("Step 1: Creating ID-JAG assertion...")
	assertion := createIDJAGAssertion(mockHydra.URL, privateKey, keyID)
	fmt.Printf("  Assertion (truncated): %s...\n", assertion[:50])
	fmt.Println()

	// Step 2: Exchange assertion for access token
	fmt.Println("Step 2: Exchanging assertion via Hydra...")
	resp, err := client.ExchangeIDJAG(ctx, assertion,
		hydra.WithScope("read write"),
		hydra.WithAudience("https://api.example.com"),
	)
	if err != nil {
		log.Fatalf("Token exchange failed: %v", err)
	}
	fmt.Printf("  Access Token: %s...\n", resp.AccessToken[:20])
	fmt.Printf("  Token Type: %s\n", resp.TokenType)
	fmt.Printf("  Expires In: %d seconds\n", resp.ExpiresIn)
	fmt.Println()

	// Step 3: Create assertion with delegation (act claim)
	fmt.Println("Step 3: Creating assertion with delegation...")
	delegatedAssertion := createDelegatedAssertion(mockHydra.URL, privateKey, keyID)
	fmt.Printf("  Delegated Assertion (truncated): %s...\n", delegatedAssertion[:50])
	fmt.Println()

	// Step 4: Exchange delegated assertion
	fmt.Println("Step 4: Exchanging delegated assertion...")
	delegatedResp, err := client.ExchangeIDJAG(ctx, delegatedAssertion,
		hydra.WithScope("calendar:read"),
	)
	if err != nil {
		log.Fatalf("Delegated token exchange failed: %v", err)
	}
	fmt.Printf("  Delegated Access Token: %s...\n", delegatedResp.AccessToken[:20])
	fmt.Println()

	// Step 5: Introspect the token
	fmt.Println("Step 5: Introspecting access token...")
	introspectResp, err := client.IntrospectToken(ctx, resp.AccessToken)
	if err != nil {
		log.Fatalf("Introspection failed: %v", err)
	}
	fmt.Printf("  Active: %v\n", introspectResp.Active)
	fmt.Printf("  Subject: %s\n", introspectResp.Sub)
	fmt.Printf("  Scope: %s\n", introspectResp.Scope)
	fmt.Println()

	// Step 6: Use JWT Bearer grant
	fmt.Println("Step 6: Using JWT Bearer grant...")
	jwtResp, err := client.JWTBearerGrant(ctx, assertion,
		hydra.WithScope("api:access"),
	)
	if err != nil {
		log.Fatalf("JWT Bearer grant failed: %v", err)
	}
	fmt.Printf("  JWT Bearer Access Token: %s...\n", jwtResp.AccessToken[:20])
	fmt.Println()

	fmt.Println("=== Demo Complete ===")
}

// createIDJAGAssertion creates a basic ID-JAG assertion.
func createIDJAGAssertion(issuer string, privateKey *rsa.PrivateKey, keyID string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "user:alice",
		"aud": issuer + "/oauth2/token",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": generateJTI(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = TokenTypeIDJAG

	signed, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("Failed to sign assertion: %v", err)
	}
	return signed
}

// createDelegatedAssertion creates an ID-JAG assertion with delegation.
func createDelegatedAssertion(issuer string, privateKey *rsa.PrivateKey, keyID string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": "agent:calendar-bot",
		"aud": issuer + "/oauth2/token",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": generateJTI(),
		"act": map[string]interface{}{
			"sub": "user:alice",
			"iss": "https://users.example.com",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = TokenTypeIDJAG

	signed, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("Failed to sign assertion: %v", err)
	}
	return signed
}

// generateJTI generates a unique JWT ID.
func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// createMockHydraServer creates a mock Ory Hydra server.
func createMockHydraServer(privateKey *rsa.PrivateKey, keyID string) *httptest.Server {
	tokenCounter := 0

	mux := http.NewServeMux()

	// Token endpoint
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		tokenCounter++
		resp := hydra.TokenResponse{
			AccessToken:     fmt.Sprintf("hydra_access_token_%d_%s", tokenCounter, generateJTI()[:8]),
			TokenType:       "Bearer",
			ExpiresIn:       3600,
			IssuedTokenType: hydra.TokenTypeAccessToken,
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock server response for demo
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// Introspection endpoint
	mux.HandleFunc("/admin/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		resp := hydra.IntrospectionResponse{
			Active:   true,
			Sub:      "user:alice",
			Iss:      "http://" + r.Host,
			Aud:      []string{"https://api.example.com"},
			ClientID: "demo-client",
			Scope:    "read write",
			Exp:      time.Now().Add(time.Hour).Unix(),
			Iat:      time.Now().Unix(),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// JWKS endpoint
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
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
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// OpenID Configuration
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]string{
			"issuer":         "http://" + r.Host,
			"token_endpoint": "http://" + r.Host + "/oauth2/token",
			"jwks_uri":       "http://" + r.Host + "/.well-known/jwks.json",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	return httptest.NewServer(mux)
}
