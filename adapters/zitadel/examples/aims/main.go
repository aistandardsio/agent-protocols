// Package main demonstrates AIMS Workload Identity Token verification with Zitadel.
//
// This example shows how to:
//  1. Create and sign an AIMS WIT (Workload Identity Token)
//  2. Verify the WIT using Zitadel's JWKS infrastructure
//  3. Use HTTP middleware for WIT validation
//
// Run with: go run ./adapters/zitadel/examples/aims
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

	"github.com/aistandardsio/agent-protocols/adapters/zitadel"
	"github.com/aistandardsio/agent-protocols/aims"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// Generate a key pair for signing WITs
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	keyID := "workload-key-1"

	// Create a mock Zitadel server
	mockServer := createMockZitadelServer(privateKey, keyID)
	defer mockServer.Close()

	fmt.Println("=== AIMS WIT Verification with Zitadel Demo ===")
	fmt.Println()

	// Step 1: Create a SPIFFE ID for the workload
	fmt.Println("Step 1: Creating SPIFFE ID and WIT...")
	spiffeID, err := aims.ParseSPIFFEID("spiffe://example.com/workload/api-server")
	if err != nil {
		log.Fatalf("Failed to parse SPIFFE ID: %v", err)
	}

	// Create a Workload Identity Token
	wit := aims.NewWIT(
		spiffeID,
		[]string{"https://api.example.com", "https://backend.example.com"},
		5*time.Minute,
	)

	fmt.Printf("  SPIFFE ID: %s\n", wit.Subject)
	fmt.Printf("  Issuer: %s\n", wit.Issuer)
	fmt.Printf("  Audiences: %v\n", wit.Audience)
	fmt.Println()

	// Step 2: Sign the WIT using the signing key
	fmt.Println("Step 2: Signing WIT...")

	// For demo purposes, we'll sign using the RSA key
	// (normally you'd use Sign method with a crypto.Signer)
	signedWIT := signWIT(wit, privateKey, keyID, mockServer.URL)

	fmt.Printf("  Signed WIT: %s...\n", signedWIT[:50])
	fmt.Println()

	// Step 3: Verify the WIT using Zitadel verifier
	fmt.Println("Step 3: Verifying WIT...")
	verifier, err := zitadel.NewVerifier(
		mockServer.URL,
		zitadel.WithStaticJWKSURL(mockServer.URL+"/jwks"),
	)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	ctx := context.Background()
	verifiedWIT, err := verifier.VerifyAIMSWIT(ctx, signedWIT)
	if err != nil {
		log.Fatalf("WIT verification failed: %v", err)
	}

	fmt.Printf("  Verified subject: %s\n", verifiedWIT.Subject)
	fmt.Printf("  Verified issuer: %s\n", verifiedWIT.Issuer)
	fmt.Printf("  Verified audiences: %v\n", verifiedWIT.Audience)
	fmt.Println()

	// Step 4: Demonstrate middleware usage
	fmt.Println("Step 4: Demonstrating middleware usage...")

	// Create middleware that requires AIMS tokens
	middleware := zitadel.RequireAIMS(verifier, zitadel.MiddlewareOptions{})

	// Create a test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wit, ok := zitadel.AIMSWITFromContext(r.Context())
		if !ok {
			http.Error(w, "No WIT in context", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Authenticated workload: %s", wit.Subject)
	})

	// Create a test request with the WIT
	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+signedWIT)

	rr := httptest.NewRecorder()
	middleware.Handler(handler).ServeHTTP(rr, req)

	fmt.Printf("  Response status: %d\n", rr.Code)
	fmt.Printf("  Response body: %s\n", rr.Body.String())
	fmt.Println()

	fmt.Println("=== Demo completed successfully ===")
}

// signWIT signs a WIT using RSA for demonstration purposes.
func signWIT(wit *aims.WorkloadIdentityToken, privateKey *rsa.PrivateKey, keyID, issuer string) string {
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": wit.Subject,
		"aud": wit.Audience,
		"iat": wit.IssuedAt.Unix(),
		"exp": wit.Expiry.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	signed, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("Failed to sign WIT: %v", err)
	}
	return signed
}

// createMockZitadelServer creates a mock Zitadel server for the demo.
func createMockZitadelServer(privateKey *rsa.PrivateKey, keyID string) *httptest.Server {
	mux := http.NewServeMux()

	// OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]string{
			"issuer":   "http://" + r.Host,
			"jwks_uri": "http://" + r.Host + "/jwks",
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

	return httptest.NewServer(mux)
}
