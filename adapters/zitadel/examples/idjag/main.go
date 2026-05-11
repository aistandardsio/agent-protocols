// Package main demonstrates ID-JAG assertion exchange with Zitadel.
//
// This example shows how to:
//  1. Create and sign an ID-JAG assertion
//  2. Exchange the assertion for an access token via Zitadel
//  3. Verify the resulting token
//
// Run with: go run ./adapters/zitadel/examples/idjag
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
	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// Generate a key pair for signing assertions
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	keyID := "example-key-1"

	// Create a mock Zitadel server
	mockServer := createMockZitadelServer(privateKey, keyID)
	defer mockServer.Close()

	fmt.Println("=== ID-JAG to Zitadel Token Exchange Demo ===")
	fmt.Println()

	// Step 1: Create an ID-JAG assertion
	fmt.Println("Step 1: Creating ID-JAG assertion...")
	assertion := idjag.NewAssertion(
		mockServer.URL,
		"user:alice@example.com",
		[]string{mockServer.URL + "/token"},
		5*time.Minute,
	)

	// For delegation, add an actor
	assertion.WithActor(&idjag.Actor{
		Subject: "agent:calendar-bot",
	})

	fmt.Printf("  Subject: %s\n", assertion.Subject)
	fmt.Printf("  Actor: %s\n", assertion.Actor.Subject)
	fmt.Println()

	// Step 2: Sign the assertion
	fmt.Println("Step 2: Signing assertion...")
	signedAssertion, err := assertion.Sign(jwt.SigningMethodRS256, privateKey, keyID)
	if err != nil {
		log.Fatalf("Failed to sign assertion: %v", err)
	}
	fmt.Printf("  Signed assertion: %s...\n", signedAssertion[:50])
	fmt.Println()

	// Step 3: Exchange the assertion for an access token
	fmt.Println("Step 3: Exchanging assertion for access token...")
	exchanger, err := zitadel.NewTokenExchanger(
		mockServer.URL,
		zitadel.WithStaticTokenEndpoint(mockServer.URL+"/token"),
	)
	if err != nil {
		log.Fatalf("Failed to create exchanger: %v", err)
	}

	ctx := context.Background()
	resp, err := exchanger.ExchangeAssertion(ctx, signedAssertion,
		zitadel.WithScope("openid profile"),
	)
	if err != nil {
		log.Fatalf("Token exchange failed: %v", err)
	}

	fmt.Printf("  Access token: %s...\n", resp.AccessToken[:50])
	fmt.Printf("  Token type: %s\n", resp.TokenType)
	fmt.Printf("  Expires in: %d seconds\n", resp.ExpiresIn)
	fmt.Println()

	// Step 4: Verify the access token
	fmt.Println("Step 4: Verifying access token...")
	verifier, err := zitadel.NewVerifier(
		mockServer.URL,
		zitadel.WithStaticJWKSURL(mockServer.URL+"/jwks"),
	)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	verified, err := verifier.VerifyIDJAGAssertion(ctx, resp.AccessToken)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("  Verified subject: %s\n", verified.Subject)
	if verified.Actor != nil {
		fmt.Printf("  Verified actor: %s\n", verified.Actor.Subject)
	}
	fmt.Println()

	fmt.Println("=== Demo completed successfully ===")
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

	// Token endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		grantType := r.PostForm.Get("grant_type")
		subjectToken := r.PostForm.Get("subject_token")

		if grantType != zitadel.GrantTypeTokenExchange {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "unsupported_grant_type",
				"error_description": "Only token exchange is supported",
			})
			return
		}

		// Parse the incoming assertion to extract claims
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		token, _, err := parser.ParseUnverified(subjectToken, jwt.MapClaims{})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "Invalid assertion",
			})
			return
		}

		// Create an access token with the same claims
		inClaims := token.Claims.(jwt.MapClaims)
		outClaims := jwt.MapClaims{
			"iss": "http://" + r.Host,
			"sub": inClaims["sub"],
			"aud": "http://" + r.Host,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		if act, ok := inClaims["act"]; ok {
			outClaims["act"] = act
		}

		accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, outClaims)
		accessToken.Header["kid"] = keyID

		signedToken, err := accessToken.SignedString(privateKey)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		resp := map[string]interface{}{
			"access_token":      signedToken,
			"token_type":        "Bearer",
			"expires_in":        3600,
			"issued_token_type": zitadel.TokenTypeAccessToken,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}
