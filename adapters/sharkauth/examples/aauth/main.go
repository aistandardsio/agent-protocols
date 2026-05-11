// Package main demonstrates AAuth protocol integration with SharkAuth.
//
// This example shows:
// 1. Creating delegation grants with may_act_grants
// 2. Exchanging AAuth tokens for SharkAuth access tokens
// 3. Using DPoP for proof-of-possession
//
// Run: go run ./adapters/sharkauth/examples/aauth
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/adapters/sharkauth"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	fmt.Println("=== AAuth + SharkAuth Integration Demo ===")
	fmt.Println()

	// Generate agent key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// Create mock SharkAuth server
	mockServer := createMockSharkAuthServer()
	defer mockServer.Close()

	// Create SharkAuth client
	client, err := sharkauth.NewClient(mockServer.URL,
		sharkauth.WithClientCredentials("demo-client", "demo-secret"),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Step 1: Create a delegation grant
	fmt.Println("Step 1: Creating delegation grant...")
	grant, err := client.CreateDelegationGrant(ctx, sharkauth.DelegationGrantRequest{
		ActorSubject: "agent:calendar-bot",
		UserSubject:  "user:alice",
		Scopes:       []string{"calendar:read", "calendar:write"},
		TTL:          24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("Failed to create delegation grant: %v", err)
	}
	fmt.Printf("  Grant ID: %s\n", grant.GrantID)
	fmt.Printf("  Actor: %s\n", grant.ActorSubject)
	fmt.Printf("  User: %s\n", grant.UserSubject)
	fmt.Printf("  Scopes: %v\n", grant.Scopes)
	fmt.Println()

	// Step 2: Create AAuth agent
	fmt.Println("Step 2: Creating AAuth agent...")
	agent, err := aauth.NewAgent(
		&aauth.AAuthID{
			Local:  "calendar-bot",
			Domain: "example.com",
		},
		privateKey,
		aauth.WithAgentProviderURL("https://agents.example.com"),
		aauth.WithTokenTTL(5*time.Minute),
		aauth.WithSigningMethod(jwt.SigningMethodES256),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Agent ID: %s\n", agent.ID().String())
	fmt.Printf("  Key ID: %s\n", agent.KeyPair().KeyID)
	fmt.Println()

	// Step 3: Create agent token
	fmt.Println("Step 3: Creating AAuth agent token...")
	signedToken, err := agent.SignAgentToken(mockServer.URL)
	if err != nil {
		log.Fatalf("Failed to sign agent token: %v", err)
	}
	fmt.Printf("  Token (truncated): %s...\n", signedToken[:50])
	fmt.Println()

	// Step 4: Create DPoP proof
	fmt.Println("Step 4: Creating DPoP proof...")
	dpopProof, err := sharkauth.CreateDPoPProof(privateKey, "POST", client.TokenURL())
	if err != nil {
		log.Fatalf("Failed to create DPoP proof: %v", err)
	}
	fmt.Printf("  DPoP JTI: %s\n", dpopProof.JTI)
	fmt.Println()

	// Step 5: Exchange AAuth token for SharkAuth access token
	fmt.Println("Step 5: Exchanging token with SharkAuth...")
	resp, err := client.ExchangeAAuthToken(ctx, signedToken,
		sharkauth.WithScope("calendar:read"),
		sharkauth.WithDPoP(dpopProof.Token),
	)
	if err != nil {
		log.Fatalf("Token exchange failed: %v", err)
	}
	fmt.Printf("  Access Token (truncated): %s...\n", resp.AccessToken[:20])
	fmt.Printf("  Token Type: %s\n", resp.TokenType)
	fmt.Printf("  Expires In: %d seconds\n", resp.ExpiresIn)
	fmt.Printf("  Grant ID: %s\n", resp.GrantID)
	fmt.Println()

	// Step 6: List active grants
	fmt.Println("Step 6: Listing active grants for user...")
	grants, err := client.ListDelegationGrants(ctx,
		sharkauth.WithUserSubject("user:alice"),
		sharkauth.WithActiveOnly(),
	)
	if err != nil {
		log.Fatalf("Failed to list grants: %v", err)
	}
	fmt.Printf("  Found %d active grants\n", len(grants))
	for _, g := range grants {
		fmt.Printf("    - %s: %s -> %s\n", g.GrantID, g.UserSubject, g.ActorSubject)
	}
	fmt.Println()

	// Step 7: Revoke the grant (cascade revocation)
	fmt.Println("Step 7: Revoking delegation grant...")
	if err := client.RevokeDelegationGrant(ctx, grant.GrantID); err != nil {
		log.Fatalf("Failed to revoke grant: %v", err)
	}
	fmt.Printf("  Grant %s revoked (cascade to child grants)\n", grant.GrantID)
	fmt.Println()

	fmt.Println("=== Demo Complete ===")
}

// createMockSharkAuthServer creates a mock SharkAuth server for testing.
func createMockSharkAuthServer() *httptest.Server {
	mux := http.NewServeMux()

	// Token exchange endpoint
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check for DPoP header
		dpop := r.Header.Get("DPoP")
		tokenType := "Bearer"
		if dpop != "" {
			tokenType = "DPoP"
		}

		resp := sharkauth.TokenResponse{
			AccessToken:     "shark_" + generateID(),
			IssuedTokenType: sharkauth.TokenTypeAccessToken,
			TokenType:       tokenType,
			ExpiresIn:       3600,
			GrantID:         "grant-" + generateID(),
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock server response for demo
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// Delegation grants endpoints
	mux.HandleFunc("/grants/delegation", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			// Create grant
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			grant := sharkauth.DelegationGrant{
				GrantID:      "grant-" + generateID(),
				ActorSubject: req["actor_subject"].(string),
				UserSubject:  req["user_subject"].(string),
				Scopes:       toStringSlice(req["scopes"]),
				CreatedAt:    time.Now(),
				Active:       true,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(grant); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}

		case http.MethodGet:
			// List grants
			grants := []*sharkauth.DelegationGrant{
				{
					GrantID:      "grant-001",
					ActorSubject: "agent:calendar-bot",
					UserSubject:  "user:alice",
					Scopes:       []string{"calendar:read"},
					Active:       true,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(grants); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Single grant endpoint
	mux.HandleFunc("/grants/delegation/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			grant := sharkauth.DelegationGrant{
				GrantID: "grant-001",
				Active:  true,
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(grant); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}

		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	return httptest.NewServer(mux)
}

func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, len(arr))
	for i, item := range arr {
		result[i], _ = item.(string)
	}
	return result
}
