// Package main demonstrates the AAuth resource-managed flow.
//
// In the resource-managed flow:
// 1. Agent presents identity to resource
// 2. Resource returns WWW-Authenticate challenge with resource token
// 3. Agent exchanges resource token at Person Server for auth token
// 4. Agent presents both identity and auth token to resource
//
// This flow is used when resources need to verify that the Person Server
// has authorized the agent for specific scopes.
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
)

func main() {
	// Generate keys for all parties
	agentKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resourceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	psKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create the Person Server
	ps, err := aauth.NewAuthServer(
		"https://ps.example.com",
		psKey,
		"ps-key-1",
		aauth.WithAuthTokenTTL(time.Hour),
	)
	if err != nil {
		log.Fatalf("Failed to create person server: %v", err)
	}

	// Start the Person Server
	psHandler := ps.Handler()
	psServer := httptest.NewServer(psHandler)
	defer psServer.Close()

	fmt.Printf("Person Server running at: %s\n", psServer.URL)

	// Create the agent
	agentID, _ := aauth.NewAAuthID("calendar-bot", "example.com")
	agent, err := aauth.NewAgent(
		agentID,
		agentKey,
		aauth.WithAgentProviderURL("https://agents.example.com"),
	)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	fmt.Printf("Created agent: %s\n", agentID)

	// Create the resource server
	rs, err := aauth.NewResourceServer(
		"https://calendar.example.com",
		resourceKey,
		"resource-key-1",
		aauth.WithResourcePersonServer(psServer.URL),
		aauth.WithRequiredScope("calendar:read"),
		aauth.WithIdentityOnlyMode(false), // Auth token required
	)
	if err != nil {
		log.Fatalf("Failed to create resource server: %v", err)
	}

	fmt.Printf("Created resource server: %s\n", rs.URL())

	// Create a resource handler that requires auth token
	resourceHandler := rs.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, ok := aauth.VerificationResultFromContext(r.Context())
		if !ok {
			http.Error(w, "No verification result", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"message":    "Access granted to calendar!",
			"agent_id":   result.AgentID.String(),
			"has_auth":   result.AuthToken != nil,
			"auth_scope": "",
		}
		if result.AuthToken != nil {
			response["auth_scope"] = result.AuthToken.Scope
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))

	resourceServer := httptest.NewServer(resourceHandler)
	defer resourceServer.Close()

	fmt.Printf("Resource server running at: %s\n\n", resourceServer.URL)

	// Step 1: Try to access resource without auth token
	fmt.Println("Step 1: Attempting access without auth token...")

	ctx := context.Background()
	req, _ := agent.SignedRequest(ctx, "GET", resourceServer.URL+"/events", nil)
	resp, _ := http.DefaultClient.Do(req)

	fmt.Printf("  Response: %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))

	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get(aauth.HeaderWWWAuthenticate)
		fmt.Printf("  WWW-Authenticate: %s\n", wwwAuth)

		// Parse the challenge
		challenge, err := aauth.ParseChallenge(wwwAuth)
		if err != nil {
			log.Fatalf("Failed to parse challenge: %v", err)
		}
		fmt.Printf("  Parsed challenge - Realm: %s, PS: %s\n", challenge.Realm, challenge.PersonServerURL)
	}
	resp.Body.Close()

	// Step 2: Get agent's JWK thumbprint for the resource token
	fmt.Println("\nStep 2: Creating resource token for exchange...")

	agentJKT, err := agent.KeyPair().Thumbprint()
	if err != nil {
		log.Fatalf("Failed to get agent thumbprint: %v", err)
	}

	resourceToken, err := rs.SignResourceToken(agentID, agentJKT, "calendar:read")
	if err != nil {
		log.Fatalf("Failed to sign resource token: %v", err)
	}
	fmt.Printf("  Resource token issued (length: %d chars)\n", len(resourceToken))

	// Step 3: Exchange resource token at Person Server
	fmt.Println("\nStep 3: Exchanging resource token at Person Server...")

	exchangeClient := aauth.NewExchangeClient(psServer.URL+"/token", nil)
	exchangeReq := aauth.NewResourceManagedExchangeRequest(
		resourceToken,
		[]string{rs.URL()},
		"calendar:read",
	)

	tokenResp, err := exchangeClient.Exchange(exchangeReq)
	if err != nil {
		// In a real implementation, the PS would verify the resource token
		// For this demo, we'll simulate issuing an auth token directly
		fmt.Printf("  (Exchange requires full PS implementation - simulating...)\n")

		// Simulate PS issuing an auth token
		cnf, _ := aauth.NewCNFWithJWK(&agentKey.PublicKey, "agent-key-1")
		authTokenStr, _ := ps.SignAuthToken(agentID, cnf, []string{rs.URL()}, "calendar:read")
		fmt.Printf("  Auth token issued (length: %d chars)\n", len(authTokenStr))

		// Parse for verification
		authToken, _ := aauth.ParseAuthToken(authTokenStr)
		fmt.Printf("  Auth token subject: %s\n", authToken.Subject)
		fmt.Printf("  Auth token scope: %s\n", authToken.Scope)

		tokenResp = &aauth.TokenExchangeResponse{
			AccessToken:     authTokenStr,
			IssuedTokenType: aauth.TokenTypeURIAuthJWT,
			TokenType:       "Bearer",
			ExpiresIn:       3600,
			Scope:           "calendar:read",
		}
	}

	fmt.Printf("  Received auth token (type: %s)\n", tokenResp.IssuedTokenType)

	// Step 4: Access resource with auth token
	fmt.Println("\nStep 4: Accessing resource with auth token...")

	req, _ = agent.SignedRequest(ctx, "GET", resourceServer.URL+"/events", nil)
	req.Header.Set(aauth.HeaderAuthorization, "Bearer "+tokenResp.AccessToken)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("  Response: %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))

	if resp.StatusCode == http.StatusOK {
		var body map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		fmt.Printf("  Response body: %v\n", body)
	}

	fmt.Println("\nResource-managed flow completed!")
}
