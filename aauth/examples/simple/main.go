// Package main demonstrates the AAuth identity-only flow.
//
// In the identity-only flow, agents present their identity token directly
// to resources without requiring an auth token from a Person Server.
// This is suitable for resources that only need to verify agent identity.
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
	// Generate keys for the agent
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate agent key: %v", err)
	}

	// Generate keys for the resource server
	resourceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate resource key: %v", err)
	}

	// Create the agent
	agentID, err := aauth.NewAAuthID("calendar-bot", "example.com")
	if err != nil {
		log.Fatalf("Failed to create agent ID: %v", err)
	}

	agent, err := aauth.NewAgent(
		agentID,
		agentKey,
		aauth.WithAgentProviderURL("https://agents.example.com"), // Agent Provider (issuer)
		aauth.WithTokenTTL(time.Hour),
	)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	fmt.Printf("Created agent: %s\n", agentID)

	// Create the resource server (identity-only mode)
	rs, err := aauth.NewResourceServer(
		"https://calendar.example.com",
		resourceKey,
		"resource-key-1",
		aauth.WithIdentityOnlyMode(true), // No auth token required
	)
	if err != nil {
		log.Fatalf("Failed to create resource server: %v", err)
	}

	fmt.Printf("Created resource server: %s\n", rs.URL())

	// Create a test HTTP server with the resource's verification middleware
	handler := rs.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the verified agent information from context
		result, ok := aauth.VerificationResultFromContext(r.Context())
		if !ok {
			http.Error(w, "No verification result", http.StatusInternalServerError)
			return
		}

		agentID, _ := aauth.AgentIDFromContext(r.Context())

		response := map[string]interface{}{
			"message":  "Hello from the resource!",
			"agent_id": agentID.String(),
			"key_id":   result.KeyID,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	fmt.Printf("Resource server running at: %s\n\n", server.URL)

	// Create a signed request to the resource
	ctx := context.Background()
	req, err := agent.SignedRequest(ctx, "GET", server.URL+"/events", nil)
	if err != nil {
		log.Fatalf("Failed to create signed request: %v", err)
	}

	fmt.Println("Sending signed request to resource...")
	fmt.Printf("  URL: %s\n", req.URL)
	fmt.Printf("  Signature-Key header present: %v\n", req.Header.Get(aauth.HeaderSignatureKey) != "")
	fmt.Printf("  Signature header present: %v\n", req.Header.Get(aauth.HeaderSignature) != "")
	fmt.Println()

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %d\n", resp.StatusCode)

	if resp.StatusCode == http.StatusOK {
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			log.Fatalf("Failed to decode response: %v", err)
		}
		fmt.Printf("Response: %v\n", body)
	} else {
		fmt.Println("Request was rejected (check signature or token)")
	}

	fmt.Println("\nIdentity-only flow completed successfully!")
}
