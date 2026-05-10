// Package main demonstrates all three agent authentication protocols.
//
// This demo shows:
//   - ID-JAG: OAuth 2.0 token exchange with JWT assertions
//   - AIMS: SPIFFE-based workload identity with WIT/WPT
//   - AAuth: HTTP message signatures with agent tokens
//
// Each protocol has different strengths and use cases. This demo
// illustrates how they can coexist in a multi-agent environment.
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
	"strings"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/aims"
	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           Multi-Protocol Agent Authentication Demo           ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Protocol  │  Identity Model  │  Authentication Method       ║")
	fmt.Println("╠════════════╪══════════════════╪══════════════════════════════╣")
	fmt.Println("║  ID-JAG    │  OAuth assertion │  Token exchange (RFC 8693)   ║")
	fmt.Println("║  AIMS      │  SPIFFE ID       │  WIT + WPT tokens            ║")
	fmt.Println("║  AAuth     │  AAuth URI       │  HTTP signatures (RFC 9421)  ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Generate shared key for demos
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Run each protocol demo
	demoIDJAG(privateKey)
	demoAIMS(privateKey)
	demoAAuth(privateKey)
	demoComparison()
}

func demoIDJAG(privateKey *ecdsa.PrivateKey) {
	fmt.Println("┌───────────────────────────────────────────────────────────────┐")
	fmt.Println("│                     ID-JAG Protocol Demo                      │")
	fmt.Println("└───────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Configuration
	issuerURL := "https://issuer.example.com"
	keyID := "idjag-key-1"
	fmt.Printf("  Issuer URL: %s\n", issuerURL)

	// Create assertion
	subject := "agent:calendar-bot"
	audience := []string{issuerURL}
	assertion := idjag.NewAssertion(issuerURL, subject, audience, 5*time.Minute)
	fmt.Printf("  Subject: %s\n", subject)
	fmt.Printf("  Audience: %v\n", audience)

	// Sign assertion
	signedAssertion, err := assertion.Sign(jwt.SigningMethodES256, privateKey, keyID)
	if err != nil {
		log.Printf("  Error signing assertion: %v\n", err)
		return
	}
	fmt.Printf("  Signed assertion: %d chars\n", len(signedAssertion))

	// Create verifier and authorization server
	verifier := idjag.NewStaticKeyVerifier(&privateKey.PublicKey, keyID, idjag.VerifierOptions{
		ExpectedIssuer: issuerURL,
	})
	authServer := idjag.NewAuthorizationServer(
		verifier,
		jwt.SigningMethodES256,
		privateKey,
		keyID,
		issuerURL,
	)

	// Start test server
	server := httptest.NewServer(authServer)
	defer server.Close()

	// Exchange assertion for access token
	client := idjag.NewTokenExchangeClient(server.URL)
	resp, err := client.ExchangeAssertion(context.Background(), signedAssertion, "read:calendar")
	if err != nil {
		fmt.Printf("  Token exchange failed: %v\n", err)
	} else {
		fmt.Printf("  Access token received: %d chars\n", len(resp.AccessToken))
		fmt.Printf("  Token type: %s\n", resp.TokenType)
		fmt.Printf("  Expires in: %d seconds\n", resp.ExpiresIn)
	}

	fmt.Println()
	fmt.Println("  ✓ ID-JAG: Token exchange completed")
	fmt.Println()
}

func demoAIMS(privateKey *ecdsa.PrivateKey) {
	fmt.Println("┌───────────────────────────────────────────────────────────────┐")
	fmt.Println("│                      AIMS Protocol Demo                       │")
	fmt.Println("└───────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Create SPIFFE ID
	spiffeID, _ := aims.NewSPIFFEID("example.com", "/agent/calendar-bot")
	fmt.Printf("  SPIFFE ID: %s\n", spiffeID.String())
	fmt.Printf("  Trust Domain: %s\n", spiffeID.TrustDomain)
	fmt.Printf("  Is Agent: %v\n", spiffeID.IsAgent())

	// Create WIT
	targetAudience := "https://api.example.com"
	wit := aims.NewWIT(
		spiffeID,
		[]string{targetAudience},
		1*time.Hour,
		aims.WithWITCNF(&aims.CNF{Kid: "aims-key-1"}),
	)
	fmt.Printf("  WIT Subject: %s\n", wit.Subject)
	fmt.Printf("  WIT Audience: %v\n", wit.Audience)

	// Sign WIT
	signedWIT, err := wit.Sign(privateKey, "aims-key-1")
	if err != nil {
		log.Printf("  Error signing WIT: %v\n", err)
		return
	}
	fmt.Printf("  Signed WIT: %d chars\n", len(signedWIT))

	// Create WPT for request
	req, _ := http.NewRequest(http.MethodPost, targetAudience+"/api/v1/events", nil)
	wpt := aims.NewWPTForRequest(spiffeID.String(), targetAudience, req)
	fmt.Printf("  WPT Method (htm): %s\n", wpt.HTM)
	fmt.Printf("  WPT URI (htu): %s\n", wpt.HTU)

	// Bind WPT to request
	if err := wpt.BindToRequest(req, privateKey, "aims-key-1"); err != nil {
		log.Printf("  Error binding WPT: %v\n", err)
		return
	}
	fmt.Printf("  WPT bound to request header: %s\n", aims.HeaderWPT)

	// Validate tokens
	if err := wit.Validate(); err != nil {
		fmt.Printf("  WIT validation: FAILED (%v)\n", err)
	} else {
		fmt.Println("  WIT validation: PASSED")
	}

	if wpt.MatchesRequest(req) {
		fmt.Println("  WPT matches request: YES")
	}

	fmt.Println()
	fmt.Println("  ✓ AIMS: WIT/WPT authentication completed")
	fmt.Println()
}

func demoAAuth(privateKey *ecdsa.PrivateKey) {
	fmt.Println("┌───────────────────────────────────────────────────────────────┐")
	fmt.Println("│                     AAuth Protocol Demo                       │")
	fmt.Println("└───────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Create AAuth ID
	agentID, _ := aauth.NewAAuthID("calendar-bot", "example.com")
	fmt.Printf("  AAuth ID: %s\n", agentID.String())
	fmt.Printf("  Local: %s\n", agentID.Local)
	fmt.Printf("  Domain: %s\n", agentID.Domain)

	// Create agent
	agent, err := aauth.NewAgent(
		agentID,
		privateKey,
		aauth.WithAgentProviderURL("https://agents.example.com"),
	)
	if err != nil {
		log.Printf("  Error creating agent: %v\n", err)
		return
	}
	fmt.Println("  Agent created with signing key")

	// Create resource server
	resourceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := aauth.NewResourceServer(
		"https://calendar.example.com",
		resourceKey,
		"resource-key-1",
		aauth.WithIdentityOnlyMode(true),
	)

	// Create handler
	handler := rs.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, _ := aauth.VerificationResultFromContext(r.Context())
		response := map[string]interface{}{
			"message":  "Access granted!",
			"agent_id": result.AgentID.String(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	// Create signed request
	ctx := context.Background()
	req, _ := agent.SignedRequest(ctx, "GET", server.URL+"/events", nil)
	fmt.Printf("  Signature-Key header: %v\n", req.Header.Get(aauth.HeaderSignatureKey) != "")
	fmt.Printf("  Signature header: %v\n", req.Header.Get(aauth.HeaderSignature) != "")

	// Send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("  Request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("  Response status: %d\n", resp.StatusCode)

	if resp.StatusCode == http.StatusOK {
		var body map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		fmt.Printf("  Response: %v\n", body["message"])
	}

	fmt.Println()
	fmt.Println("  ✓ AAuth: HTTP signature authentication completed")
	fmt.Println()
}

func demoComparison() {
	fmt.Println("┌───────────────────────────────────────────────────────────────┐")
	fmt.Println("│                    Protocol Comparison                        │")
	fmt.Println("└───────────────────────────────────────────────────────────────┘")
	fmt.Println()

	comparison := []struct {
		aspect string
		idjag  string
		aims   string
		aauth  string
	}{
		{"Identity Format", "OAuth subject", "SPIFFE ID", "AAuth URI"},
		{"Credential", "JWT assertion", "X.509/JWT SVID", "Signed HTTP"},
		{"Request Binding", "None", "WPT token", "HTTP signature"},
		{"Delegation", "act claim", "SPIFFE path", "Person Server"},
		{"Best For", "OAuth envs", "K8s/mTLS", "Agent-to-agent"},
	}

	// Print header
	fmt.Printf("  %-18s │ %-14s │ %-14s │ %-14s\n", "Aspect", "ID-JAG", "AIMS", "AAuth")
	fmt.Println("  " + strings.Repeat("─", 18) + "┼" + strings.Repeat("─", 16) + "┼" + strings.Repeat("─", 16) + "┼" + strings.Repeat("─", 16))

	// Print rows
	for _, row := range comparison {
		fmt.Printf("  %-18s │ %-14s │ %-14s │ %-14s\n", row.aspect, row.idjag, row.aims, row.aauth)
	}

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    Demo Completed Successfully                ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}
