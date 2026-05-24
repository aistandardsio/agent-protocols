// Package main demonstrates cross-protocol bridging capabilities.
//
// This demo shows:
//   - Multi-protocol gateway accepting ID-JAG, AIMS, or AAuth tokens
//   - Protocol detection from JWT typ headers
//   - Token conversion between protocols
//   - Unified identity representation across all protocols
//
// Use case: Gateway services that need to accept tokens from different
// client types (OAuth clients, workloads, AI agents) and normalize them
// to a common identity format.
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
	"github.com/aistandardsio/agent-protocols/aims"
	"github.com/aistandardsio/agent-protocols/bridge"
	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Cross-Protocol Bridge Demo                       ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Demonstrates protocol-agnostic authentication gateway        ║")
	fmt.Println("║  with token conversion and unified identity handling          ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Generate keys for each protocol
	idjagKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	aimsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	aauthKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Run demos
	demoProtocolDetection()
	demoMultiProtocolGateway(idjagKey, aimsKey, aauthKey)
	demoTokenConversion(idjagKey)
	demoIdentityNormalization()

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Protocol Bridge Demo Complete                    ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

func demoProtocolDetection() {
	fmt.Println("┌───────────────────────────────────────────────────────────────┐")
	fmt.Println("│                  Protocol Detection Demo                      │")
	fmt.Println("└───────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Create sample tokens for each protocol
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// ID-JAG token
	idjagAssertion := idjag.NewAssertion(
		"https://issuer.example.com",
		"user@example.com",
		[]string{"https://api.example.com"},
		time.Hour,
	)
	idjagAssertion.ClientID = "client-123"
	idjagToken, _ := idjagAssertion.Sign(jwt.SigningMethodES256, key, "key-1")

	// AIMS WIT
	spiffeID, _ := aims.NewSPIFFEID("example.com", "/workload/api")
	wit := aims.NewWIT(spiffeID, []string{"https://api.example.com"}, time.Hour)
	aimsToken, _ := wit.Sign(key, "key-1")

	// AAuth token
	aauthID, _ := aauth.NewAAuthID("agent", "example.com")
	agentToken := aauth.NewAgentToken(
		"https://issuer.example.com",
		aauthID.String(),
		&aauth.CNF{Kid: "agent-key"},
		time.Hour,
	)
	agentToken.Audience = []string{"https://api.example.com"}
	aauthToken, _ := agentToken.Sign(jwt.SigningMethodES256, key, "key-1")

	// Detect each protocol
	tokens := []struct {
		name  string
		token string
	}{
		{"ID-JAG", idjagToken},
		{"AIMS", aimsToken},
		{"AAuth", aauthToken},
	}

	fmt.Println("  Detecting protocol from JWT typ header:")
	fmt.Println()

	for _, t := range tokens {
		protocol, err := bridge.DetectProtocol(t.token)
		if err != nil {
			fmt.Printf("  %-8s → Error: %v\n", t.name, err)
		} else {
			fmt.Printf("  %-8s → Detected: %s\n", t.name, protocol)
		}
	}

	fmt.Println()
	fmt.Println("  ✓ Protocol detection completed")
	fmt.Println()
}

func demoMultiProtocolGateway(idjagKey, aimsKey, aauthKey *ecdsa.PrivateKey) {
	fmt.Println("┌───────────────────────────────────────────────────────────────┐")
	fmt.Println("│               Multi-Protocol Gateway Demo                     │")
	fmt.Println("└───────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Create verifiers for each protocol
	idjagVerifier := &mockIDJAGVerifier{key: &idjagKey.PublicKey}
	witVerifier := &mockWITVerifier{key: &aimsKey.PublicKey}
	aauthVerifier := &mockAAuthVerifier{key: &aauthKey.PublicKey}

	// Create protected resource handler
	resourceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := bridge.IdentityFromContext(r.Context())
		if !ok {
			http.Error(w, "no identity", http.StatusUnauthorized)
			return
		}

		protocol := bridge.ProtocolFromContext(r.Context())

		response := map[string]interface{}{
			"message":  "Access granted via unified gateway",
			"protocol": string(protocol),
			"subject":  identity.Subject,
			"issuer":   identity.Issuer,
		}

		if identity.HasKeyBinding() {
			response["key_bound"] = true
		}
		if identity.HasDelegation() {
			response["delegated"] = true
			response["actor"] = identity.Actor.Subject
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})

	// Create multi-protocol middleware
	gateway := bridge.MultiProtocolMiddleware(
		bridge.WithIDJAGVerifier(idjagVerifier),
		bridge.WithWITVerifier(witVerifier),
		bridge.WithAAuthVerifier(aauthVerifier),
	)(resourceHandler)

	server := httptest.NewServer(gateway)
	defer server.Close()

	fmt.Println("  Gateway accepts: ID-JAG, AIMS, AAuth")
	fmt.Println()

	// Test with ID-JAG token
	fmt.Println("  Testing ID-JAG client:")
	idjagAssertion := idjag.NewAssertion(
		"https://idp.example.com",
		"oauth-user@example.com",
		[]string{"https://api.example.com"},
		time.Hour,
	)
	idjagAssertion.ClientID = "web-client"
	idjagToken, _ := idjagAssertion.Sign(jwt.SigningMethodES256, idjagKey, "idjag-key")

	testGateway(server.URL, idjagToken, "ID-JAG")

	// Test with AIMS token
	fmt.Println("  Testing AIMS workload:")
	spiffeID, _ := aims.NewSPIFFEID("k8s.example.com", "/ns/prod/sa/api-service")
	wit := aims.NewWIT(spiffeID, []string{"https://api.example.com"}, time.Hour,
		aims.WithWITCNF(&aims.CNF{Kid: "workload-key"}))
	aimsToken, _ := wit.Sign(aimsKey, "aims-key")

	testGateway(server.URL, aimsToken, "AIMS")

	// Test with AAuth token
	fmt.Println("  Testing AAuth agent:")
	aauthID, _ := aauth.NewAAuthID("assistant", "agents.example.com")
	agentToken := aauth.NewAgentToken(
		"https://agents.example.com",
		aauthID.String(),
		&aauth.CNF{Kid: "agent-signing-key"},
		time.Hour,
	)
	agentToken.Audience = []string{"https://api.example.com"}
	agentToken.Actor = &aauth.Actor{
		Subject: "human@example.com",
		Issuer:  "https://idp.example.com",
	}
	aauthToken, _ := agentToken.Sign(jwt.SigningMethodES256, aauthKey, "aauth-key")

	testGateway(server.URL, aauthToken, "AAuth")

	fmt.Println("  ✓ Multi-protocol gateway demo completed")
	fmt.Println()
}

func testGateway(url, token, name string) {
	req, _ := http.NewRequest("GET", url+"/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("    %s request failed: %v\n", name, err)
		return
	}
	defer resp.Body.Close()

	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)

	fmt.Printf("    Protocol: %s, Subject: %s\n", body["protocol"], body["subject"])
	if body["delegated"] == true {
		fmt.Printf("    Delegation: Acting on behalf of %s\n", body["actor"])
	}
	fmt.Println()
}

func demoTokenConversion(key *ecdsa.PrivateKey) {
	fmt.Println("┌───────────────────────────────────────────────────────────────┐")
	fmt.Println("│                 Token Conversion Demo                         │")
	fmt.Println("└───────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Start with an ID-JAG assertion
	fmt.Println("  Starting with ID-JAG assertion:")
	idjagAssertion := &idjag.Assertion{
		Issuer:    "https://idp.example.com",
		Subject:   "user@example.com",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "mobile-app",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		JWTID:     "jti-12345",
		Actor: &idjag.Actor{
			Subject: "agent@example.com",
			Issuer:  "https://agents.example.com",
		},
	}
	fmt.Printf("    Subject: %s\n", idjagAssertion.Subject)
	fmt.Printf("    Client ID: %s\n", idjagAssertion.ClientID)
	fmt.Printf("    Acting on behalf of: %s\n", idjagAssertion.Actor.Subject)
	fmt.Println()

	// Convert to canonical identity
	fmt.Println("  Converting to canonical identity:")
	identity, err := bridge.FromIDJAG(idjagAssertion)
	if err != nil {
		log.Printf("    Conversion failed: %v\n", err)
		return
	}
	fmt.Printf("    Protocol: %s\n", identity.Protocol)
	fmt.Printf("    Subject: %s\n", identity.Subject)
	fmt.Printf("    Has delegation: %v\n", identity.HasDelegation())
	fmt.Println()

	// Convert to AAuth agent token
	fmt.Println("  Converting to AAuth agent token:")
	cnf := &aauth.CNF{Kid: "new-agent-key"}
	aauthToken, err := identity.ToAAuth(cnf)
	if err != nil {
		log.Printf("    Conversion failed: %v\n", err)
		return
	}
	fmt.Printf("    Subject: %s\n", aauthToken.Subject)
	fmt.Printf("    CNF Kid: %s\n", aauthToken.CNF.Kid)
	if aauthToken.Actor != nil {
		fmt.Printf("    Actor preserved: %s\n", aauthToken.Actor.Subject)
	}
	fmt.Println()

	// Sign the converted token
	fmt.Println("  Signing converted AAuth token:")
	signedAAuth, err := identity.SignAAuth(cnf, key, "bridge-key")
	if err != nil {
		log.Printf("    Signing failed: %v\n", err)
		return
	}
	fmt.Printf("    Signed token: %d chars\n", len(signedAAuth))

	// Verify detection
	protocol, _ := bridge.DetectProtocol(signedAAuth)
	fmt.Printf("    Detected protocol: %s\n", protocol)
	fmt.Println()

	// Convert to AIMS WIT
	fmt.Println("  Converting to AIMS WIT:")
	wit, err := identity.ToWIT()
	if err != nil {
		log.Printf("    Conversion failed: %v\n", err)
		return
	}
	fmt.Printf("    Subject: %s\n", wit.Subject)
	fmt.Printf("    Issuer: %s\n", wit.Issuer)
	fmt.Println()

	fmt.Println("  ✓ Token conversion demo completed")
	fmt.Println()
}

func demoIdentityNormalization() {
	fmt.Println("┌───────────────────────────────────────────────────────────────┐")
	fmt.Println("│              Identity Normalization Demo                      │")
	fmt.Println("└───────────────────────────────────────────────────────────────┘")
	fmt.Println()

	fmt.Println("  Creating identities from different protocols:")
	fmt.Println()

	// ID-JAG identity
	idjagAssertion := &idjag.Assertion{
		Issuer:    "https://oauth.example.com",
		Subject:   "oauth-user-123",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "spa-client",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	idjagIdentity, _ := bridge.FromIDJAG(idjagAssertion)

	// AIMS identity
	spiffeID, _ := aims.NewSPIFFEID("cluster.local", "/ns/default/sa/backend")
	wit := &aims.WorkloadIdentityToken{
		Issuer:   "https://spire.cluster.local",
		Subject:  spiffeID.String(),
		Audience: []string{"https://api.example.com"},
		IssuedAt: time.Now(),
		Expiry:   time.Now().Add(time.Hour),
		CNF:      &aims.CNF{Kid: "svid-key"},
	}
	aimsIdentity, _ := bridge.FromWIT(wit)

	// AAuth identity
	aauthToken := &aauth.AgentToken{
		Issuer:    "https://agents.example.com",
		Subject:   "aauth:assistant@agents.example.com",
		Audience:  []string{"https://api.example.com"},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		CNF:       &aauth.CNF{Kid: "agent-key"},
		Actor: &aauth.Actor{
			Subject: "human@example.com",
		},
	}
	aauthIdentity, _ := bridge.FromAAuth(aauthToken)

	// Display normalized identities
	identities := []*bridge.Identity{idjagIdentity, aimsIdentity, aauthIdentity}

	fmt.Printf("  %-10s │ %-35s │ %-8s │ %-10s\n", "Protocol", "Subject", "KeyBind", "Delegation")
	fmt.Println("  " + "──────────┼─────────────────────────────────────┼──────────┼────────────")

	for _, id := range identities {
		keyBind := "No"
		if id.HasKeyBinding() {
			keyBind = "Yes"
		}
		delegation := "No"
		if id.HasDelegation() {
			delegation = "Yes"
		}

		subject := id.Subject
		if len(subject) > 35 {
			subject = subject[:32] + "..."
		}

		fmt.Printf("  %-10s │ %-35s │ %-8s │ %-10s\n",
			id.Protocol, subject, keyBind, delegation)
	}

	fmt.Println()
	fmt.Println("  All identities share common fields:")
	fmt.Println("    - Issuer, Subject, Audience")
	fmt.Println("    - IssuedAt, ExpiresAt, JWTID")
	fmt.Println("    - KeyBinding (proof-of-possession)")
	fmt.Println("    - Actor (delegation chain)")
	fmt.Println()

	fmt.Println("  ✓ Identity normalization demo completed")
	fmt.Println()
}

// Mock verifiers for demo

type mockIDJAGVerifier struct {
	key *ecdsa.PublicKey
}

func (v *mockIDJAGVerifier) Verify(_ context.Context, tokenString string) (*idjag.Assertion, error) {
	return idjag.ParseAssertion(tokenString)
}

type mockWITVerifier struct {
	key *ecdsa.PublicKey
}

func (v *mockWITVerifier) Verify(tokenString string) (*aims.WorkloadIdentityToken, error) {
	return aims.ParseWIT(tokenString)
}

type mockAAuthVerifier struct {
	key *ecdsa.PublicKey
}

func (v *mockAAuthVerifier) VerifyAgentToken(_ context.Context, tokenString string) (*aauth.AgentToken, error) {
	return aauth.ParseAgentToken(tokenString)
}
