// Package main demonstrates ID-JAG with human-to-agent delegation.
//
// This example shows the IETF-compliant flow per draft-ietf-oauth-identity-assertion-authz-grant:
//
//  1. Agent requests ID-JAG from IdP using token exchange (grant_type=token-exchange,
//     requested_token_type=id-jag)
//  2. Agent exchanges ID-JAG at Resource AS using JWT bearer (grant_type=jwt-bearer)
//  3. Agent calls protected resource with access token
//
// The ID-JAG structure per IETF draft:
//
//	Header: {"typ": "oauth-id-jag+jwt", "alg": "RS256"}
//	Payload: {
//	  "iss": "https://idp.example.com",
//	  "sub": "user:alice",
//	  "aud": "https://api.example.com",
//	  "client_id": "agent-client-123",
//	  "jti": "unique-token-id",
//	  "exp": 1699900000,
//	  "iat": 1699896400,
//	  "act": {"sub": "agent:calendar-bot"}  // Optional per RFC 8693
//	}
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

	"github.com/aistandardsio/agent-protocols/idjag"
)

const (
	serverAddr = "localhost:18081"
	keyID      = "demo-key-1"
	idpIssuer  = "https://idp.example.com"
	authServer = "http://localhost:18081"
)

func main() {
	// Generate RSA key pair for signing (shared by IdP and Auth Server in this demo)
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

	// === IdP Authorization Server ===
	// Issues ID-JAG assertions via OAuth token exchange
	idpServer := idjag.NewIdPAuthorizationServer(idpIssuer, jwt.SigningMethodRS256, privateKey, keyID)
	idpServer.AssertionTTL = 5 * time.Minute
	idpServer.DelegationPolicy = func(ctx context.Context, req *idjag.IDJAGRequest) error {
		log.Printf("   [IdP] Validating delegation for client: %s", req.ClientID)
		return nil // In production: verify user authorized this agent
	}

	// === Resource Authorization Server ===
	// Exchanges ID-JAG for access tokens via JWT bearer
	resourceVerifier := idjag.NewStaticKeyVerifier(publicKey, keyID, idjag.VerifierOptions{
		ExpectedIssuer:   idpIssuer,
		ExpectedAudience: authServer,
	})
	resourceAuthServer := idjag.NewAuthorizationServer(
		resourceVerifier,
		jwt.SigningMethodRS256,
		privateKey,
		keyID,
		authServer,
	)
	resourceAuthServer.TokenTTL = 1 * time.Hour

	// === Resource Server ===
	accessTokenVerifier := idjag.NewStaticKeyVerifier(publicKey, keyID, idjag.VerifierOptions{
		ExpectedIssuer: authServer,
	})
	resourceServer := idjag.NewResourceServer(accessTokenVerifier)

	// Set up HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", idjag.NewJWKSHandler(jwks).ServeHTTP)
	mux.HandleFunc("POST /idp/token", idpServer.ServeHTTP)      // IdP token endpoint
	mux.HandleFunc("POST /token", resourceAuthServer.ServeHTTP) // Resource AS token endpoint
	mux.HandleFunc("GET /calendar", resourceServer.Middleware(http.HandlerFunc(handleCalendar)).ServeHTTP)

	// Start server in background
	server := &http.Server{
		Addr:              serverAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Server starting on %s", serverAddr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Run the demo
	if err := runDemo(privateKey); err != nil {
		log.Fatalf("Demo failed: %v", err)
	}

	log.Println("\nDemo completed successfully!")
}

func runDemo(privateKey *rsa.PrivateKey) error {
	ctx := context.Background()

	log.Println("\n=== ID-JAG IETF-Compliant Delegation Demo ===")
	log.Println("This demo shows the two-step IETF draft flow:")
	log.Println("  Step 1: token-exchange with requested_token_type=id-jag (IdP)")
	log.Println("  Step 2: jwt-bearer with assertion=ID-JAG (Resource AS)")

	// Simulate: User has already authenticated and we have their ID token
	// In production, this would come from OIDC authentication
	userIDToken := createMockUserIDToken(privateKey)
	log.Println("\n0. User has authenticated (simulated ID token)")

	// Step 1: Request ID-JAG from IdP using OAuth token exchange
	log.Println("\n1. Agent requesting ID-JAG from IdP...")
	log.Println("   grant_type=token-exchange")
	log.Println("   requested_token_type=urn:ietf:params:oauth:token-type:id-jag")

	idpClient := idjag.NewIDJAGClient(fmt.Sprintf("http://%s/idp/token", serverAddr))
	idjagResp, err := idpClient.RequestIDJAG(ctx, &idjag.IDJAGRequest{
		SubjectToken:     userIDToken,
		SubjectTokenType: idjag.TokenTypeIDToken,
		Audience:         authServer,
		ClientID:         "agent:calendar-bot",
		Scope:            "calendar:read",
	})
	if err != nil {
		return fmt.Errorf("failed to get ID-JAG: %w", err)
	}
	log.Printf("   ID-JAG received (issued_token_type=%s)", idjagResp.IssuedTokenType)
	log.Printf("   Token type: %s (N_A per RFC 8693)", idjagResp.TokenType)

	// Verify the ID-JAG has the correct typ header
	parsed, _ := idjag.ParseAssertion(idjagResp.AccessToken)
	log.Printf("   ID-JAG subject: %s", parsed.Subject)
	log.Printf("   ID-JAG client_id: %s", parsed.ClientID)

	// Step 2: Exchange ID-JAG at Resource Authorization Server
	log.Println("\n2. Exchanging ID-JAG for access token at Resource AS...")
	log.Println("   grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer")

	jwtBearerClient := idjag.NewJWTBearerClient(fmt.Sprintf("http://%s/token", serverAddr))
	tokenResp, err := jwtBearerClient.Exchange(ctx, idjagResp.AccessToken, "calendar:read")
	if err != nil {
		return fmt.Errorf("JWT bearer exchange failed: %w", err)
	}
	log.Printf("   Access token received (length: %d)", len(tokenResp.AccessToken))
	log.Printf("   Token type: %s", tokenResp.TokenType)

	// Step 3: Call protected resource
	log.Println("\n3. Agent calling calendar API with access token...")
	data, err := callCalendarAPI(tokenResp.AccessToken)
	if err != nil {
		return fmt.Errorf("calendar API call failed: %w", err)
	}
	log.Printf("   Response: %s", data)

	return nil
}

// createMockUserIDToken simulates an OIDC ID token from user authentication
func createMockUserIDToken(privateKey *rsa.PrivateKey) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": idpIssuer,
		"sub": "user:alice",
		"aud": idpIssuer,
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	signedToken, _ := token.SignedString(privateKey)
	return signedToken
}

func callCalendarAPI(accessToken string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/calendar", serverAddr), nil)
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

func handleCalendar(w http.ResponseWriter, r *http.Request) {
	assertion := idjag.AssertionFromContext(r.Context())
	if assertion == nil {
		http.Error(w, "no assertion in context", http.StatusInternalServerError)
		return
	}

	response := map[string]any{
		"message":   "Calendar access granted",
		"user":      assertion.Subject,
		"delegated": assertion.IsDelegated(),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if assertion.IsDelegated() {
		chain := assertion.DelegationChain()
		actors := make([]string, len(chain))
		for i, actor := range chain {
			actors[i] = actor.Subject
		}
		response["acting_as"] = actors
	}

	response["events"] = []map[string]string{
		{"title": "Team Standup", "time": "09:00"},
		{"title": "Project Review", "time": "14:00"},
		{"title": "1:1 Meeting", "time": "16:00"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
