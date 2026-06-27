package authzserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

func setupTestServer(t *testing.T) (*Server, *MockStore, *ecdsa.PrivateKey) {
	t.Helper()

	store := NewMockStore()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create some default policies
	_ = store.CreateScopePolicy(context.Background(), &ScopePolicy{
		ID:       "policy-read",
		Pattern:  "read:*",
		Protocol: "idjag",
		Priority: 100,
	})
	_ = store.CreateScopePolicy(context.Background(), &ScopePolicy{
		ID:              "policy-write",
		Pattern:         "write:*",
		Protocol:        "aauth",
		InteractionType: "supervised",
		Priority:        100,
	})

	server, err := New(store, "https://auth.example.com", key, "key-1")
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	return server, store, key
}

func createTestAssertion(t *testing.T, key *ecdsa.PrivateKey, subject, actor, issuer string) string {
	t.Helper()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"aud": issuer,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	if actor != "" {
		claims["act"] = map[string]string{"sub": actor}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = idjag.TokenTypeIDJAG

	signedToken, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("Failed to sign assertion: %v", err)
	}

	return signedToken
}

func TestHandleMetadata(t *testing.T) {
	server, _, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	server.HandleMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var metadata map[string]any
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("Failed to decode metadata: %v", err)
	}

	if metadata["issuer"] != "https://auth.example.com" {
		t.Errorf("Unexpected issuer: %v", metadata["issuer"])
	}
	if metadata["token_endpoint"] != "https://auth.example.com/token" {
		t.Errorf("Unexpected token_endpoint: %v", metadata["token_endpoint"])
	}
}

func TestHandleJWKS(t *testing.T) {
	server, _, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	server.HandleJWKS(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var jwks map[string]any
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("Failed to decode JWKS: %v", err)
	}

	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Errorf("Expected 1 key in JWKS, got %v", jwks["keys"])
	}
}

func TestHandleToken_UnsupportedGrantType(t *testing.T) {
	server, _, _ := setupTestServer(t)

	form := url.Values{}
	form.Set("grant_type", "unsupported")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error: %v", err)
	}
	if errResp.Error != "unsupported_grant_type" {
		t.Errorf("Expected unsupported_grant_type error, got %s", errResp.Error)
	}
}

func TestHandleToken_TokenExchange_MissingSubjectToken(t *testing.T) {
	server, _, _ := setupTestServer(t)

	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	// Missing subject_token

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error: %v", err)
	}
	if errResp.Error != "invalid_request" {
		t.Errorf("Expected invalid_request error, got %s", errResp.Error)
	}
}

func TestHandleToken_TokenExchange_Success(t *testing.T) {
	server, _, key := setupTestServer(t)

	// Create assertion (without verifier, it will be parsed without verification)
	assertion := createTestAssertion(t, key, "user-1", "agent-1", "https://auth.example.com")

	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", assertion)
	form.Set("subject_token_type", TokenTypeIDJAG)
	form.Set("scope", "read:email read:profile")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Error("Expected access token")
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("Expected Bearer token type, got %s", tokenResp.TokenType)
	}
}

func TestHandleToken_JWTBearer_Success(t *testing.T) {
	server, _, key := setupTestServer(t)

	// Create assertion
	assertion := createTestAssertion(t, key, "user-1", "agent-1", "https://auth.example.com")

	form := url.Values{}
	form.Set("grant_type", GrantTypeJWTBearer)
	form.Set("assertion", assertion)
	form.Set("scope", "read:data")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleToken_ConsentRequired(t *testing.T) {
	store := NewMockStore()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create policy requiring aauth
	_ = store.CreateScopePolicy(context.Background(), &ScopePolicy{
		ID:       "policy-write",
		Pattern:  "write:*",
		Protocol: "aauth",
		Priority: 100,
	})

	server, _ := New(store, "https://auth.example.com", key, "key-1",
		WithPersonServerURL("https://person.example.com"),
	)

	assertion := createTestAssertion(t, key, "user-1", "agent-1", "https://auth.example.com")

	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", assertion)
	form.Set("subject_token_type", TokenTypeIDJAG)
	form.Set("scope", "write:profile")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.HandleToken(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error: %v", err)
	}
	if errResp.Error != "consent_required" {
		t.Errorf("Expected consent_required error, got %s", errResp.Error)
	}
}

func TestHandleIntrospect(t *testing.T) {
	server, _, key := setupTestServer(t)

	// Create a token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   "https://auth.example.com",
		"sub":   "user-1",
		"scope": "read:email",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, _ := token.SignedString(key)

	form := url.Values{}
	form.Set("token", signedToken)

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.HandleIntrospect(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var introspectResp IntrospectionResponse
	if err := json.NewDecoder(w.Body).Decode(&introspectResp); err != nil {
		t.Fatalf("Failed to decode introspection response: %v", err)
	}
	if !introspectResp.Active {
		t.Error("Expected active=true")
	}
	if introspectResp.Sub != "user-1" {
		t.Errorf("Expected sub=user-1, got %s", introspectResp.Sub)
	}
}

func TestHandleIntrospect_ExpiredToken(t *testing.T) {
	server, _, key := setupTestServer(t)

	// Create an expired token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://auth.example.com",
		"sub": "user-1",
		"iat": now.Add(-2 * time.Hour).Unix(),
		"exp": now.Add(-time.Hour).Unix(), // Expired
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, _ := token.SignedString(key)

	form := url.Values{}
	form.Set("token", signedToken)

	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.HandleIntrospect(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var introspectResp IntrospectionResponse
	if err := json.NewDecoder(w.Body).Decode(&introspectResp); err != nil {
		t.Fatalf("Failed to decode introspection response: %v", err)
	}
	if introspectResp.Active {
		t.Error("Expected active=false for expired token")
	}
}

func TestHandleRevoke(t *testing.T) {
	server, store, key := setupTestServer(t)

	// Create a token with jti claim
	now := time.Now()
	tokenID := "token-123"
	claims := jwt.MapClaims{
		"iss": "https://auth.example.com",
		"sub": "user-1",
		"jti": tokenID,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, _ := token.SignedString(key)

	// Store the token
	_ = store.CreateToken(context.Background(), &Token{
		ID:        tokenID,
		UserID:    "user-1",
		ExpiresAt: now.Add(time.Hour),
	})

	form := url.Values{}
	form.Set("token", signedToken)

	req := httptest.NewRequest("POST", "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.HandleRevoke(w, req)

	// RFC 7009: always return 200 for revocation
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHandlePolicyEvaluate(t *testing.T) {
	server, _, _ := setupTestServer(t)

	reqBody := map[string]any{
		"agent_id": "agent-1",
		"scopes":   []string{"read:email", "write:profile"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/policy/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandlePolicyEvaluate(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var decision PolicyDecision
	if err := json.NewDecoder(w.Body).Decode(&decision); err != nil {
		t.Fatalf("Failed to decode decision: %v", err)
	}
	if decision.Protocol != "aauth" {
		t.Errorf("Expected aauth protocol (mixed scopes), got %s", decision.Protocol)
	}
}

func TestHandleListPolicies(t *testing.T) {
	server, _, _ := setupTestServer(t)

	req := httptest.NewRequest("GET", "/admin/policies", nil)
	w := httptest.NewRecorder()

	server.HandleListPolicies(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var policies []*ScopePolicy
	if err := json.NewDecoder(w.Body).Decode(&policies); err != nil {
		t.Fatalf("Failed to decode policies: %v", err)
	}
	if len(policies) < 1 {
		t.Error("Expected at least 1 policy")
	}
}

func TestHandleCreatePolicy(t *testing.T) {
	server, _, _ := setupTestServer(t)

	policy := ScopePolicy{
		Pattern:  "delete:*",
		Protocol: "aauth",
		Priority: 200,
	}
	body, _ := json.Marshal(policy)

	req := httptest.NewRequest("POST", "/admin/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.HandleCreatePolicy(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var created ScopePolicy
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("Failed to decode created policy: %v", err)
	}
	if created.ID == "" {
		t.Error("Expected policy ID to be generated")
	}
}

func TestHandleListTokens(t *testing.T) {
	server, store, _ := setupTestServer(t)

	// Create a token
	_ = store.CreateToken(context.Background(), &Token{
		AgentID:   "agent-1",
		UserID:    "user-1",
		Scopes:    "read:data",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	req := httptest.NewRequest("GET", "/admin/tokens", nil)
	w := httptest.NewRecorder()

	server.HandleListTokens(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var tokens []*Token
	if err := json.NewDecoder(w.Body).Decode(&tokens); err != nil {
		t.Fatalf("Failed to decode tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("Expected 1 token, got %d", len(tokens))
	}
}

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"read:email", []string{"read:email"}},
		{"read:email write:profile", []string{"read:email", "write:profile"}},
		{"  read:email   write:profile  ", []string{"read:email", "write:profile"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitScopes(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("splitScopes(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitScopes(%q)[%d] = %v, want %v", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}
