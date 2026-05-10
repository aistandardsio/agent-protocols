package aauth

import (
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
)

func TestNewAuthServer(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, err := NewAuthServer(
		"https://ps.example.com",
		privateKey,
		"test-key-1",
	)
	if err != nil {
		t.Fatalf("failed to create auth server: %v", err)
	}

	if as.Issuer() != "https://ps.example.com" {
		t.Errorf("expected issuer https://ps.example.com, got %s", as.Issuer())
	}
}

func TestNewAuthServer_Errors(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name       string
		issuer     string
		privateKey interface{}
		keyID      string
		wantErr    bool
	}{
		{
			name:       "valid",
			issuer:     "https://ps.example.com",
			privateKey: privateKey,
			keyID:      "key-1",
			wantErr:    false,
		},
		{
			name:       "empty issuer",
			issuer:     "",
			privateKey: privateKey,
			keyID:      "key-1",
			wantErr:    true,
		},
		{
			name:       "nil key",
			issuer:     "https://ps.example.com",
			privateKey: nil,
			keyID:      "key-1",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthServer(tt.issuer, tt.privateKey, tt.keyID)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAuthServerOptions(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	scopeHandler := func(agentID *AAuthID, scope string) (string, error) {
		return "granted", nil
	}

	as, err := NewAuthServer(
		"https://ps.example.com",
		privateKey,
		"test-key-1",
		WithAuthTokenTTL(2*time.Hour),
		WithTokenEndpointPath("/oauth/token"),
		WithScopeHandler(scopeHandler),
	)
	if err != nil {
		t.Fatalf("failed to create auth server: %v", err)
	}

	opts := as.Options()
	if opts.authTokenTTL != 2*time.Hour {
		t.Errorf("expected TTL 2h, got %s", opts.authTokenTTL)
	}
	if opts.tokenEndpointPath != "/oauth/token" {
		t.Errorf("expected token endpoint /oauth/token, got %s", opts.tokenEndpointPath)
	}
	if opts.scopeHandler == nil {
		t.Error("expected scope handler to be set")
	}
}

func TestAuthServer_IssueAuthToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, err := NewAuthServer(
		"https://ps.example.com",
		privateKey,
		"test-key-1",
	)
	if err != nil {
		t.Fatalf("failed to create auth server: %v", err)
	}

	agentID, _ := NewAAuthID("agent", "example.com")
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "agent-key")

	token, err := as.IssueAuthToken(
		agentID,
		cnf,
		[]string{"https://resource.example.com"},
		"read write",
	)
	if err != nil {
		t.Fatalf("failed to issue auth token: %v", err)
	}

	if token.Issuer != "https://ps.example.com" {
		t.Errorf("expected issuer https://ps.example.com, got %s", token.Issuer)
	}
	if token.Subject != "aauth:agent@example.com" {
		t.Errorf("expected subject aauth:agent@example.com, got %s", token.Subject)
	}
	if token.Scope != "read write" {
		t.Errorf("expected scope 'read write', got %s", token.Scope)
	}
}

func TestAuthServer_IssueAuthToken_Errors(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, err := NewAuthServer(
		"https://ps.example.com",
		privateKey,
		"test-key-1",
	)
	if err != nil {
		t.Fatalf("failed to create auth server: %v", err)
	}

	agentID, _ := NewAAuthID("agent", "example.com")
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "agent-key")

	tests := []struct {
		name     string
		agentID  *AAuthID
		cnf      *CNF
		audience []string
		wantErr  bool
	}{
		{
			name:     "valid",
			agentID:  agentID,
			cnf:      cnf,
			audience: []string{"https://resource.example.com"},
			wantErr:  false,
		},
		{
			name:     "nil agent ID",
			agentID:  nil,
			cnf:      cnf,
			audience: []string{"https://resource.example.com"},
			wantErr:  true,
		},
		{
			name:     "nil CNF",
			agentID:  agentID,
			cnf:      nil,
			audience: []string{"https://resource.example.com"},
			wantErr:  true,
		},
		{
			name:     "empty audience",
			agentID:  agentID,
			cnf:      cnf,
			audience: []string{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := as.IssueAuthToken(tt.agentID, tt.cnf, tt.audience, "read")
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAuthServer_SignAuthToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, err := NewAuthServer(
		"https://ps.example.com",
		privateKey,
		"test-key-1",
	)
	if err != nil {
		t.Fatalf("failed to create auth server: %v", err)
	}

	agentID, _ := NewAAuthID("agent", "example.com")
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "agent-key")

	tokenStr, err := as.SignAuthToken(
		agentID,
		cnf,
		[]string{"https://resource.example.com"},
		"read",
	)
	if err != nil {
		t.Fatalf("failed to sign auth token: %v", err)
	}

	if tokenStr == "" {
		t.Error("expected non-empty token string")
	}

	// Verify it's a valid JWT
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts in JWT, got %d", len(parts))
	}
}

func TestAuthServer_ServeHTTP_MethodNotAllowed(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, _ := NewAuthServer("https://ps.example.com", privateKey, "test-key")

	req := httptest.NewRequest("GET", "/token", nil)
	rec := httptest.NewRecorder()

	as.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}

func TestAuthServer_ServeHTTP_InvalidRequest(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, _ := NewAuthServer("https://ps.example.com", privateKey, "test-key")

	// Missing required fields
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	as.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var errResp TokenErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != ErrorInvalidRequest {
		t.Errorf("expected error code %s, got %s", ErrorInvalidRequest, errResp.Error)
	}
}

func TestAuthServer_ServeHTTP_UnsupportedGrantType(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Configure server to only support a custom grant type
	as, _ := NewAuthServer(
		"https://ps.example.com",
		privateKey,
		"test-key",
		WithSupportedGrantTypes([]string{"custom_grant"}),
	)

	// Use a valid token exchange request format, but the server doesn't support this grant type
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", "test-token")
	form.Set("subject_token_type", TokenTypeURIAgentJWT)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	as.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var errResp TokenErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != ErrorUnsupportedGrantType {
		t.Errorf("expected error code %s, got %s", ErrorUnsupportedGrantType, errResp.Error)
	}
}

func TestAuthServer_Metadata(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, _ := NewAuthServer(
		"https://ps.example.com",
		privateKey,
		"test-key",
		WithTokenEndpointPath("/oauth/token"),
	)

	metadata := as.Metadata()

	if metadata.Issuer != "https://ps.example.com" {
		t.Errorf("expected issuer https://ps.example.com, got %s", metadata.Issuer)
	}
	if metadata.TokenEndpoint != "https://ps.example.com/oauth/token" {
		t.Errorf("expected token endpoint https://ps.example.com/oauth/token, got %s", metadata.TokenEndpoint)
	}
	if metadata.JWKSURI != "https://ps.example.com/.well-known/jwks.json" {
		t.Errorf("expected JWKS URI ending with .well-known/jwks.json, got %s", metadata.JWKSURI)
	}
	if len(metadata.GrantTypesSupported) == 0 {
		t.Error("expected at least one grant type")
	}
}

func TestAuthServer_PublicJWKS(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, _ := NewAuthServer("https://ps.example.com", privateKey, "test-key")

	jwks, err := as.PublicJWKS()
	if err != nil {
		t.Fatalf("failed to get JWKS: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != "test-key" {
		t.Errorf("expected kid 'test-key', got %s", jwks.Keys[0].Kid)
	}
}

func TestAuthServer_TokenEndpoint(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, _ := NewAuthServer(
		"https://ps.example.com",
		privateKey,
		"test-key",
		WithTokenEndpointPath("/oauth/token"),
	)

	if as.TokenEndpoint() != "https://ps.example.com/oauth/token" {
		t.Errorf("expected https://ps.example.com/oauth/token, got %s", as.TokenEndpoint())
	}
}

func TestAuthServer_Handler(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, _ := NewAuthServer("https://ps.example.com", privateKey, "test-key")

	handler := as.Handler()
	if handler == nil {
		t.Error("expected non-nil handler")
	}
}

func TestAuthServer_KeyPair(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	as, _ := NewAuthServer("https://ps.example.com", privateKey, "test-key")

	kp := as.KeyPair()
	if kp == nil {
		t.Fatal("expected non-nil key pair")
	}
	if kp.KeyID != "test-key" {
		t.Errorf("expected key ID 'test-key', got %s", kp.KeyID)
	}
}
