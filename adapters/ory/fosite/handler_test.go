package fosite

import (
	"context"
	"testing"
	"time"

	"github.com/aistandardsio/agent-protocols/idjag"
)

func TestIDJAGHandlerCanHandle(t *testing.T) {
	handler := &IDJAGHandler{}

	tests := []struct {
		name      string
		grantType string
		want      bool
	}{
		{"jwt-bearer", GrantTypeJWTBearer, true},
		{"token-exchange", GrantTypeTokenExchange, true},
		{"client-credentials", "client_credentials", false},
		{"password", "password", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &TokenRequest{GrantType: tt.grantType}
			if got := handler.CanHandle(req); got != tt.want {
				t.Errorf("CanHandle() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAAuthHandlerCanHandle(t *testing.T) {
	handler := &AAuthHandler{}

	tests := []struct {
		name             string
		grantType        string
		subjectTokenType string
		want             bool
	}{
		{"aauth-agent", GrantTypeAAuthAgent, "", true},
		{"token-exchange-aauth", GrantTypeTokenExchange, TokenTypeAAuthAgent, true},
		{"token-exchange-jwt", GrantTypeTokenExchange, TokenTypeJWT, false},
		{"jwt-bearer", GrantTypeJWTBearer, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &TokenRequest{
				GrantType:        tt.grantType,
				SubjectTokenType: tt.subjectTokenType,
			}
			if got := handler.CanHandle(req); got != tt.want {
				t.Errorf("CanHandle() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultHandlerConfig(t *testing.T) {
	config := DefaultHandlerConfig("https://auth.example.com")

	if config.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %v, want https://auth.example.com", config.Issuer)
	}

	if config.AccessTokenLifetime != time.Hour {
		t.Errorf("AccessTokenLifetime = %v, want 1h", config.AccessTokenLifetime)
	}

	if config.RefreshTokenLifetime != 24*time.Hour {
		t.Errorf("RefreshTokenLifetime = %v, want 24h", config.RefreshTokenLifetime)
	}
}

func TestDefaultScopeStrategy(t *testing.T) {
	strategy := DefaultScopeStrategy{}
	scopes, err := strategy.ValidateScopes([]string{"read", "write"}, nil)
	if err != nil {
		t.Fatalf("ValidateScopes() error = %v", err)
	}

	if len(scopes) != 2 || scopes[0] != "read" || scopes[1] != "write" {
		t.Errorf("ValidateScopes() = %v, want [read write]", scopes)
	}
}

func TestDefaultAudienceStrategy(t *testing.T) {
	strategy := DefaultAudienceStrategy{}
	err := strategy.ValidateAudience([]string{"https://api.example.com"})
	if err != nil {
		t.Errorf("ValidateAudience() error = %v", err)
	}
}

func TestScopesToString(t *testing.T) {
	tests := []struct {
		scopes []string
		want   string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"read"}, "read"},
		{[]string{"read", "write"}, "read write"},
		{[]string{"a", "b", "c"}, "a b c"},
	}

	for _, tt := range tests {
		got := scopesToString(tt.scopes)
		if got != tt.want {
			t.Errorf("scopesToString(%v) = %v, want %v", tt.scopes, got, tt.want)
		}
	}
}

func TestNewIDJAGHandler(t *testing.T) {
	verifier := idjag.NewJWKSVerifier("https://issuer.example.com/.well-known/jwks.json", idjag.VerifierOptions{
		ExpectedIssuer: "https://issuer.example.com",
	})
	config := DefaultHandlerConfig("https://auth.example.com")
	storage := NewMemoryStorage()

	handler := NewIDJAGHandler(verifier, config, storage)

	if handler == nil {
		t.Fatal("NewIDJAGHandler() returned nil")
	}

	if handler.verifier != verifier {
		t.Error("verifier not set correctly")
	}

	if handler.config.Issuer != config.Issuer {
		t.Error("config not set correctly")
	}
}

func TestNewAAuthHandler(t *testing.T) {
	config := DefaultHandlerConfig("https://auth.example.com")
	storage := NewMemoryStorage()

	handler := NewAAuthHandler("https://issuer.example.com", "https://issuer.example.com/jwks", config, storage)

	if handler == nil {
		t.Fatal("NewAAuthHandler() returned nil")
	}

	if handler.issuer != "https://issuer.example.com" {
		t.Error("issuer not set correctly")
	}
}

func TestAAuthHandlerHandleUnsupportedGrant(t *testing.T) {
	config := DefaultHandlerConfig("https://auth.example.com")
	storage := NewMemoryStorage()
	handler := NewAAuthHandler("https://issuer.example.com", "https://issuer.example.com/jwks", config, storage)

	req := &TokenRequest{
		GrantType: "unsupported_grant",
	}

	_, err := handler.HandleTokenRequest(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for unsupported grant")
	}
}
