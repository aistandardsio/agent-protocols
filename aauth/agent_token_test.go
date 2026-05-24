package aauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewAgentToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	token := NewAgentToken("https://issuer.example.com", "aauth:agent@example.com", cnf, 5*time.Minute)

	if token.Issuer != "https://issuer.example.com" {
		t.Errorf("expected issuer https://issuer.example.com, got %s", token.Issuer)
	}
	if token.Subject != "aauth:agent@example.com" {
		t.Errorf("expected subject aauth:agent@example.com, got %s", token.Subject)
	}
	if token.CNF == nil {
		t.Error("expected CNF to be set")
	}
	if token.IsExpired() {
		t.Error("expected token to not be expired")
	}
}

func TestAgentToken_Builder(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	token := NewAgentToken("https://issuer.example.com", "aauth:agent@example.com", cnf, 5*time.Minute).
		WithAudience("https://resource.example.com").
		WithJWTID("unique-id").
		WithDWK("https://agent.example.com/.well-known/aauth-agent.json").
		WithPS("https://person.example.com").
		WithActor(&Actor{Subject: "user@example.com"}).
		WithClaim("custom", "value")

	if len(token.Audience) != 1 || token.Audience[0] != "https://resource.example.com" {
		t.Error("expected audience to be set")
	}
	if token.JWTID != "unique-id" {
		t.Error("expected JWTID to be set")
	}
	if token.DWK != "https://agent.example.com/.well-known/aauth-agent.json" {
		t.Error("expected DWK to be set")
	}
	if token.PS != "https://person.example.com" {
		t.Error("expected PS to be set")
	}
	if token.Actor == nil || token.Actor.Subject != "user@example.com" {
		t.Error("expected Actor to be set")
	}
	if token.Claims["custom"] != "value" {
		t.Error("expected custom claim to be set")
	}
}

func TestAgentToken_Validate(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	tests := []struct {
		name    string
		token   *AgentToken
		wantErr bool
	}{
		{
			name:    "valid",
			token:   NewAgentToken("https://issuer.example.com", "aauth:agent@example.com", cnf, 5*time.Minute),
			wantErr: false,
		},
		{
			name: "missing issuer",
			token: &AgentToken{
				Subject:   "aauth:agent@example.com",
				CNF:       cnf,
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			wantErr: true,
		},
		{
			name: "missing subject",
			token: &AgentToken{
				Issuer:    "https://issuer.example.com",
				CNF:       cnf,
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			wantErr: true,
		},
		{
			name: "missing CNF",
			token: &AgentToken{
				Issuer:    "https://issuer.example.com",
				Subject:   "aauth:agent@example.com",
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			wantErr: true,
		},
		{
			name: "expired",
			token: &AgentToken{
				Issuer:    "https://issuer.example.com",
				Subject:   "aauth:agent@example.com",
				CNF:       cnf,
				ExpiresAt: time.Now().Add(-5 * time.Minute),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.token.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAgentToken_Sign(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	token := NewAgentToken("https://issuer.example.com", "aauth:agent@example.com", cnf, 5*time.Minute)

	signed, err := token.Sign(jwt.SigningMethodES256, privateKey, "test-key")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if signed == "" {
		t.Error("expected non-empty signed token")
	}

	// Parse and verify the token has expected header
	parsedToken, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse signed token: %v", err)
	}

	if parsedToken.Header["typ"] != TokenTypeAgentJWT {
		t.Errorf("expected typ %s, got %v", TokenTypeAgentJWT, parsedToken.Header["typ"])
	}
	if parsedToken.Header["kid"] != "test-key" {
		t.Errorf("expected kid test-key, got %v", parsedToken.Header["kid"])
	}
}

func TestAgentToken_IsExpired(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	freshToken := NewAgentToken("https://issuer.example.com", "sub", cnf, time.Hour)
	if freshToken.IsExpired() {
		t.Error("expected fresh token to not be expired")
	}

	expiredToken := &AgentToken{
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	if !expiredToken.IsExpired() {
		t.Error("expected expired token to be expired")
	}
}

func TestAgentToken_TimeToExpiry(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	token := NewAgentToken("https://issuer.example.com", "sub", cnf, time.Hour)
	ttl := token.TimeToExpiry()

	// Should be close to 1 hour
	if ttl < 59*time.Minute || ttl > 61*time.Minute {
		t.Errorf("expected TTL around 1 hour, got %v", ttl)
	}

	expiredToken := &AgentToken{
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	if expiredToken.TimeToExpiry() != 0 {
		t.Error("expected expired token TTL to be 0")
	}
}

func TestParseAgentToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	original := NewAgentToken("https://issuer.example.com", "aauth:agent@example.com", cnf, 5*time.Minute).
		WithAudience("https://resource.example.com").
		WithJWTID("unique-id")

	signed, _ := original.Sign(jwt.SigningMethodES256, privateKey, "test-key")

	parsed, err := ParseAgentToken(signed)
	if err != nil {
		t.Fatalf("ParseAgentToken() error = %v", err)
	}

	if parsed.Issuer != original.Issuer {
		t.Errorf("Issuer mismatch: %s vs %s", parsed.Issuer, original.Issuer)
	}
	if parsed.Subject != original.Subject {
		t.Errorf("Subject mismatch: %s vs %s", parsed.Subject, original.Subject)
	}
	if parsed.JWTID != original.JWTID {
		t.Errorf("JWTID mismatch: %s vs %s", parsed.JWTID, original.JWTID)
	}
}

func TestParseAgentToken_Invalid(t *testing.T) {
	_, err := ParseAgentToken("not-a-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestAgentToken_WithMultipleAudiences(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	token := NewAgentToken("https://issuer.example.com", "aauth:agent@example.com", cnf, 5*time.Minute).
		WithAudience("https://resource1.example.com", "https://resource2.example.com")

	if len(token.Audience) != 2 {
		t.Errorf("expected 2 audiences, got %d", len(token.Audience))
	}

	signed, _ := token.Sign(jwt.SigningMethodES256, privateKey, "test-key")
	parsed, _ := ParseAgentToken(signed)

	if len(parsed.Audience) != 2 {
		t.Errorf("expected 2 audiences after parsing, got %d", len(parsed.Audience))
	}
}

func TestParseAgentToken_WrongTypHeader(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	original := NewAgentToken("https://issuer.example.com", "aauth:agent@example.com", cnf, 5*time.Minute)

	// Manually create a token with wrong typ header
	claims := jwt.MapClaims{
		"iss": original.Issuer,
		"sub": original.Subject,
		"iat": jwt.NewNumericDate(original.IssuedAt),
		"exp": jwt.NewNumericDate(original.ExpiresAt),
		"cnf": cnf,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = TokenTypeAuthJWT // Wrong type - using auth instead of agent
	token.Header["kid"] = "test-key"

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// ParseAgentToken should reject the token with wrong typ header
	_, err = ParseAgentToken(signed)
	if err == nil {
		t.Error("expected error for token with wrong typ header")
	}
}

func TestParseAgentToken_MissingTypHeader(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	original := NewAgentToken("https://issuer.example.com", "aauth:agent@example.com", cnf, 5*time.Minute)

	// Manually create a token without typ header (backward compatibility)
	claims := jwt.MapClaims{
		"iss": original.Issuer,
		"sub": original.Subject,
		"iat": jwt.NewNumericDate(original.IssuedAt),
		"exp": jwt.NewNumericDate(original.ExpiresAt),
		"cnf": cnf,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key"
	// Note: No typ header set

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// ParseAgentToken should accept tokens without typ header for backward compatibility
	parsed, err := ParseAgentToken(signed)
	if err != nil {
		t.Errorf("ParseAgentToken() error = %v, expected nil for missing typ header", err)
	}
	if parsed.Issuer != original.Issuer {
		t.Errorf("Issuer mismatch: %s vs %s", parsed.Issuer, original.Issuer)
	}
}
