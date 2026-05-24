package aauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewAuthToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	token := NewAuthToken(
		"https://ps.example.com",
		"aauth:agent@example.com",
		[]string{"https://resource.example.com"},
		cnf,
		5*time.Minute,
	)

	if token.Issuer != "https://ps.example.com" {
		t.Errorf("expected issuer https://ps.example.com, got %s", token.Issuer)
	}
	if token.Subject != "aauth:agent@example.com" {
		t.Errorf("expected subject aauth:agent@example.com, got %s", token.Subject)
	}
	if len(token.Audience) != 1 || token.Audience[0] != "https://resource.example.com" {
		t.Error("expected audience to be set")
	}
	if token.CNF == nil {
		t.Error("expected CNF to be set")
	}
}

func TestAuthToken_Builder(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	token := NewAuthToken(
		"https://ps.example.com",
		"aauth:agent@example.com",
		[]string{"https://resource.example.com"},
		cnf,
		5*time.Minute,
	).
		WithScope("read write").
		WithJWTID("unique-id").
		WithActor(&Actor{Subject: "user@example.com"}).
		WithMayAct(&Actor{Subject: "delegate@example.com"}).
		WithClaim("custom", "value")

	if token.Scope != "read write" {
		t.Error("expected Scope to be set")
	}
	if token.JWTID != "unique-id" {
		t.Error("expected JWTID to be set")
	}
	if token.Actor == nil || token.Actor.Subject != "user@example.com" {
		t.Error("expected Actor to be set")
	}
	if token.MayAct == nil || token.MayAct.Subject != "delegate@example.com" {
		t.Error("expected MayAct to be set")
	}
	if token.Claims["custom"] != "value" {
		t.Error("expected custom claim to be set")
	}
}

func TestAuthToken_Validate(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	tests := []struct {
		name    string
		token   *AuthToken
		wantErr bool
	}{
		{
			name: "valid",
			token: NewAuthToken(
				"https://ps.example.com",
				"aauth:agent@example.com",
				[]string{"https://resource.example.com"},
				cnf,
				5*time.Minute,
			),
			wantErr: false,
		},
		{
			name: "missing issuer",
			token: &AuthToken{
				Subject:   "aauth:agent@example.com",
				Audience:  []string{"https://resource.example.com"},
				CNF:       cnf,
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			wantErr: true,
		},
		{
			name: "missing audience",
			token: &AuthToken{
				Issuer:    "https://ps.example.com",
				Subject:   "aauth:agent@example.com",
				CNF:       cnf,
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			wantErr: true,
		},
		{
			name: "missing CNF",
			token: &AuthToken{
				Issuer:    "https://ps.example.com",
				Subject:   "aauth:agent@example.com",
				Audience:  []string{"https://resource.example.com"},
				ExpiresAt: time.Now().Add(5 * time.Minute),
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

func TestAuthToken_Sign(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	token := NewAuthToken(
		"https://ps.example.com",
		"aauth:agent@example.com",
		[]string{"https://resource.example.com"},
		cnf,
		5*time.Minute,
	)

	signed, err := token.Sign(jwt.SigningMethodES256, privateKey, "test-key")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Parse and verify the token has expected header
	parsedToken, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse signed token: %v", err)
	}

	if parsedToken.Header["typ"] != TokenTypeAuthJWT {
		t.Errorf("expected typ %s, got %v", TokenTypeAuthJWT, parsedToken.Header["typ"])
	}
}

func TestAuthToken_HasAudience(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	token := NewAuthToken(
		"https://ps.example.com",
		"aauth:agent@example.com",
		[]string{"https://resource1.example.com", "https://resource2.example.com"},
		cnf,
		5*time.Minute,
	)

	if !token.HasAudience("https://resource1.example.com") {
		t.Error("expected HasAudience to return true for resource1")
	}
	if !token.HasAudience("https://resource2.example.com") {
		t.Error("expected HasAudience to return true for resource2")
	}
	if token.HasAudience("https://other.example.com") {
		t.Error("expected HasAudience to return false for other")
	}
}

func TestParseAuthToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	original := NewAuthToken(
		"https://ps.example.com",
		"aauth:agent@example.com",
		[]string{"https://resource.example.com"},
		cnf,
		5*time.Minute,
	).
		WithScope("read write").
		WithJWTID("unique-id")

	signed, _ := original.Sign(jwt.SigningMethodES256, privateKey, "test-key")

	parsed, err := ParseAuthToken(signed)
	if err != nil {
		t.Fatalf("ParseAuthToken() error = %v", err)
	}

	if parsed.Issuer != original.Issuer {
		t.Errorf("Issuer mismatch: %s vs %s", parsed.Issuer, original.Issuer)
	}
	if parsed.Subject != original.Subject {
		t.Errorf("Subject mismatch: %s vs %s", parsed.Subject, original.Subject)
	}
	if parsed.Scope != original.Scope {
		t.Errorf("Scope mismatch: %s vs %s", parsed.Scope, original.Scope)
	}
}

func TestParseAuthToken_WrongTypHeader(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	original := NewAuthToken(
		"https://ps.example.com",
		"aauth:agent@example.com",
		[]string{"https://resource.example.com"},
		cnf,
		5*time.Minute,
	)

	// Manually create a token with wrong typ header
	claims := jwt.MapClaims{
		"iss": original.Issuer,
		"sub": original.Subject,
		"aud": original.Audience,
		"iat": jwt.NewNumericDate(original.IssuedAt),
		"exp": jwt.NewNumericDate(original.ExpiresAt),
		"cnf": cnf,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = TokenTypeAgentJWT // Wrong type - using agent instead of auth
	token.Header["kid"] = "test-key"

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// ParseAuthToken should reject the token with wrong typ header
	_, err = ParseAuthToken(signed)
	if err == nil {
		t.Error("expected error for token with wrong typ header")
	}
}

func TestParseAuthToken_MissingTypHeader(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")

	original := NewAuthToken(
		"https://ps.example.com",
		"aauth:agent@example.com",
		[]string{"https://resource.example.com"},
		cnf,
		5*time.Minute,
	)

	// Manually create a token without typ header (backward compatibility)
	claims := jwt.MapClaims{
		"iss": original.Issuer,
		"sub": original.Subject,
		"aud": original.Audience,
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

	// ParseAuthToken should accept tokens without typ header for backward compatibility
	parsed, err := ParseAuthToken(signed)
	if err != nil {
		t.Errorf("ParseAuthToken() error = %v, expected nil for missing typ header", err)
	}
	if parsed.Issuer != original.Issuer {
		t.Errorf("Issuer mismatch: %s vs %s", parsed.Issuer, original.Issuer)
	}
}
