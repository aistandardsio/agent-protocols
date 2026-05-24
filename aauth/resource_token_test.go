package aauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewResourceToken(t *testing.T) {
	token := NewResourceToken(
		"https://resource.example.com",
		"aauth:agent@example.com",
		[]string{"https://ps.example.com"},
		"jkt-thumbprint",
		0, // Use default TTL
	)

	if token.Issuer != "https://resource.example.com" {
		t.Errorf("expected issuer https://resource.example.com, got %s", token.Issuer)
	}
	if token.Subject != "aauth:agent@example.com" {
		t.Errorf("expected subject aauth:agent@example.com, got %s", token.Subject)
	}
	if token.AgentJKT != "jkt-thumbprint" {
		t.Errorf("expected AgentJKT jkt-thumbprint, got %s", token.AgentJKT)
	}

	// Check default TTL is around 5 minutes
	ttl := token.TimeToExpiry()
	if ttl < 4*time.Minute || ttl > 6*time.Minute {
		t.Errorf("expected TTL around 5 minutes, got %v", ttl)
	}
}

func TestResourceToken_Builder(t *testing.T) {
	token := NewResourceToken(
		"https://resource.example.com",
		"aauth:agent@example.com",
		[]string{"https://ps.example.com"},
		"jkt-thumbprint",
		5*time.Minute,
	).
		WithScope("calendar.read").
		WithJWTID("unique-id").
		WithAgent("aauth:agent@example.com").
		WithDWK("https://agent.example.com/.well-known/aauth-agent.json").
		WithMission(map[string]any{"task": "schedule-meeting"}).
		WithClaim("custom", "value")

	if token.Scope != "calendar.read" {
		t.Error("expected Scope to be set")
	}
	if token.JWTID != "unique-id" {
		t.Error("expected JWTID to be set")
	}
	if token.Agent != "aauth:agent@example.com" {
		t.Error("expected Agent to be set")
	}
	if token.DWK != "https://agent.example.com/.well-known/aauth-agent.json" {
		t.Error("expected DWK to be set")
	}
	if token.Mission["task"] != "schedule-meeting" {
		t.Error("expected Mission to be set")
	}
	if token.Claims["custom"] != "value" {
		t.Error("expected custom claim to be set")
	}
}

func TestResourceToken_Validate(t *testing.T) {
	tests := []struct {
		name    string
		token   *ResourceToken
		wantErr bool
	}{
		{
			name: "valid",
			token: NewResourceToken(
				"https://resource.example.com",
				"aauth:agent@example.com",
				[]string{"https://ps.example.com"},
				"jkt-thumbprint",
				5*time.Minute,
			),
			wantErr: false,
		},
		{
			name: "missing issuer",
			token: &ResourceToken{
				Subject:   "aauth:agent@example.com",
				Audience:  []string{"https://ps.example.com"},
				AgentJKT:  "jkt-thumbprint",
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			wantErr: true,
		},
		{
			name: "missing audience",
			token: &ResourceToken{
				Issuer:    "https://resource.example.com",
				Subject:   "aauth:agent@example.com",
				AgentJKT:  "jkt-thumbprint",
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			wantErr: true,
		},
		{
			name: "missing agent_jkt",
			token: &ResourceToken{
				Issuer:    "https://resource.example.com",
				Subject:   "aauth:agent@example.com",
				Audience:  []string{"https://ps.example.com"},
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

func TestResourceToken_Sign(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	token := NewResourceToken(
		"https://resource.example.com",
		"aauth:agent@example.com",
		[]string{"https://ps.example.com"},
		"jkt-thumbprint",
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

	if parsedToken.Header["typ"] != TokenTypeResourceJWT {
		t.Errorf("expected typ %s, got %v", TokenTypeResourceJWT, parsedToken.Header["typ"])
	}
}

func TestParseResourceToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	original := NewResourceToken(
		"https://resource.example.com",
		"aauth:agent@example.com",
		[]string{"https://ps.example.com"},
		"jkt-thumbprint",
		5*time.Minute,
	).
		WithScope("calendar.read").
		WithJWTID("unique-id")

	signed, _ := original.Sign(jwt.SigningMethodES256, privateKey, "test-key")

	parsed, err := ParseResourceToken(signed)
	if err != nil {
		t.Fatalf("ParseResourceToken() error = %v", err)
	}

	if parsed.Issuer != original.Issuer {
		t.Errorf("Issuer mismatch: %s vs %s", parsed.Issuer, original.Issuer)
	}
	if parsed.Subject != original.Subject {
		t.Errorf("Subject mismatch: %s vs %s", parsed.Subject, original.Subject)
	}
	if parsed.AgentJKT != original.AgentJKT {
		t.Errorf("AgentJKT mismatch: %s vs %s", parsed.AgentJKT, original.AgentJKT)
	}
	if parsed.Scope != original.Scope {
		t.Errorf("Scope mismatch: %s vs %s", parsed.Scope, original.Scope)
	}
}

func TestResourceToken_ShortTTL(t *testing.T) {
	// Resource tokens should typically have short TTLs
	token := NewResourceToken(
		"https://resource.example.com",
		"aauth:agent@example.com",
		[]string{"https://ps.example.com"},
		"jkt-thumbprint",
		2*time.Minute,
	)

	ttl := token.TimeToExpiry()
	if ttl < 1*time.Minute || ttl > 3*time.Minute {
		t.Errorf("expected TTL around 2 minutes, got %v", ttl)
	}
}

func TestParseResourceToken_WrongTypHeader(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	original := NewResourceToken(
		"https://resource.example.com",
		"aauth:agent@example.com",
		[]string{"https://ps.example.com"},
		"jkt-thumbprint",
		5*time.Minute,
	)

	// Manually create a token with wrong typ header
	claims := jwt.MapClaims{
		"iss":       original.Issuer,
		"sub":       original.Subject,
		"aud":       original.Audience,
		"iat":       jwt.NewNumericDate(original.IssuedAt),
		"exp":       jwt.NewNumericDate(original.ExpiresAt),
		"agent_jkt": original.AgentJKT,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = TokenTypeAgentJWT // Wrong type - using agent instead of resource
	token.Header["kid"] = "test-key"

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// ParseResourceToken should reject the token with wrong typ header
	_, err = ParseResourceToken(signed)
	if err == nil {
		t.Error("expected error for token with wrong typ header")
	}
}

func TestParseResourceToken_MissingTypHeader(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	original := NewResourceToken(
		"https://resource.example.com",
		"aauth:agent@example.com",
		[]string{"https://ps.example.com"},
		"jkt-thumbprint",
		5*time.Minute,
	)

	// Manually create a token without typ header (backward compatibility)
	claims := jwt.MapClaims{
		"iss":       original.Issuer,
		"sub":       original.Subject,
		"aud":       original.Audience,
		"iat":       jwt.NewNumericDate(original.IssuedAt),
		"exp":       jwt.NewNumericDate(original.ExpiresAt),
		"agent_jkt": original.AgentJKT,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key"
	// Note: No typ header set

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// ParseResourceToken should accept tokens without typ header for backward compatibility
	parsed, err := ParseResourceToken(signed)
	if err != nil {
		t.Errorf("ParseResourceToken() error = %v, expected nil for missing typ header", err)
	}
	if parsed.Issuer != original.Issuer {
		t.Errorf("Issuer mismatch: %s vs %s", parsed.Issuer, original.Issuer)
	}
}
