package bridge

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/aims"
	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

func TestFromIDJAG(t *testing.T) {
	assertion := &idjag.Assertion{
		Issuer:    "https://issuer.example.com",
		Subject:   "user@example.com",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-123",
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		JWTID:     "jti-123",
	}

	identity, err := FromIDJAG(assertion)
	if err != nil {
		t.Fatalf("FromIDJAG failed: %v", err)
	}

	if identity.Protocol != ProtocolIDJAG {
		t.Errorf("expected protocol %s, got %s", ProtocolIDJAG, identity.Protocol)
	}
	if identity.Issuer != assertion.Issuer {
		t.Errorf("expected issuer %s, got %s", assertion.Issuer, identity.Issuer)
	}
	if identity.Subject != assertion.Subject {
		t.Errorf("expected subject %s, got %s", assertion.Subject, identity.Subject)
	}
	if len(identity.Audience) != 1 || identity.Audience[0] != assertion.Audience[0] {
		t.Errorf("expected audience %v, got %v", assertion.Audience, identity.Audience)
	}
	if identity.OriginalClaims["client_id"] != assertion.ClientID {
		t.Errorf("expected client_id %s, got %v", assertion.ClientID, identity.OriginalClaims["client_id"])
	}
}

func TestFromIDJAGNil(t *testing.T) {
	_, err := FromIDJAG(nil)
	if err != ErrInvalidIdentity {
		t.Errorf("expected ErrInvalidIdentity, got %v", err)
	}
}

func TestFromWIT(t *testing.T) {
	wit := &aims.WorkloadIdentityToken{
		Issuer:   "https://issuer.example.com",
		Subject:  "spiffe://example.com/workload",
		Audience: []string{"https://api.example.com"},
		IssuedAt: time.Now().Add(-time.Minute),
		Expiry:   time.Now().Add(time.Hour),
		JWTID:    "jti-456",
		CNF: &aims.CNF{
			Kid: "key-123",
		},
	}

	identity, err := FromWIT(wit)
	if err != nil {
		t.Fatalf("FromWIT failed: %v", err)
	}

	if identity.Protocol != ProtocolAIMS {
		t.Errorf("expected protocol %s, got %s", ProtocolAIMS, identity.Protocol)
	}
	if identity.Subject != wit.Subject {
		t.Errorf("expected subject %s, got %s", wit.Subject, identity.Subject)
	}
	if !identity.HasKeyBinding() {
		t.Error("expected key binding")
	}
	if identity.KeyBinding.Kid != wit.CNF.Kid {
		t.Errorf("expected kid %s, got %s", wit.CNF.Kid, identity.KeyBinding.Kid)
	}
}

func TestFromWITNil(t *testing.T) {
	_, err := FromWIT(nil)
	if err != ErrInvalidIdentity {
		t.Errorf("expected ErrInvalidIdentity, got %v", err)
	}
}

func TestFromAAuth(t *testing.T) {
	token := &aauth.AgentToken{
		Issuer:    "https://issuer.example.com",
		Subject:   "aauth:agent:123",
		Audience:  []string{"https://api.example.com"},
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		JWTID:     "jti-789",
		DWK:       "delegated-worker-key",
		PS:        "https://person.example.com",
		CNF: &aauth.CNF{
			Kid: "cnf-key-456",
		},
		Actor: &aauth.Actor{
			Subject: "user@example.com",
			Issuer:  "https://idp.example.com",
		},
	}

	identity, err := FromAAuth(token)
	if err != nil {
		t.Fatalf("FromAAuth failed: %v", err)
	}

	if identity.Protocol != ProtocolAAuth {
		t.Errorf("expected protocol %s, got %s", ProtocolAAuth, identity.Protocol)
	}
	if identity.Subject != token.Subject {
		t.Errorf("expected subject %s, got %s", token.Subject, identity.Subject)
	}
	if !identity.HasKeyBinding() {
		t.Error("expected key binding")
	}
	if !identity.HasDelegation() {
		t.Error("expected delegation chain")
	}
	if identity.Actor.Subject != token.Actor.Subject {
		t.Errorf("expected actor subject %s, got %s", token.Actor.Subject, identity.Actor.Subject)
	}
	if identity.OriginalClaims["dwk"] != token.DWK {
		t.Errorf("expected dwk %s, got %v", token.DWK, identity.OriginalClaims["dwk"])
	}
	if identity.OriginalClaims["ps"] != token.PS {
		t.Errorf("expected ps %s, got %v", token.PS, identity.OriginalClaims["ps"])
	}
}

func TestFromAAuthNil(t *testing.T) {
	_, err := FromAAuth(nil)
	if err != ErrInvalidIdentity {
		t.Errorf("expected ErrInvalidIdentity, got %v", err)
	}
}

func TestToIDJAG(t *testing.T) {
	identity := &Identity{
		Protocol:  ProtocolAIMS,
		Issuer:    "https://issuer.example.com",
		Subject:   "user@example.com",
		Audience:  []string{"https://api.example.com"},
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		JWTID:     "jti-123",
	}

	assertion, err := identity.ToIDJAG("client-456")
	if err != nil {
		t.Fatalf("ToIDJAG failed: %v", err)
	}

	if assertion.ClientID != "client-456" {
		t.Errorf("expected client_id client-456, got %s", assertion.ClientID)
	}
	if assertion.Issuer != identity.Issuer {
		t.Errorf("expected issuer %s, got %s", identity.Issuer, assertion.Issuer)
	}
	if assertion.Subject != identity.Subject {
		t.Errorf("expected subject %s, got %s", identity.Subject, assertion.Subject)
	}
}

func TestToIDJAGMissingClientID(t *testing.T) {
	identity := &Identity{
		Subject: "user@example.com",
	}

	_, err := identity.ToIDJAG("")
	if err != ErrMissingRequiredField {
		t.Errorf("expected ErrMissingRequiredField, got %v", err)
	}
}

func TestToWIT(t *testing.T) {
	identity := &Identity{
		Protocol:  ProtocolIDJAG,
		Issuer:    "https://issuer.example.com",
		Subject:   "spiffe://example.com/workload",
		Audience:  []string{"https://api.example.com"},
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		JWTID:     "jti-123",
		KeyBinding: &KeyBinding{
			Kid: "key-789",
		},
	}

	wit, err := identity.ToWIT()
	if err != nil {
		t.Fatalf("ToWIT failed: %v", err)
	}

	if wit.Issuer != identity.Issuer {
		t.Errorf("expected issuer %s, got %s", identity.Issuer, wit.Issuer)
	}
	if wit.Subject != identity.Subject {
		t.Errorf("expected subject %s, got %s", identity.Subject, wit.Subject)
	}
	if wit.CNF == nil || wit.CNF.Kid != identity.KeyBinding.Kid {
		t.Errorf("expected CNF kid %s", identity.KeyBinding.Kid)
	}
}

func TestToAAuth(t *testing.T) {
	identity := &Identity{
		Protocol:  ProtocolIDJAG,
		Issuer:    "https://issuer.example.com",
		Subject:   "user@example.com",
		Audience:  []string{"https://api.example.com"},
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		JWTID:     "jti-123",
		Actor: &Actor{
			Subject: "agent@example.com",
		},
		OriginalClaims: map[string]any{
			"dwk": "delegated-key",
			"ps":  "https://person.example.com",
		},
	}

	cnf := &aauth.CNF{Kid: "cnf-key"}
	token, err := identity.ToAAuth(cnf)
	if err != nil {
		t.Fatalf("ToAAuth failed: %v", err)
	}

	if token.Subject != identity.Subject {
		t.Errorf("expected subject %s, got %s", identity.Subject, token.Subject)
	}
	if token.CNF.Kid != cnf.Kid {
		t.Errorf("expected CNF kid %s, got %s", cnf.Kid, token.CNF.Kid)
	}
	if token.Actor == nil || token.Actor.Subject != identity.Actor.Subject {
		t.Error("expected actor chain")
	}
	if token.DWK != identity.OriginalClaims["dwk"] {
		t.Errorf("expected dwk %s, got %s", identity.OriginalClaims["dwk"], token.DWK)
	}
}

func TestToAAuthMissingCNF(t *testing.T) {
	identity := &Identity{
		Subject: "user@example.com",
	}

	_, err := identity.ToAAuth(nil)
	if err != ErrMissingRequiredField {
		t.Errorf("expected ErrMissingRequiredField, got %v", err)
	}
}

func TestIsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{"not expired", time.Now().Add(time.Hour), false},
		{"expired", time.Now().Add(-time.Hour), true},
		{"zero time", time.Time{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{ExpiresAt: tt.expiresAt}
			if identity.IsExpired() != tt.expected {
				t.Errorf("expected IsExpired() = %v", tt.expected)
			}
		})
	}
}

func TestHasKeyBinding(t *testing.T) {
	tests := []struct {
		name       string
		keyBinding *KeyBinding
		expected   bool
	}{
		{"nil", nil, false},
		{"empty", &KeyBinding{}, false},
		{"with kid", &KeyBinding{Kid: "key-123"}, true},
		{"with jwk", &KeyBinding{JWK: []byte(`{"kty":"EC"}`)}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{KeyBinding: tt.keyBinding}
			if identity.HasKeyBinding() != tt.expected {
				t.Errorf("expected HasKeyBinding() = %v", tt.expected)
			}
		})
	}
}

func TestHasDelegation(t *testing.T) {
	tests := []struct {
		name     string
		actor    *Actor
		expected bool
	}{
		{"nil", nil, false},
		{"present", &Actor{Subject: "agent@example.com"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{Actor: tt.actor}
			if identity.HasDelegation() != tt.expected {
				t.Errorf("expected HasDelegation() = %v", tt.expected)
			}
		})
	}
}

func TestSigningMethodForSigner(t *testing.T) {
	// Generate test keys
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	ecKey256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC P-256 key: %v", err)
	}

	ecKey384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC P-384 key: %v", err)
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	t.Run("RSA", func(t *testing.T) {
		method := signingMethodForSigner(rsaKey)
		if method != jwt.SigningMethodRS256 {
			t.Errorf("expected RS256, got %s", method.Alg())
		}
	})

	t.Run("EC P-256", func(t *testing.T) {
		method := signingMethodForSigner(ecKey256)
		if method != jwt.SigningMethodES256 {
			t.Errorf("expected ES256, got %s", method.Alg())
		}
	})

	t.Run("EC P-384", func(t *testing.T) {
		method := signingMethodForSigner(ecKey384)
		if method != jwt.SigningMethodES384 {
			t.Errorf("expected ES384, got %s", method.Alg())
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		method := signingMethodForSigner(edKey)
		if method != jwt.SigningMethodEdDSA {
			t.Errorf("expected EdDSA, got %s", method.Alg())
		}
	})
}

func TestRoundTrip(t *testing.T) {
	// Create an identity from ID-JAG
	idjagAssertion := &idjag.Assertion{
		Issuer:    "https://issuer.example.com",
		Subject:   "user@example.com",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-123",
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		JWTID:     "jti-123",
		Actor: &idjag.Actor{
			Subject: "agent@example.com",
			Issuer:  "https://agent-issuer.example.com",
		},
	}

	// Convert to canonical identity
	identity, err := FromIDJAG(idjagAssertion)
	if err != nil {
		t.Fatalf("FromIDJAG failed: %v", err)
	}

	// Convert to AAuth
	cnf := &aauth.CNF{Kid: "agent-key"}
	aauthToken, err := identity.ToAAuth(cnf)
	if err != nil {
		t.Fatalf("ToAAuth failed: %v", err)
	}

	// Verify the conversion preserved key fields
	if aauthToken.Subject != idjagAssertion.Subject {
		t.Errorf("subject mismatch: %s != %s", aauthToken.Subject, idjagAssertion.Subject)
	}
	if aauthToken.Issuer != idjagAssertion.Issuer {
		t.Errorf("issuer mismatch: %s != %s", aauthToken.Issuer, idjagAssertion.Issuer)
	}
	if aauthToken.Actor == nil {
		t.Fatal("actor chain lost in conversion")
	}
	if aauthToken.Actor.Subject != idjagAssertion.Actor.Subject {
		t.Errorf("actor subject mismatch: %s != %s", aauthToken.Actor.Subject, idjagAssertion.Actor.Subject)
	}
}
