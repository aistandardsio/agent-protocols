package idjag

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewAssertion(t *testing.T) {
	issuer := "https://issuer.example.com"
	subject := "agent:test"
	audience := []string{"https://auth.example.com"}
	ttl := 5 * time.Minute

	a := NewAssertion(issuer, subject, audience, ttl)

	if a.Issuer != issuer {
		t.Errorf("expected issuer %s, got %s", issuer, a.Issuer)
	}
	if a.Subject != subject {
		t.Errorf("expected subject %s, got %s", subject, a.Subject)
	}
	if len(a.Audience) != 1 || a.Audience[0] != audience[0] {
		t.Errorf("expected audience %v, got %v", audience, a.Audience)
	}
	if a.IssuedAt.IsZero() {
		t.Error("expected IssuedAt to be set")
	}
	if a.ExpiresAt.IsZero() {
		t.Error("expected ExpiresAt to be set")
	}
	if a.Actor != nil {
		t.Error("expected Actor to be nil for non-delegated assertion")
	}
}

func TestNewDelegatedAssertion(t *testing.T) {
	issuer := "https://issuer.example.com"
	subject := "user:alice"
	actorSubject := "agent:calendar-bot"
	audience := []string{"https://auth.example.com"}
	ttl := 5 * time.Minute

	a := NewDelegatedAssertion(issuer, subject, actorSubject, audience, ttl)

	if a.Subject != subject {
		t.Errorf("expected subject %s, got %s", subject, a.Subject)
	}
	if a.Actor == nil {
		t.Fatal("expected Actor to be set")
	}
	if a.Actor.Subject != actorSubject {
		t.Errorf("expected actor subject %s, got %s", actorSubject, a.Actor.Subject)
	}
}

func TestAssertion_IsDelegated(t *testing.T) {
	a1 := NewAssertion("iss", "sub", []string{"aud"}, time.Minute)
	if a1.IsDelegated() {
		t.Error("expected IsDelegated to return false for non-delegated assertion")
	}

	a2 := NewDelegatedAssertion("iss", "sub", "actor", []string{"aud"}, time.Minute)
	if !a2.IsDelegated() {
		t.Error("expected IsDelegated to return true for delegated assertion")
	}
}

func TestAssertion_IsExpired(t *testing.T) {
	// Non-expired assertion
	a1 := NewAssertion("iss", "sub", []string{"aud"}, time.Hour)
	if a1.IsExpired() {
		t.Error("expected IsExpired to return false for fresh assertion")
	}

	// Expired assertion
	a2 := &Assertion{
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	if !a2.IsExpired() {
		t.Error("expected IsExpired to return true for expired assertion")
	}
}

func TestAssertion_DelegationChain(t *testing.T) {
	// Non-delegated
	a1 := NewAssertion("iss", "sub", []string{"aud"}, time.Minute)
	chain1 := a1.DelegationChain()
	if chain1 != nil {
		t.Error("expected nil chain for non-delegated assertion")
	}

	// Single delegation
	a2 := NewDelegatedAssertion("iss", "sub", "actor1", []string{"aud"}, time.Minute)
	chain2 := a2.DelegationChain()
	if len(chain2) != 1 {
		t.Fatalf("expected chain length 1, got %d", len(chain2))
	}
	if chain2[0].Subject != "actor1" {
		t.Errorf("expected actor1, got %s", chain2[0].Subject)
	}

	// Nested delegation
	a3 := NewAssertion("iss", "sub", []string{"aud"}, time.Minute)
	a3.Actor = &Actor{
		Subject: "actor1",
		Actor: &Actor{
			Subject: "actor2",
			Actor: &Actor{
				Subject: "actor3",
			},
		},
	}
	chain3 := a3.DelegationChain()
	if len(chain3) != 3 {
		t.Fatalf("expected chain length 3, got %d", len(chain3))
	}
	if chain3[0].Subject != "actor1" {
		t.Errorf("expected actor1 at index 0, got %s", chain3[0].Subject)
	}
	if chain3[1].Subject != "actor2" {
		t.Errorf("expected actor2 at index 1, got %s", chain3[1].Subject)
	}
	if chain3[2].Subject != "actor3" {
		t.Errorf("expected actor3 at index 2, got %s", chain3[2].Subject)
	}
}

func TestAssertion_SignAndParse(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	a := NewDelegatedAssertion(
		"https://issuer.example.com",
		"user:alice",
		"agent:bot",
		[]string{"https://auth.example.com"},
		5*time.Minute,
	)
	a.JWTID = "test-jti"
	a.WithClaim("custom", "value")

	signed, err := a.Sign(jwt.SigningMethodRS256, privateKey, "key-1")
	if err != nil {
		t.Fatalf("failed to sign assertion: %v", err)
	}

	if signed == "" {
		t.Fatal("expected non-empty signed JWT")
	}

	// Parse it back
	parsed, err := ParseAssertion(signed)
	if err != nil {
		t.Fatalf("failed to parse assertion: %v", err)
	}

	if parsed.Issuer != a.Issuer {
		t.Errorf("issuer mismatch: expected %s, got %s", a.Issuer, parsed.Issuer)
	}
	if parsed.Subject != a.Subject {
		t.Errorf("subject mismatch: expected %s, got %s", a.Subject, parsed.Subject)
	}
	if len(parsed.Audience) != 1 || parsed.Audience[0] != a.Audience[0] {
		t.Errorf("audience mismatch: expected %v, got %v", a.Audience, parsed.Audience)
	}
	if parsed.JWTID != a.JWTID {
		t.Errorf("jti mismatch: expected %s, got %s", a.JWTID, parsed.JWTID)
	}
	if parsed.Actor == nil {
		t.Fatal("expected actor to be present")
	}
	if parsed.Actor.Subject != a.Actor.Subject {
		t.Errorf("actor subject mismatch: expected %s, got %s", a.Actor.Subject, parsed.Actor.Subject)
	}
	if parsed.Claims["custom"] != "value" {
		t.Errorf("custom claim mismatch: expected 'value', got %v", parsed.Claims["custom"])
	}
}

func TestAssertion_WithActor(t *testing.T) {
	a := NewAssertion("iss", "sub", []string{"aud"}, time.Minute)
	a.WithActor(&Actor{Subject: "actor"})

	if a.Actor == nil {
		t.Fatal("expected Actor to be set")
	}
	if a.Actor.Subject != "actor" {
		t.Errorf("expected actor subject 'actor', got %s", a.Actor.Subject)
	}
}

func TestAssertion_WithClaim(t *testing.T) {
	a := NewAssertion("iss", "sub", []string{"aud"}, time.Minute)
	a.WithClaim("key1", "value1")
	a.WithClaim("key2", 42)

	if a.Claims["key1"] != "value1" {
		t.Errorf("expected key1='value1', got %v", a.Claims["key1"])
	}
	if a.Claims["key2"] != 42 {
		t.Errorf("expected key2=42, got %v", a.Claims["key2"])
	}
}
