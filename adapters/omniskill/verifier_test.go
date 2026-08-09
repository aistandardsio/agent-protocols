package omniskill

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aistandardsio/agent-protocols/idjag"
)

const (
	testIssuer   = "https://idp.example"
	testAudience = "https://mcp.example/mcp"
	testKeyID    = "test-key-1"
)

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return key
}

func signDelegatedToken(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	assertion := idjag.NewDelegatedAssertion(testIssuer, "user:alice", "agent:worker", []string{testAudience}, 5*time.Minute)
	assertion.ClientID = "agent-client"
	assertion.Claims = map[string]any{"scope": "docs:read sheets:read"}
	token, err := assertion.Sign(jwt.SigningMethodRS256, key, testKeyID)
	if err != nil {
		t.Fatalf("signing assertion: %v", err)
	}
	return token
}

func TestVerifier_StaticKey(t *testing.T) {
	key := newTestKey(t)
	token := signDelegatedToken(t, key)

	verifier := NewVerifier(testIssuer, testAudience,
		WithIDJAGVerifier(idjag.NewStaticKeyVerifier(&key.PublicKey, testKeyID, idjag.VerifierOptions{
			ExpectedIssuer:   testIssuer,
			ExpectedAudience: testAudience,
		})),
	)

	info, err := verifier.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}

	if info.Subject != "user:alice" {
		t.Errorf("expected subject user:alice, got %q", info.Subject)
	}
	if len(info.Actor) != 1 || info.Actor[0] != "agent:worker" {
		t.Errorf("unexpected actor chain: %v", info.Actor)
	}
	if info.ClientID != "agent-client" {
		t.Errorf("expected client agent-client, got %q", info.ClientID)
	}
	if info.Scope != "docs:read sheets:read" {
		t.Errorf("unexpected scope: %q", info.Scope)
	}
	if info.Claims["iss"] != testIssuer {
		t.Errorf("expected iss claim %q, got %v", testIssuer, info.Claims["iss"])
	}
	if info.TokenType != "Bearer" {
		t.Errorf("expected Bearer token type, got %q", info.TokenType)
	}
}

func TestVerifier_RejectsInvalid(t *testing.T) {
	key := newTestKey(t)
	otherKey := newTestKey(t)

	staticVerifier := func(pub *rsa.PublicKey) Option {
		return WithIDJAGVerifier(idjag.NewStaticKeyVerifier(pub, testKeyID, idjag.VerifierOptions{
			ExpectedIssuer:   testIssuer,
			ExpectedAudience: testAudience,
		}))
	}

	t.Run("wrong_signature", func(t *testing.T) {
		token := signDelegatedToken(t, key)
		verifier := NewVerifier(testIssuer, testAudience, staticVerifier(&otherKey.PublicKey))
		if _, err := verifier.VerifyToken(context.Background(), token); err == nil {
			t.Fatal("expected error for wrong signing key")
		}
	})

	t.Run("wrong_audience", func(t *testing.T) {
		assertion := idjag.NewAssertion(testIssuer, "user:alice", []string{"https://other.example"}, 5*time.Minute)
		token, err := assertion.Sign(jwt.SigningMethodRS256, key, testKeyID)
		if err != nil {
			t.Fatal(err)
		}
		verifier := NewVerifier(testIssuer, testAudience, staticVerifier(&key.PublicKey))
		if _, err := verifier.VerifyToken(context.Background(), token); err == nil {
			t.Fatal("expected error for wrong audience")
		}
	})

	t.Run("expired", func(t *testing.T) {
		assertion := idjag.NewAssertion(testIssuer, "user:alice", []string{testAudience}, -time.Minute)
		token, err := assertion.Sign(jwt.SigningMethodRS256, key, testKeyID)
		if err != nil {
			t.Fatal(err)
		}
		verifier := NewVerifier(testIssuer, testAudience, staticVerifier(&key.PublicKey))
		if _, err := verifier.VerifyToken(context.Background(), token); err == nil {
			t.Fatal("expected error for expired token")
		}
	})
}

func TestVerifier_JWKSDiscovery(t *testing.T) {
	key := newTestKey(t)

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	jwks := idjag.JWKS{Keys: []idjag.JWK{idjag.NewJWKFromRSAPublicKey(&key.PublicKey, testKeyID, "RS256")}}
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Errorf("encoding jwks: %v", err)
		}
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"jwks_uri": server.URL + "/jwks"}); err != nil {
			t.Errorf("encoding discovery: %v", err)
		}
	})

	// The issuer claim must match the discovery host for this test.
	assertion := idjag.NewDelegatedAssertion(server.URL, "user:bob", "agent:calendar-bot", []string{testAudience}, 5*time.Minute)
	token, err := assertion.Sign(jwt.SigningMethodRS256, key, testKeyID)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewVerifier(server.URL, testAudience)
	info, err := verifier.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken with JWKS discovery: %v", err)
	}
	if info.Subject != "user:bob" {
		t.Errorf("expected subject user:bob, got %q", info.Subject)
	}
	if len(info.Actor) != 1 || info.Actor[0] != "agent:calendar-bot" {
		t.Errorf("unexpected actor chain: %v", info.Actor)
	}
}
