package authzserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

func TestMultiIssuerVerifier_AddRemoveIssuer(t *testing.T) {
	issuers := map[string]string{
		"https://idp1.example.com": "https://idp1.example.com/.well-known/jwks.json",
	}
	verifier := NewMultiIssuerVerifier(issuers, idjag.VerifierOptions{})

	// Check initial issuers
	initialIssuers := verifier.Issuers()
	if len(initialIssuers) != 1 {
		t.Errorf("Expected 1 issuer, got %d", len(initialIssuers))
	}

	// Add issuer
	verifier.AddIssuer("https://idp2.example.com", "https://idp2.example.com/jwks")
	afterAdd := verifier.Issuers()
	if len(afterAdd) != 2 {
		t.Errorf("Expected 2 issuers after add, got %d", len(afterAdd))
	}

	// Remove issuer
	verifier.RemoveIssuer("https://idp1.example.com")
	afterRemove := verifier.Issuers()
	if len(afterRemove) != 1 {
		t.Errorf("Expected 1 issuer after remove, got %d", len(afterRemove))
	}
}

func TestMultiIssuerVerifier_UntrustedIssuer(t *testing.T) {
	issuers := map[string]string{
		"https://trusted.example.com": "https://trusted.example.com/jwks",
	}
	verifier := NewMultiIssuerVerifier(issuers, idjag.VerifierOptions{})

	// Create a token from an untrusted issuer
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://untrusted.example.com",
		"sub": "user-1",
		"aud": "https://api.example.com",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, _ := token.SignedString(key)

	_, err := verifier.Verify(context.Background(), signedToken)
	if err == nil {
		t.Error("Expected error for untrusted issuer")
	}
}

func TestVerifierChain_Empty(t *testing.T) {
	chain := NewVerifierChain()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "user-1",
		"aud": "https://api.example.com",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, _ := token.SignedString(key)

	_, err := chain.Verify(context.Background(), signedToken)
	if err == nil {
		t.Error("Expected error from empty chain")
	}
}

func TestVerifierChain_Add(t *testing.T) {
	chain := NewVerifierChain()

	// Create a mock verifier that always fails
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	staticVerifier := idjag.NewStaticKeyVerifier(key.Public(), "key-1", idjag.VerifierOptions{
		ExpectedIssuer:   "https://issuer.example.com",
		ExpectedAudience: "https://api.example.com",
	})

	chain.Add(staticVerifier)

	// The chain should now have 1 verifier
	if len(chain.verifiers) != 1 {
		t.Errorf("Expected 1 verifier in chain, got %d", len(chain.verifiers))
	}
}

func TestVerifierChain_Success(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create a chain with a static verifier
	staticVerifier := idjag.NewStaticKeyVerifier(key.Public(), "key-1", idjag.VerifierOptions{
		ExpectedIssuer:   "https://issuer.example.com",
		ExpectedAudience: "https://api.example.com",
	})
	chain := NewVerifierChain(staticVerifier)

	// Create a valid token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "user-1",
		"aud": "https://api.example.com",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "key-1"
	signedToken, _ := token.SignedString(key)

	assertion, err := chain.Verify(context.Background(), signedToken)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if assertion.Subject != "user-1" {
		t.Errorf("Expected subject user-1, got %s", assertion.Subject)
	}
}

func TestVerifierChain_FirstSuccessWins(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create a chain with two verifiers - second one has the right key
	verifier1 := idjag.NewStaticKeyVerifier(key1.Public(), "key-wrong", idjag.VerifierOptions{
		ExpectedIssuer:   "https://issuer.example.com",
		ExpectedAudience: "https://api.example.com",
	})
	verifier2 := idjag.NewStaticKeyVerifier(key2.Public(), "key-2", idjag.VerifierOptions{
		ExpectedIssuer:   "https://issuer.example.com",
		ExpectedAudience: "https://api.example.com",
	})
	chain := NewVerifierChain(verifier1, verifier2)

	// Create a token signed with key2
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "user-1",
		"aud": "https://api.example.com",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "key-2"
	signedToken, _ := token.SignedString(key2)

	// Should succeed because verifier2 will verify it
	assertion, err := chain.Verify(context.Background(), signedToken)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if assertion.Subject != "user-1" {
		t.Errorf("Expected subject user-1, got %s", assertion.Subject)
	}
}
