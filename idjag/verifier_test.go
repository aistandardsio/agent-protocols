package idjag

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestStaticKeyVerifier_Verify(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	issuer := "https://issuer.example.com"
	audience := "https://auth.example.com"
	keyID := "test-key"

	verifier := NewStaticKeyVerifier(publicKey, keyID, VerifierOptions{
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
	})

	t.Run("valid assertion", func(t *testing.T) {
		a := NewAssertion(issuer, "agent:test", []string{audience}, 5*time.Minute)
		signed, err := a.Sign(jwt.SigningMethodRS256, privateKey, keyID)
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}

		parsed, err := verifier.Verify(context.Background(), signed)
		if err != nil {
			t.Fatalf("verification failed: %v", err)
		}

		if parsed.Subject != a.Subject {
			t.Errorf("subject mismatch: expected %s, got %s", a.Subject, parsed.Subject)
		}
	})

	t.Run("expired assertion", func(t *testing.T) {
		a := &Assertion{
			Issuer:    issuer,
			Subject:   "agent:test",
			Audience:  []string{audience},
			IssuedAt:  time.Now().Add(-time.Hour),
			ExpiresAt: time.Now().Add(-30 * time.Minute),
		}
		signed, err := a.Sign(jwt.SigningMethodRS256, privateKey, keyID)
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}

		_, err = verifier.Verify(context.Background(), signed)
		if err == nil {
			t.Error("expected error for expired assertion")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		a := NewAssertion("wrong-issuer", "agent:test", []string{audience}, 5*time.Minute)
		signed, err := a.Sign(jwt.SigningMethodRS256, privateKey, keyID)
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}

		_, err = verifier.Verify(context.Background(), signed)
		if err == nil {
			t.Error("expected error for wrong issuer")
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		a := NewAssertion(issuer, "agent:test", []string{"wrong-audience"}, 5*time.Minute)
		signed, err := a.Sign(jwt.SigningMethodRS256, privateKey, keyID)
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}

		_, err = verifier.Verify(context.Background(), signed)
		if err == nil {
			t.Error("expected error for wrong audience")
		}
	})

	t.Run("require actor", func(t *testing.T) {
		v := NewStaticKeyVerifier(publicKey, keyID, VerifierOptions{
			ExpectedIssuer:   issuer,
			ExpectedAudience: audience,
			RequireActor:     true,
		})

		// Without actor
		a1 := NewAssertion(issuer, "agent:test", []string{audience}, 5*time.Minute)
		signed1, _ := a1.Sign(jwt.SigningMethodRS256, privateKey, keyID)
		_, err := v.Verify(context.Background(), signed1)
		if err == nil {
			t.Error("expected error when actor required but missing")
		}

		// With actor
		a2 := NewDelegatedAssertion(issuer, "user:alice", "agent:bot", []string{audience}, 5*time.Minute)
		signed2, _ := a2.Sign(jwt.SigningMethodRS256, privateKey, keyID)
		_, err = v.Verify(context.Background(), signed2)
		if err != nil {
			t.Errorf("unexpected error with actor present: %v", err)
		}
	})

	t.Run("wrong key ID", func(t *testing.T) {
		v := NewStaticKeyVerifier(publicKey, "expected-key", VerifierOptions{})

		a := NewAssertion(issuer, "agent:test", []string{audience}, 5*time.Minute)
		signed, _ := a.Sign(jwt.SigningMethodRS256, privateKey, "wrong-key")

		_, err := v.Verify(context.Background(), signed)
		if err == nil {
			t.Error("expected error for wrong key ID")
		}
	})

	t.Run("clock skew tolerance", func(t *testing.T) {
		v := NewStaticKeyVerifier(publicKey, keyID, VerifierOptions{
			ExpectedIssuer:   issuer,
			ExpectedAudience: audience,
			ClockSkew:        5 * time.Minute,
		})

		// Slightly expired (within tolerance)
		a := &Assertion{
			Issuer:    issuer,
			Subject:   "agent:test",
			Audience:  []string{audience},
			IssuedAt:  time.Now().Add(-10 * time.Minute),
			ExpiresAt: time.Now().Add(-1 * time.Minute), // Expired 1 min ago
		}
		signed, _ := a.Sign(jwt.SigningMethodRS256, privateKey, keyID)

		_, err := v.Verify(context.Background(), signed)
		if err != nil {
			t.Errorf("expected verification to pass with clock skew: %v", err)
		}
	})
}

func TestJWK_ToPublicKey_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	jwk := NewJWKFromRSAPublicKey(publicKey, "test-key", AlgorithmRS256)

	if jwk.KeyType != "RSA" {
		t.Errorf("expected key type RSA, got %s", jwk.KeyType)
	}
	if jwk.KeyID != "test-key" {
		t.Errorf("expected key ID test-key, got %s", jwk.KeyID)
	}
	if jwk.Algorithm != AlgorithmRS256 {
		t.Errorf("expected algorithm RS256, got %s", jwk.Algorithm)
	}

	// Convert back to public key
	recovered, err := jwk.ToPublicKey()
	if err != nil {
		t.Fatalf("failed to convert JWK to public key: %v", err)
	}

	rsaKey, ok := recovered.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected *rsa.PublicKey")
	}

	if rsaKey.N.Cmp(publicKey.N) != 0 {
		t.Error("modulus mismatch")
	}
	if rsaKey.E != publicKey.E {
		t.Error("exponent mismatch")
	}
}

func TestVerifier_Interface(t *testing.T) {
	var _ Verifier = &StaticKeyVerifier{}
	var _ Verifier = &JWKSVerifier{}
}
