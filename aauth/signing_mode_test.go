package aauth

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJWTKeyProvider(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	provider := NewJWTKeyProvider(keyPair)

	t.Run("Mode", func(t *testing.T) {
		if provider.Mode() != SigningModeJWT {
			t.Errorf("expected mode %s, got %s", SigningModeJWT, provider.Mode())
		}
	})

	t.Run("KeyID", func(t *testing.T) {
		if provider.KeyID() != "test-key" {
			t.Errorf("expected key ID test-key, got %s", provider.KeyID())
		}
	})

	t.Run("Algorithm", func(t *testing.T) {
		if provider.Algorithm() != AlgorithmES256 {
			t.Errorf("expected algorithm %s, got %s", AlgorithmES256, provider.Algorithm())
		}
	})

	t.Run("PublicKey", func(t *testing.T) {
		ctx := context.Background()
		pub, err := provider.PublicKey(ctx)
		if err != nil {
			t.Fatalf("failed to get public key: %v", err)
		}
		if pub == nil {
			t.Error("public key is nil")
		}
	})

	t.Run("CNF", func(t *testing.T) {
		ctx := context.Background()
		cnf, err := provider.CNF(ctx)
		if err != nil {
			t.Fatalf("failed to get CNF: %v", err)
		}
		if !cnf.IsEmbedded() {
			t.Error("expected embedded JWK in CNF")
		}
	})

	t.Run("Sign", func(t *testing.T) {
		ctx := context.Background()
		data := []byte("test data to sign")
		sig, err := provider.Sign(ctx, data)
		if err != nil {
			t.Fatalf("failed to sign data: %v", err)
		}
		if len(sig) == 0 {
			t.Error("signature is empty")
		}
	})
}

func TestJWKSURIKeyProvider(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Create a mock JWKS server
	jwk, err := keyPair.ToJWK()
	if err != nil {
		t.Fatalf("failed to convert to JWK: %v", err)
	}

	jwks := JWKSet{Keys: []JWK{*jwk}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	provider := NewJWKSURIKeyProvider(keyPair, server.URL,
		WithJWKSCacheTTL(1*time.Second),
	)

	t.Run("Mode", func(t *testing.T) {
		if provider.Mode() != SigningModeJWKSURI {
			t.Errorf("expected mode %s, got %s", SigningModeJWKSURI, provider.Mode())
		}
	})

	t.Run("JWKSURI", func(t *testing.T) {
		if provider.JWKSURI() != server.URL {
			t.Errorf("expected JWKS URI %s, got %s", server.URL, provider.JWKSURI())
		}
	})

	t.Run("CNF", func(t *testing.T) {
		ctx := context.Background()
		cnf, err := provider.CNF(ctx)
		if err != nil {
			t.Fatalf("failed to get CNF: %v", err)
		}
		if cnf.JKU != server.URL {
			t.Errorf("expected JKU %s, got %s", server.URL, cnf.JKU)
		}
		if cnf.Kid != "test-key" {
			t.Errorf("expected kid test-key, got %s", cnf.Kid)
		}
	})

	t.Run("FetchJWKS", func(t *testing.T) {
		ctx := context.Background()
		fetchedJWKS, err := provider.FetchJWKS(ctx)
		if err != nil {
			t.Fatalf("failed to fetch JWKS: %v", err)
		}
		if len(fetchedJWKS.Keys) != 1 {
			t.Errorf("expected 1 key, got %d", len(fetchedJWKS.Keys))
		}
	})

	t.Run("FindKey", func(t *testing.T) {
		ctx := context.Background()
		foundKey, err := provider.FindKey(ctx, "test-key")
		if err != nil {
			t.Fatalf("failed to find key: %v", err)
		}
		if foundKey.Kid != "test-key" {
			t.Errorf("expected kid test-key, got %s", foundKey.Kid)
		}
	})

	t.Run("FindKeyNotFound", func(t *testing.T) {
		ctx := context.Background()
		_, err := provider.FindKey(ctx, "nonexistent")
		if err == nil {
			t.Error("expected error for nonexistent key")
		}
	})
}

func TestJKTJWTKeyProvider(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	provider, err := NewJKTJWTKeyProvider(keyPair)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	t.Run("Mode", func(t *testing.T) {
		if provider.Mode() != SigningModeJKTJWT {
			t.Errorf("expected mode %s, got %s", SigningModeJKTJWT, provider.Mode())
		}
	})

	t.Run("Thumbprint", func(t *testing.T) {
		if provider.Thumbprint() == "" {
			t.Error("thumbprint is empty")
		}
		// Thumbprint should be the key ID
		if provider.KeyID() != provider.Thumbprint() {
			t.Errorf("expected keyID to equal thumbprint")
		}
	})

	t.Run("CNF", func(t *testing.T) {
		ctx := context.Background()
		cnf, err := provider.CNF(ctx)
		if err != nil {
			t.Fatalf("failed to get CNF: %v", err)
		}
		if cnf.Kid != provider.Thumbprint() {
			t.Errorf("expected kid %s, got %s", provider.Thumbprint(), cnf.Kid)
		}
	})
}

func TestHWKKeyProvider(t *testing.T) {
	// Use a regular key pair as a mock hardware key
	keyPair, err := GenerateECDSAKeyPair("hwk-test", elliptic.P256())
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// ECDSA private keys implement crypto.Signer
	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		t.Skip("private key does not implement crypto.Signer")
	}

	attestation := []byte("mock attestation data")
	provider, err := NewHWKKeyProvider("hwk-key", AlgorithmES256, signer,
		WithHWKAttestation(attestation))
	if err != nil {
		t.Fatalf("failed to create HWK provider: %v", err)
	}

	t.Run("Mode", func(t *testing.T) {
		if provider.Mode() != SigningModeHWK {
			t.Errorf("expected mode %s, got %s", SigningModeHWK, provider.Mode())
		}
	})

	t.Run("KeyID", func(t *testing.T) {
		if provider.KeyID() != "hwk-key" {
			t.Errorf("expected key ID hwk-key, got %s", provider.KeyID())
		}
	})

	t.Run("Algorithm", func(t *testing.T) {
		if provider.Algorithm() != AlgorithmES256 {
			t.Errorf("expected algorithm %s, got %s", AlgorithmES256, provider.Algorithm())
		}
	})

	t.Run("Attestation", func(t *testing.T) {
		if string(provider.Attestation()) != string(attestation) {
			t.Error("attestation mismatch")
		}
	})

	t.Run("PublicKey", func(t *testing.T) {
		ctx := context.Background()
		pub, err := provider.PublicKey(ctx)
		if err != nil {
			t.Fatalf("failed to get public key: %v", err)
		}
		if pub == nil {
			t.Error("public key is nil")
		}
	})

	t.Run("CNF", func(t *testing.T) {
		ctx := context.Background()
		cnf, err := provider.CNF(ctx)
		if err != nil {
			t.Fatalf("failed to get CNF: %v", err)
		}
		if !cnf.IsEmbedded() {
			t.Error("expected embedded JWK in CNF")
		}
	})

	t.Run("Sign", func(t *testing.T) {
		ctx := context.Background()
		data := []byte("test data to sign")
		sig, err := provider.Sign(ctx, data)
		if err != nil {
			t.Fatalf("failed to sign data: %v", err)
		}
		if len(sig) == 0 {
			t.Error("signature is empty")
		}
	})
}

func TestKeyProviderFromKeyPair(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	t.Run("JWT mode", func(t *testing.T) {
		provider, err := KeyProviderFromKeyPair(keyPair, SigningModeJWT)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}
		if provider.Mode() != SigningModeJWT {
			t.Errorf("expected mode %s, got %s", SigningModeJWT, provider.Mode())
		}
	})

	t.Run("Empty mode defaults to JWT", func(t *testing.T) {
		provider, err := KeyProviderFromKeyPair(keyPair, "")
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}
		if provider.Mode() != SigningModeJWT {
			t.Errorf("expected mode %s, got %s", SigningModeJWT, provider.Mode())
		}
	})

	t.Run("JKT-JWT mode", func(t *testing.T) {
		provider, err := KeyProviderFromKeyPair(keyPair, SigningModeJKTJWT)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}
		if provider.Mode() != SigningModeJKTJWT {
			t.Errorf("expected mode %s, got %s", SigningModeJKTJWT, provider.Mode())
		}
	})

	t.Run("JWKS_URI mode requires URI", func(t *testing.T) {
		_, err := KeyProviderFromKeyPair(keyPair, SigningModeJWKSURI)
		if err == nil {
			t.Error("expected error for missing JWKS URI")
		}
	})

	t.Run("JWKS_URI mode with URI", func(t *testing.T) {
		provider, err := KeyProviderFromKeyPair(keyPair, SigningModeJWKSURI, "https://example.com/.well-known/jwks.json")
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}
		if provider.Mode() != SigningModeJWKSURI {
			t.Errorf("expected mode %s, got %s", SigningModeJWKSURI, provider.Mode())
		}
	})

	t.Run("Unsupported mode", func(t *testing.T) {
		_, err := KeyProviderFromKeyPair(keyPair, SigningMode("unsupported"))
		if err == nil {
			t.Error("expected error for unsupported mode")
		}
	})
}
