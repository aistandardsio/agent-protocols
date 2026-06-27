package authzserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return key
}

func TestNew(t *testing.T) {
	store := NewMockStore()
	key := generateTestKey(t)

	server, err := New(store, "https://auth.example.com", key, "key-1")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if server.Issuer() != "https://auth.example.com" {
		t.Errorf("Issuer() = %v, want https://auth.example.com", server.Issuer())
	}
	if server.KeyID() != "key-1" {
		t.Errorf("KeyID() = %v, want key-1", server.KeyID())
	}
	if server.PublicKey() == nil {
		t.Error("PublicKey() should not be nil")
	}
	if server.Store() != store {
		t.Error("Store() should return the provided store")
	}
}

func TestNew_InvalidPrivateKey(t *testing.T) {
	store := NewMockStore()

	// Use an invalid private key (not implementing crypto.Signer)
	_, err := New(store, "https://auth.example.com", "not-a-key", "key-1")
	if err != ErrInvalidPrivateKey {
		t.Errorf("Expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestNew_WithOptions(t *testing.T) {
	store := NewMockStore()
	key := generateTestKey(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	server, err := New(store, "https://auth.example.com", key, "key-1",
		WithLogger(logger),
		WithTokenTTL(2*time.Hour),
		WithSigningMethod(jwt.SigningMethodES384),
		WithPersonServerURL("https://person.example.com"),
	)
	if err != nil {
		t.Fatalf("New() with options failed: %v", err)
	}

	// Verify the server was created successfully
	if server == nil {
		t.Error("Server should not be nil")
	}
}

func TestNew_WithPolicyEvaluator(t *testing.T) {
	store := NewMockStore()
	key := generateTestKey(t)

	evaluator := NewStaticPolicyEvaluator().
		WithIDJAGScopes("read:*").
		WithAAuthScopes("write:*")

	server, err := New(store, "https://auth.example.com", key, "key-1",
		WithPolicyEvaluator(evaluator),
	)
	if err != nil {
		t.Fatalf("New() with policy evaluator failed: %v", err)
	}

	if server == nil {
		t.Error("Server should not be nil")
	}
}

func TestNew_DefaultPolicyEvaluator(t *testing.T) {
	store := NewMockStore()
	key := generateTestKey(t)

	// When no policy evaluator is provided, a default one should be created
	server, err := New(store, "https://auth.example.com", key, "key-1")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if server == nil {
		t.Error("Server should not be nil")
	}
}

func TestServer_Handler(t *testing.T) {
	store := NewMockStore()
	key := generateTestKey(t)

	server, err := New(store, "https://auth.example.com", key, "key-1")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	handler := server.Handler()
	if handler == nil {
		t.Error("Handler() should return a non-nil handler")
	}
}
