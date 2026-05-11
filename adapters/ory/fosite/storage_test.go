package fosite

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStorage(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	data := &TokenData{
		Subject:   "test-subject",
		Issuer:    "https://issuer.example.com",
		Audience:  []string{"https://api.example.com"},
		Scopes:    []string{"read", "write"},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		ClientID:  "test-client",
	}

	// Create token
	token, err := storage.CreateAccessToken(ctx, data)
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	if token == "" {
		t.Fatal("Expected non-empty token")
	}

	// Get token
	retrieved, err := storage.GetAccessToken(ctx, token)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}

	if retrieved.Subject != data.Subject {
		t.Errorf("Subject = %v, want %v", retrieved.Subject, data.Subject)
	}

	if retrieved.Issuer != data.Issuer {
		t.Errorf("Issuer = %v, want %v", retrieved.Issuer, data.Issuer)
	}

	// Revoke token
	err = storage.RevokeAccessToken(ctx, token)
	if err != nil {
		t.Fatalf("RevokeAccessToken() error = %v", err)
	}

	// Verify revoked
	_, err = storage.GetAccessToken(ctx, token)
	if err == nil {
		t.Fatal("Expected error for revoked token")
	}
}

func TestMemoryStorageExpiredToken(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	data := &TokenData{
		Subject:   "test-subject",
		Issuer:    "https://issuer.example.com",
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour), // Expired
	}

	token, err := storage.CreateAccessToken(ctx, data)
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	// Should fail for expired token
	_, err = storage.GetAccessToken(ctx, token)
	if err == nil {
		t.Fatal("Expected error for expired token")
	}
}

func TestMemoryStorageTokenNotFound(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	_, err := storage.GetAccessToken(ctx, "nonexistent-token")
	if err == nil {
		t.Fatal("Expected error for nonexistent token")
	}
}

func TestMemoryStorageWithActor(t *testing.T) {
	storage := NewMemoryStorage()
	ctx := context.Background()

	data := &TokenData{
		Subject:   "agent-subject",
		Issuer:    "https://issuer.example.com",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Actor: &ActorData{
			Subject: "user-subject",
			Issuer:  "https://user-issuer.example.com",
		},
	}

	token, err := storage.CreateAccessToken(ctx, data)
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	retrieved, err := storage.GetAccessToken(ctx, token)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}

	if retrieved.Actor == nil {
		t.Fatal("Expected actor in retrieved token")
	}

	if retrieved.Actor.Subject != "user-subject" {
		t.Errorf("Actor.Subject = %v, want user-subject", retrieved.Actor.Subject)
	}
}
