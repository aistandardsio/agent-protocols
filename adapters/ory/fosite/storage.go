package fosite

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// TokenData contains the data for an access token.
type TokenData struct {
	// Subject is the token subject.
	Subject string

	// Issuer is the token issuer.
	Issuer string

	// Audience is the intended audience.
	Audience []string

	// Scopes are the granted scopes.
	Scopes []string

	// IssuedAt is when the token was issued.
	IssuedAt time.Time

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time

	// ClientID is the OAuth client ID.
	ClientID string

	// Actor contains delegation information (optional).
	Actor *ActorData
}

// ActorData contains actor delegation information.
type ActorData struct {
	// Subject is the actor's subject.
	Subject string

	// Issuer is the actor's issuer.
	Issuer string
}

// TokenStorage provides token persistence.
type TokenStorage interface {
	// CreateAccessToken creates and stores an access token.
	CreateAccessToken(ctx context.Context, data *TokenData) (string, error)

	// GetAccessToken retrieves token data by token string.
	GetAccessToken(ctx context.Context, token string) (*TokenData, error)

	// RevokeAccessToken revokes an access token.
	RevokeAccessToken(ctx context.Context, token string) error
}

// MemoryStorage is an in-memory token storage for development/testing.
type MemoryStorage struct {
	mu     sync.RWMutex
	tokens map[string]*TokenData
}

// NewMemoryStorage creates a new in-memory token storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		tokens: make(map[string]*TokenData),
	}
}

// CreateAccessToken creates and stores an access token.
func (s *MemoryStorage) CreateAccessToken(_ context.Context, data *TokenData) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	s.mu.Lock()
	s.tokens[token] = data
	s.mu.Unlock()

	return token, nil
}

// GetAccessToken retrieves token data by token string.
func (s *MemoryStorage) GetAccessToken(_ context.Context, token string) (*TokenData, error) {
	s.mu.RLock()
	data, ok := s.tokens[token]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("token not found")
	}

	if time.Now().After(data.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	return data, nil
}

// RevokeAccessToken revokes an access token.
func (s *MemoryStorage) RevokeAccessToken(_ context.Context, token string) error {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()
	return nil
}

// generateToken generates a random token string.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
