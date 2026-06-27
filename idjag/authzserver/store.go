// Package authzserver implements the ID-JAG Authorization Server.
// It handles token exchange (RFC 8693) and provides policy-based routing between
// automated (ID-JAG) and human consent (AAuth) flows.
package authzserver

import (
	"context"
	"errors"
	"time"
)

// Store is the interface for authzserver data persistence.
// Implementations should be thread-safe.
type Store interface {
	// Close closes the store.
	Close() error

	// Token operations

	// CreateToken stores a new token record.
	CreateToken(ctx context.Context, token *Token) error

	// GetToken retrieves a token by ID.
	GetToken(ctx context.Context, id string) (*Token, error)

	// RevokeToken marks a token as revoked.
	RevokeToken(ctx context.Context, id string) error

	// ListTokens returns all tokens (for admin purposes).
	ListTokens(ctx context.Context) ([]*Token, error)

	// ScopePolicy operations

	// CreateScopePolicy creates a new scope policy.
	CreateScopePolicy(ctx context.Context, policy *ScopePolicy) error

	// GetScopePolicy retrieves a scope policy by ID.
	GetScopePolicy(ctx context.Context, id string) (*ScopePolicy, error)

	// ListScopePolicies returns all scope policies ordered by priority.
	ListScopePolicies(ctx context.Context) ([]*ScopePolicy, error)

	// DeleteScopePolicy removes a scope policy by ID.
	DeleteScopePolicy(ctx context.Context, id string) error
}

// Token represents a token record in the store.
type Token struct {
	ID        string     `json:"id"`
	MissionID string     `json:"mission_id,omitempty"`
	AgentID   string     `json:"agent_id"`
	UserID    string     `json:"user_id"`
	Scopes    string     `json:"scopes"`
	TokenType string     `json:"token_type"`
	Protocol  string     `json:"protocol"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// IsValid returns true if the token is still valid.
func (t *Token) IsValid() bool {
	if t.RevokedAt != nil {
		return false
	}
	return time.Now().Before(t.ExpiresAt)
}

// ScopePolicy defines the authorization protocol for a scope pattern.
type ScopePolicy struct {
	ID              string    `json:"id"`
	Pattern         string    `json:"pattern"`
	Protocol        string    `json:"protocol"`
	InteractionType string    `json:"interaction_type,omitempty"`
	Description     string    `json:"description,omitempty"`
	Priority        int       `json:"priority"`
	CreatedAt       time.Time `json:"created_at"`
}

// Standard errors for the Store interface.
var (
	// ErrNotFound is returned when a requested resource doesn't exist.
	ErrNotFound = errors.New("resource not found")

	// ErrAlreadyExists is returned when trying to create a resource that already exists.
	ErrAlreadyExists = errors.New("resource already exists")

	// ErrInvalidInput is returned when input validation fails.
	ErrInvalidInput = errors.New("invalid input")
)
