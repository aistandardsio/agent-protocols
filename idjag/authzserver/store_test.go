package authzserver

import (
	"context"
	"sync"
	"testing"
	"time"
)

// MockStore is an in-memory implementation of the Store interface for testing.
type MockStore struct {
	mu            sync.RWMutex
	tokens        map[string]*Token
	scopePolicies map[string]*ScopePolicy
	closed        bool
}

// NewMockStore creates a new mock store.
func NewMockStore() *MockStore {
	return &MockStore{
		tokens:        make(map[string]*Token),
		scopePolicies: make(map[string]*ScopePolicy),
	}
}

func (s *MockStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *MockStore) CreateToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token.ID == "" {
		token.ID = "token-" + time.Now().Format("20060102150405.000000")
	}
	if token.IssuedAt.IsZero() {
		token.IssuedAt = time.Now()
	}
	if _, exists := s.tokens[token.ID]; exists {
		return ErrAlreadyExists
	}
	s.tokens[token.ID] = token
	return nil
}

func (s *MockStore) GetToken(ctx context.Context, id string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, exists := s.tokens[id]
	if !exists {
		return nil, ErrNotFound
	}
	return token, nil
}

func (s *MockStore) RevokeToken(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, exists := s.tokens[id]
	if !exists {
		return ErrNotFound
	}
	now := time.Now()
	token.RevokedAt = &now
	return nil
}

func (s *MockStore) ListTokens(ctx context.Context) ([]*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tokens := make([]*Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		tokens = append(tokens, t)
	}
	return tokens, nil
}

func (s *MockStore) CreateScopePolicy(ctx context.Context, policy *ScopePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if policy.ID == "" {
		policy.ID = "policy-" + time.Now().Format("20060102150405.000000")
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now()
	}
	if _, exists := s.scopePolicies[policy.ID]; exists {
		return ErrAlreadyExists
	}
	s.scopePolicies[policy.ID] = policy
	return nil
}

func (s *MockStore) GetScopePolicy(ctx context.Context, id string) (*ScopePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	policy, exists := s.scopePolicies[id]
	if !exists {
		return nil, ErrNotFound
	}
	return policy, nil
}

func (s *MockStore) ListScopePolicies(ctx context.Context) ([]*ScopePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	policies := make([]*ScopePolicy, 0, len(s.scopePolicies))
	for _, p := range s.scopePolicies {
		policies = append(policies, p)
	}
	return policies, nil
}

func (s *MockStore) DeleteScopePolicy(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.scopePolicies[id]; !exists {
		return ErrNotFound
	}
	delete(s.scopePolicies, id)
	return nil
}

// Verify MockStore implements Store interface
var _ Store = (*MockStore)(nil)

func TestMockStore_TokenOperations(t *testing.T) {
	ctx := context.Background()
	store := NewMockStore()
	defer store.Close()

	// Create token
	token := &Token{
		AgentID:   "agent-1",
		UserID:    "user-1",
		Scopes:    "read:data",
		Protocol:  "idjag",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := store.CreateToken(ctx, token)
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}
	if token.ID == "" {
		t.Error("Token ID should be generated")
	}

	// Get token
	retrieved, err := store.GetToken(ctx, token.ID)
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}
	if retrieved.AgentID != token.AgentID {
		t.Errorf("AgentID mismatch: got %s, want %s", retrieved.AgentID, token.AgentID)
	}

	// List tokens
	tokens, err := store.ListTokens(ctx)
	if err != nil {
		t.Fatalf("ListTokens failed: %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("Expected 1 token, got %d", len(tokens))
	}

	// Revoke token
	err = store.RevokeToken(ctx, token.ID)
	if err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	retrieved, _ = store.GetToken(ctx, token.ID)
	if retrieved.RevokedAt == nil {
		t.Error("Token should be revoked")
	}
	if retrieved.IsValid() {
		t.Error("Revoked token should not be valid")
	}

	// Get non-existent token
	_, err = store.GetToken(ctx, "non-existent")
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestMockStore_ScopePolicyOperations(t *testing.T) {
	ctx := context.Background()
	store := NewMockStore()
	defer store.Close()

	// Create policy
	policy := &ScopePolicy{
		Pattern:  "read:*",
		Protocol: "idjag",
		Priority: 100,
	}

	err := store.CreateScopePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreateScopePolicy failed: %v", err)
	}
	if policy.ID == "" {
		t.Error("Policy ID should be generated")
	}

	// Get policy
	retrieved, err := store.GetScopePolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("GetScopePolicy failed: %v", err)
	}
	if retrieved.Pattern != policy.Pattern {
		t.Errorf("Pattern mismatch: got %s, want %s", retrieved.Pattern, policy.Pattern)
	}

	// List policies
	policies, err := store.ListScopePolicies(ctx)
	if err != nil {
		t.Fatalf("ListScopePolicies failed: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	// Delete policy
	err = store.DeleteScopePolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("DeleteScopePolicy failed: %v", err)
	}

	// Verify deleted
	_, err = store.GetScopePolicy(ctx, policy.ID)
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound after delete, got %v", err)
	}
}

func TestToken_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		token Token
		want  bool
	}{
		{
			name: "valid token",
			token: Token{
				ExpiresAt: time.Now().Add(time.Hour),
				RevokedAt: nil,
			},
			want: true,
		},
		{
			name: "expired token",
			token: Token{
				ExpiresAt: time.Now().Add(-time.Hour),
				RevokedAt: nil,
			},
			want: false,
		},
		{
			name: "revoked token",
			token: Token{
				ExpiresAt: time.Now().Add(time.Hour),
				RevokedAt: func() *time.Time { t := time.Now(); return &t }(),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.IsValid(); got != tt.want {
				t.Errorf("Token.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
