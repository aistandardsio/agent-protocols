// Package personserver implements the AAuth Person Server.
// The Person Server handles human consent for agent authorization.
package personserver

import (
	"context"
	"time"
)

// MissionStatus represents the status of a mission request.
type MissionStatus string

// Mission statuses.
const (
	MissionStatusPending  MissionStatus = "pending"
	MissionStatusApproved MissionStatus = "approved"
	MissionStatusDenied   MissionStatus = "denied"
	MissionStatusExpired  MissionStatus = "expired"
	MissionStatusRevoked  MissionStatus = "revoked"
)

// User represents a person who can authorize agents.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Agent represents a registered agent that can request authorization.
type Agent struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	PublicKey   string    `json:"public_key"`
	RedirectURI string    `json:"redirect_uri,omitempty"`
	Trusted     bool      `json:"trusted"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Mission represents an agent's request to act on behalf of a user.
type Mission struct {
	ID              string        `json:"id"`
	AgentID         string        `json:"agent_id"`
	UserID          string        `json:"user_id"`
	Name            string        `json:"name"`
	Description     string        `json:"description,omitempty"`
	Scopes          string        `json:"scopes"`
	InteractionType string        `json:"interaction_type"`
	Status          MissionStatus `json:"status"`
	Duration        int64         `json:"duration"`
	ExpiresAt       *time.Time    `json:"expires_at,omitempty"`
	ApprovedAt      *time.Time    `json:"approved_at,omitempty"`
	DeniedAt        *time.Time    `json:"denied_at,omitempty"`
	DenialReason    string        `json:"denial_reason,omitempty"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// IsActive returns true if the mission is currently active.
func (m *Mission) IsActive() bool {
	if m.Status != MissionStatusApproved {
		return false
	}
	if m.ExpiresAt != nil && time.Now().After(*m.ExpiresAt) {
		return false
	}
	return true
}

// Token represents an issued auth token record.
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

// Store defines the interface for Person Server storage.
// Implementations can use SQLite, DynamoDB, PostgreSQL, etc.
type Store interface {
	// Close closes the store connection.
	Close() error

	// User operations
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)

	// Agent operations
	CreateAgent(ctx context.Context, agent *Agent) error
	GetAgent(ctx context.Context, id string) (*Agent, error)
	ListAgents(ctx context.Context) ([]*Agent, error)

	// Mission operations
	CreateMission(ctx context.Context, mission *Mission) error
	GetMission(ctx context.Context, id string) (*Mission, error)
	ApproveMission(ctx context.Context, id string, duration time.Duration) error
	DenyMission(ctx context.Context, id, reason string) error
	ListPendingMissions(ctx context.Context) ([]*Mission, error)
	ListMissionsByUser(ctx context.Context, userID string) ([]*Mission, error)

	// Token operations
	CreateToken(ctx context.Context, token *Token) error
	GetToken(ctx context.Context, id string) (*Token, error)
	RevokeToken(ctx context.Context, id string) error
}

// StoreError represents storage errors.
type StoreError string

func (e StoreError) Error() string { return string(e) }

// Store errors.
const (
	ErrNotFound      StoreError = "not found"
	ErrAlreadyExists StoreError = "already exists"
	ErrInvalidInput  StoreError = "invalid input"
)
