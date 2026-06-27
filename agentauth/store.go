package agentauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// Store errors.
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidInput  = errors.New("invalid input")
)

// Store provides shared persistence for the authorization servers.
type Store struct {
	db *sql.DB
}

// NewStore creates a new SQLite-backed store.
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return store, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// DB returns the underlying database connection for advanced use cases.
func (s *Store) DB() *sql.DB {
	return s.db
}

// migrate creates the database schema.
func (s *Store) migrate() error {
	schema := `
	-- Users (persons who can authorize agents)
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	-- Agents (registered agents that can request authorization)
	CREATE TABLE IF NOT EXISTS agents (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		public_key TEXT NOT NULL,
		redirect_uri TEXT,
		trusted INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	-- Missions (AAuth mission-based authorization requests)
	CREATE TABLE IF NOT EXISTS missions (
		id TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL REFERENCES agents(id),
		user_id TEXT NOT NULL REFERENCES users(id),
		name TEXT NOT NULL,
		description TEXT,
		scopes TEXT NOT NULL,
		interaction_type TEXT NOT NULL DEFAULT 'supervised',
		status TEXT NOT NULL DEFAULT 'pending',
		duration INTEGER NOT NULL DEFAULT 3600,
		expires_at DATETIME,
		approved_at DATETIME,
		denied_at DATETIME,
		denial_reason TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	-- Tokens (issued auth tokens)
	CREATE TABLE IF NOT EXISTS tokens (
		id TEXT PRIMARY KEY,
		mission_id TEXT REFERENCES missions(id),
		agent_id TEXT NOT NULL REFERENCES agents(id),
		user_id TEXT NOT NULL REFERENCES users(id),
		scopes TEXT NOT NULL,
		token_type TEXT NOT NULL DEFAULT 'access_token',
		protocol TEXT NOT NULL DEFAULT 'aauth',
		issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		revoked_at DATETIME
	);

	-- Pre-authorizations (AAuth pre-approved scopes)
	CREATE TABLE IF NOT EXISTS pre_authorizations (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id),
		agent_id TEXT NOT NULL REFERENCES agents(id),
		scopes TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		UNIQUE(user_id, agent_id)
	);

	-- Scope policies (for ID-JAG automatic authorization)
	CREATE TABLE IF NOT EXISTS scope_policies (
		id TEXT PRIMARY KEY,
		pattern TEXT NOT NULL UNIQUE,
		protocol TEXT NOT NULL DEFAULT 'idjag',
		interaction_type TEXT,
		description TEXT,
		priority INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	-- Indexes
	CREATE INDEX IF NOT EXISTS idx_missions_user_id ON missions(user_id);
	CREATE INDEX IF NOT EXISTS idx_missions_agent_id ON missions(agent_id);
	CREATE INDEX IF NOT EXISTS idx_missions_status ON missions(status);
	CREATE INDEX IF NOT EXISTS idx_tokens_mission_id ON tokens(mission_id);
	CREATE INDEX IF NOT EXISTS idx_tokens_agent_id ON tokens(agent_id);
	CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
	CREATE INDEX IF NOT EXISTS idx_pre_auth_user_agent ON pre_authorizations(user_id, agent_id);
	CREATE INDEX IF NOT EXISTS idx_scope_policies_pattern ON scope_policies(pattern);
	`

	_, err := s.db.Exec(schema)
	return err
}

// ============================================================================
// User operations
// ============================================================================

// User represents a person who can authorize agents.
type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// CreateUser creates a new user.
func (s *Store) CreateUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, email, name, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, user.ID, user.Email, user.Name, user.CreatedAt, user.UpdatedAt)

	if err != nil {
		if isUniqueConstraintError(err) {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

// GetUser retrieves a user by ID.
func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	var user User
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, name, created_at, updated_at
		FROM users WHERE id = ?
	`, id).Scan(&user.ID, &user.Email, &user.Name, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, name, created_at, updated_at
		FROM users WHERE email = ?
	`, email).Scan(&user.ID, &user.Email, &user.Name, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ListUsers lists all users.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, email, name, created_at, updated_at
		FROM users ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Email, &user.Name, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	return users, rows.Err()
}

// ============================================================================
// Agent operations
// ============================================================================

// Agent represents a registered agent that can request authorization.
type Agent struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description,omitempty" db:"description"`
	PublicKey   string    `json:"public_key" db:"public_key"`
	RedirectURI string    `json:"redirect_uri,omitempty" db:"redirect_uri"`
	Trusted     bool      `json:"trusted" db:"trusted"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// CreateAgent creates a new agent.
func (s *Store) CreateAgent(ctx context.Context, agent *Agent) error {
	if agent.ID == "" {
		agent.ID = uuid.New().String()
	}
	now := time.Now()
	agent.CreatedAt = now
	agent.UpdatedAt = now

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agents (id, name, description, public_key, redirect_uri, trusted, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, agent.ID, agent.Name, agent.Description, agent.PublicKey, agent.RedirectURI, agent.Trusted, agent.CreatedAt, agent.UpdatedAt)

	return err
}

// GetAgent retrieves an agent by ID.
func (s *Store) GetAgent(ctx context.Context, id string) (*Agent, error) {
	var agent Agent
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, description, public_key, redirect_uri, trusted, created_at, updated_at
		FROM agents WHERE id = ?
	`, id).Scan(&agent.ID, &agent.Name, &agent.Description, &agent.PublicKey, &agent.RedirectURI, &agent.Trusted, &agent.CreatedAt, &agent.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &agent, nil
}

// ListAgents lists all agents.
func (s *Store) ListAgents(ctx context.Context) ([]*Agent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, description, public_key, redirect_uri, trusted, created_at, updated_at
		FROM agents ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*Agent
	for rows.Next() {
		var agent Agent
		if err := rows.Scan(&agent.ID, &agent.Name, &agent.Description, &agent.PublicKey, &agent.RedirectURI, &agent.Trusted, &agent.CreatedAt, &agent.UpdatedAt); err != nil {
			return nil, err
		}
		agents = append(agents, &agent)
	}
	return agents, rows.Err()
}

// ============================================================================
// Mission operations (AAuth)
// ============================================================================

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

// Mission represents an agent's request to act on behalf of a user.
type Mission struct {
	ID              string        `json:"id" db:"id"`
	AgentID         string        `json:"agent_id" db:"agent_id"`
	UserID          string        `json:"user_id" db:"user_id"`
	Name            string        `json:"name" db:"name"`
	Description     string        `json:"description,omitempty" db:"description"`
	Scopes          string        `json:"scopes" db:"scopes"`
	InteractionType string        `json:"interaction_type" db:"interaction_type"`
	Status          MissionStatus `json:"status" db:"status"`
	Duration        int64         `json:"duration" db:"duration"`
	ExpiresAt       *time.Time    `json:"expires_at,omitempty" db:"expires_at"`
	ApprovedAt      *time.Time    `json:"approved_at,omitempty" db:"approved_at"`
	DeniedAt        *time.Time    `json:"denied_at,omitempty" db:"denied_at"`
	DenialReason    string        `json:"denial_reason,omitempty" db:"denial_reason"`
	CreatedAt       time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at" db:"updated_at"`
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

// CreateMission creates a new mission.
func (s *Store) CreateMission(ctx context.Context, mission *Mission) error {
	if mission.ID == "" {
		mission.ID = uuid.New().String()
	}
	now := time.Now()
	mission.CreatedAt = now
	mission.UpdatedAt = now
	if mission.Status == "" {
		mission.Status = MissionStatusPending
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO missions (id, agent_id, user_id, name, description, scopes, interaction_type, status, duration, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, mission.ID, mission.AgentID, mission.UserID, mission.Name, mission.Description, mission.Scopes,
		mission.InteractionType, mission.Status, mission.Duration, mission.ExpiresAt, mission.CreatedAt, mission.UpdatedAt)

	return err
}

// GetMission retrieves a mission by ID.
func (s *Store) GetMission(ctx context.Context, id string) (*Mission, error) {
	var mission Mission
	var expiresAt, approvedAt, deniedAt sql.NullTime
	var description, denialReason sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, agent_id, user_id, name, description, scopes, interaction_type, status, duration,
		       expires_at, approved_at, denied_at, denial_reason, created_at, updated_at
		FROM missions WHERE id = ?
	`, id).Scan(&mission.ID, &mission.AgentID, &mission.UserID, &mission.Name, &description,
		&mission.Scopes, &mission.InteractionType, &mission.Status, &mission.Duration,
		&expiresAt, &approvedAt, &deniedAt, &denialReason, &mission.CreatedAt, &mission.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if description.Valid {
		mission.Description = description.String
	}
	if denialReason.Valid {
		mission.DenialReason = denialReason.String
	}
	if expiresAt.Valid {
		mission.ExpiresAt = &expiresAt.Time
	}
	if approvedAt.Valid {
		mission.ApprovedAt = &approvedAt.Time
	}
	if deniedAt.Valid {
		mission.DeniedAt = &deniedAt.Time
	}

	return &mission, nil
}

// ApproveMission approves a mission.
func (s *Store) ApproveMission(ctx context.Context, id string, duration time.Duration) error {
	now := time.Now()
	expiresAt := now.Add(duration)

	result, err := s.db.ExecContext(ctx, `
		UPDATE missions
		SET status = ?, approved_at = ?, expires_at = ?, updated_at = ?
		WHERE id = ? AND status = ?
	`, MissionStatusApproved, now, expiresAt, now, id, MissionStatusPending)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// DenyMission denies a mission.
func (s *Store) DenyMission(ctx context.Context, id, reason string) error {
	now := time.Now()

	result, err := s.db.ExecContext(ctx, `
		UPDATE missions
		SET status = ?, denied_at = ?, denial_reason = ?, updated_at = ?
		WHERE id = ? AND status = ?
	`, MissionStatusDenied, now, reason, now, id, MissionStatusPending)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// ListPendingMissions lists all pending missions.
func (s *Store) ListPendingMissions(ctx context.Context) ([]*Mission, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, agent_id, user_id, name, description, scopes, interaction_type, status, duration,
		       expires_at, approved_at, denied_at, denial_reason, created_at, updated_at
		FROM missions WHERE status = ? ORDER BY created_at DESC
	`, MissionStatusPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanMissions(rows)
}

// ListMissionsByUser lists missions for a user.
func (s *Store) ListMissionsByUser(ctx context.Context, userID string) ([]*Mission, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, agent_id, user_id, name, description, scopes, interaction_type, status, duration,
		       expires_at, approved_at, denied_at, denial_reason, created_at, updated_at
		FROM missions WHERE user_id = ? ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanMissions(rows)
}

func scanMissions(rows *sql.Rows) ([]*Mission, error) {
	var missions []*Mission
	for rows.Next() {
		var mission Mission
		var expiresAt, approvedAt, deniedAt sql.NullTime
		var description, denialReason sql.NullString

		if err := rows.Scan(&mission.ID, &mission.AgentID, &mission.UserID, &mission.Name, &description,
			&mission.Scopes, &mission.InteractionType, &mission.Status, &mission.Duration,
			&expiresAt, &approvedAt, &deniedAt, &denialReason, &mission.CreatedAt, &mission.UpdatedAt); err != nil {
			return nil, err
		}

		if description.Valid {
			mission.Description = description.String
		}
		if denialReason.Valid {
			mission.DenialReason = denialReason.String
		}
		if expiresAt.Valid {
			mission.ExpiresAt = &expiresAt.Time
		}
		if approvedAt.Valid {
			mission.ApprovedAt = &approvedAt.Time
		}
		if deniedAt.Valid {
			mission.DeniedAt = &deniedAt.Time
		}

		missions = append(missions, &mission)
	}
	return missions, rows.Err()
}

// ============================================================================
// Token operations
// ============================================================================

// Token represents an issued auth token.
type Token struct {
	ID        string     `json:"id" db:"id"`
	MissionID string     `json:"mission_id,omitempty" db:"mission_id"`
	AgentID   string     `json:"agent_id" db:"agent_id"`
	UserID    string     `json:"user_id" db:"user_id"`
	Scopes    string     `json:"scopes" db:"scopes"`
	TokenType string     `json:"token_type" db:"token_type"`
	Protocol  string     `json:"protocol" db:"protocol"`
	IssuedAt  time.Time  `json:"issued_at" db:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// IsValid returns true if the token is still valid.
func (t *Token) IsValid() bool {
	if t.RevokedAt != nil {
		return false
	}
	return time.Now().Before(t.ExpiresAt)
}

// CreateToken creates a new token record.
func (s *Store) CreateToken(ctx context.Context, token *Token) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	token.IssuedAt = time.Now()
	if token.TokenType == "" {
		token.TokenType = "access_token"
	}
	if token.Protocol == "" {
		token.Protocol = "aauth"
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tokens (id, mission_id, agent_id, user_id, scopes, token_type, protocol, issued_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, token.ID, token.MissionID, token.AgentID, token.UserID, token.Scopes, token.TokenType, token.Protocol, token.IssuedAt, token.ExpiresAt)

	return err
}

// GetToken retrieves a token by ID.
func (s *Store) GetToken(ctx context.Context, id string) (*Token, error) {
	var token Token
	var revokedAt sql.NullTime
	var missionID sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, mission_id, agent_id, user_id, scopes, token_type, protocol, issued_at, expires_at, revoked_at
		FROM tokens WHERE id = ?
	`, id).Scan(&token.ID, &missionID, &token.AgentID, &token.UserID, &token.Scopes,
		&token.TokenType, &token.Protocol, &token.IssuedAt, &token.ExpiresAt, &revokedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if missionID.Valid {
		token.MissionID = missionID.String
	}
	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}

	return &token, nil
}

// RevokeToken revokes a token.
func (s *Store) RevokeToken(ctx context.Context, id string) error {
	now := time.Now()

	result, err := s.db.ExecContext(ctx, `
		UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL
	`, now, id)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// ============================================================================
// Pre-authorization operations (AAuth)
// ============================================================================

// PreAuthorization allows users to pre-approve certain scopes for agents.
type PreAuthorization struct {
	ID        string     `json:"id" db:"id"`
	UserID    string     `json:"user_id" db:"user_id"`
	AgentID   string     `json:"agent_id" db:"agent_id"`
	Scopes    string     `json:"scopes" db:"scopes"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`
}

// Covers returns true if this pre-authorization covers the requested scopes.
func (p *PreAuthorization) Covers(requestedScopes []string) bool {
	if p.ExpiresAt != nil && time.Now().After(*p.ExpiresAt) {
		return false
	}

	authorized := make(map[string]bool)
	for _, s := range splitScopes(p.Scopes) {
		authorized[s] = true
	}

	for _, s := range requestedScopes {
		if !authorized[s] {
			return false
		}
	}
	return true
}

// CreatePreAuthorization creates a pre-authorization.
func (s *Store) CreatePreAuthorization(ctx context.Context, preAuth *PreAuthorization) error {
	if preAuth.ID == "" {
		preAuth.ID = uuid.New().String()
	}
	preAuth.CreatedAt = time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO pre_authorizations (id, user_id, agent_id, scopes, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, preAuth.ID, preAuth.UserID, preAuth.AgentID, preAuth.Scopes, preAuth.CreatedAt, preAuth.ExpiresAt)

	return err
}

// GetPreAuthorization retrieves a pre-authorization for a user/agent pair.
func (s *Store) GetPreAuthorization(ctx context.Context, userID, agentID string) (*PreAuthorization, error) {
	var preAuth PreAuthorization
	var expiresAt sql.NullTime

	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, agent_id, scopes, created_at, expires_at
		FROM pre_authorizations WHERE user_id = ? AND agent_id = ?
	`, userID, agentID).Scan(&preAuth.ID, &preAuth.UserID, &preAuth.AgentID, &preAuth.Scopes, &preAuth.CreatedAt, &expiresAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if expiresAt.Valid {
		preAuth.ExpiresAt = &expiresAt.Time
	}

	return &preAuth, nil
}

// DeletePreAuthorization deletes a pre-authorization.
func (s *Store) DeletePreAuthorization(ctx context.Context, userID, agentID string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM pre_authorizations WHERE user_id = ? AND agent_id = ?
	`, userID, agentID)
	return err
}

// ============================================================================
// Scope policy operations (ID-JAG)
// ============================================================================

// StoredScopePolicy represents a scope policy stored in the database.
type StoredScopePolicy struct {
	ID              string    `json:"id" db:"id"`
	Pattern         string    `json:"pattern" db:"pattern"`
	Protocol        string    `json:"protocol" db:"protocol"`
	InteractionType string    `json:"interaction_type,omitempty" db:"interaction_type"`
	Description     string    `json:"description,omitempty" db:"description"`
	Priority        int       `json:"priority" db:"priority"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

// CreateScopePolicy creates a scope policy.
func (s *Store) CreateScopePolicy(ctx context.Context, policy *StoredScopePolicy) error {
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	policy.CreatedAt = time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO scope_policies (id, pattern, protocol, interaction_type, description, priority, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, policy.ID, policy.Pattern, policy.Protocol, policy.InteractionType, policy.Description, policy.Priority, policy.CreatedAt)

	return err
}

// ListScopePolicies lists all scope policies.
func (s *Store) ListScopePolicies(ctx context.Context) ([]*StoredScopePolicy, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, pattern, protocol, interaction_type, description, priority, created_at
		FROM scope_policies ORDER BY priority DESC, created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*StoredScopePolicy
	for rows.Next() {
		var policy StoredScopePolicy
		var interactionType, description sql.NullString
		if err := rows.Scan(&policy.ID, &policy.Pattern, &policy.Protocol, &interactionType, &description, &policy.Priority, &policy.CreatedAt); err != nil {
			return nil, err
		}
		if interactionType.Valid {
			policy.InteractionType = interactionType.String
		}
		if description.Valid {
			policy.Description = description.String
		}
		policies = append(policies, &policy)
	}
	return policies, rows.Err()
}

// DeleteScopePolicy deletes a scope policy.
func (s *Store) DeleteScopePolicy(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM scope_policies WHERE id = ?`, id)
	return err
}

// ============================================================================
// Helper functions
// ============================================================================

// splitScopes splits a space-separated scope string.
func splitScopes(scopes string) []string {
	if scopes == "" {
		return nil
	}
	var result []string
	current := ""
	for _, c := range scopes {
		if c == ' ' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// isUniqueConstraintError checks if an error is a unique constraint violation.
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return len(errStr) >= 6 && errStr[:6] == "UNIQUE"
}
