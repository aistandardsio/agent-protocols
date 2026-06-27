package agentauth

import (
	"context"
	"testing"
	"time"
)

func TestNewStore(t *testing.T) {
	t.Run("in-memory database", func(t *testing.T) {
		store, err := NewStore(":memory:")
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}
		defer store.Close()

		if store.DB() == nil {
			t.Error("expected database connection")
		}
	})

	t.Run("file database", func(t *testing.T) {
		tmpFile := t.TempDir() + "/test.db"
		store, err := NewStore(tmpFile)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}
		defer store.Close()

		if store.DB() == nil {
			t.Error("expected database connection")
		}
	})
}

func TestUserOperations(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	t.Run("create and get user", func(t *testing.T) {
		user := &User{
			ID:    "user-1",
			Email: "user1@example.com",
			Name:  "User One",
		}

		err := store.CreateUser(ctx, user)
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		if user.CreatedAt.IsZero() {
			t.Error("expected CreatedAt to be set")
		}

		got, err := store.GetUser(ctx, "user-1")
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}

		if got.Email != "user1@example.com" {
			t.Errorf("expected email user1@example.com, got %s", got.Email)
		}
		if got.Name != "User One" {
			t.Errorf("expected name User One, got %s", got.Name)
		}
	})

	t.Run("create user with auto-generated ID", func(t *testing.T) {
		user := &User{
			Email: "user2@example.com",
			Name:  "User Two",
		}

		err := store.CreateUser(ctx, user)
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		if user.ID == "" {
			t.Error("expected ID to be auto-generated")
		}
	})

	t.Run("get user not found", func(t *testing.T) {
		_, err := store.GetUser(ctx, "nonexistent")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("get user by email", func(t *testing.T) {
		got, err := store.GetUserByEmail(ctx, "user1@example.com")
		if err != nil {
			t.Fatalf("failed to get user by email: %v", err)
		}

		if got.ID != "user-1" {
			t.Errorf("expected ID user-1, got %s", got.ID)
		}
	})

	t.Run("get user by email not found", func(t *testing.T) {
		_, err := store.GetUserByEmail(ctx, "nonexistent@example.com")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("create duplicate user", func(t *testing.T) {
		user := &User{
			ID:    "dup-user",
			Email: "dup@example.com",
			Name:  "Dup User",
		}

		err := store.CreateUser(ctx, user)
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		// Try to create again with same email
		user2 := &User{
			ID:    "dup-user-2",
			Email: "dup@example.com",
			Name:  "Dup User 2",
		}
		err = store.CreateUser(ctx, user2)
		if err != ErrAlreadyExists {
			t.Errorf("expected ErrAlreadyExists, got %v", err)
		}
	})

	t.Run("list users", func(t *testing.T) {
		users, err := store.ListUsers(ctx)
		if err != nil {
			t.Fatalf("failed to list users: %v", err)
		}

		if len(users) < 2 {
			t.Errorf("expected at least 2 users, got %d", len(users))
		}
	})
}

func TestAgentOperations(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	t.Run("create and get agent", func(t *testing.T) {
		agent := &Agent{
			ID:          "agent-1",
			Name:        "Agent One",
			Description: "Test agent",
			PublicKey:   "test-public-key",
			Trusted:     true,
		}

		err := store.CreateAgent(ctx, agent)
		if err != nil {
			t.Fatalf("failed to create agent: %v", err)
		}

		if agent.CreatedAt.IsZero() {
			t.Error("expected CreatedAt to be set")
		}

		got, err := store.GetAgent(ctx, "agent-1")
		if err != nil {
			t.Fatalf("failed to get agent: %v", err)
		}

		if got.Name != "Agent One" {
			t.Errorf("expected name Agent One, got %s", got.Name)
		}
		if got.Description != "Test agent" {
			t.Errorf("expected description 'Test agent', got %s", got.Description)
		}
		if !got.Trusted {
			t.Error("expected trusted=true")
		}
	})

	t.Run("create agent with auto-generated ID", func(t *testing.T) {
		agent := &Agent{
			Name:      "Agent Two",
			PublicKey: "test-key-2",
		}

		err := store.CreateAgent(ctx, agent)
		if err != nil {
			t.Fatalf("failed to create agent: %v", err)
		}

		if agent.ID == "" {
			t.Error("expected ID to be auto-generated")
		}
	})

	t.Run("get agent not found", func(t *testing.T) {
		_, err := store.GetAgent(ctx, "nonexistent")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("list agents", func(t *testing.T) {
		agents, err := store.ListAgents(ctx)
		if err != nil {
			t.Fatalf("failed to list agents: %v", err)
		}

		if len(agents) < 2 {
			t.Errorf("expected at least 2 agents, got %d", len(agents))
		}
	})
}

func TestMissionOperations(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Create user and agent first
	user := &User{ID: "mission-user", Email: "mission@example.com", Name: "Mission User"}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	agent := &Agent{ID: "mission-agent", Name: "Mission Agent", PublicKey: "key"}
	if err := store.CreateAgent(ctx, agent); err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}

	t.Run("create and get mission", func(t *testing.T) {
		mission := &Mission{
			ID:              "mission-1",
			AgentID:         "mission-agent",
			UserID:          "mission-user",
			Name:            "Test Mission",
			Description:     "A test mission",
			Scopes:          "read:email write:profile",
			InteractionType: "supervised",
			Duration:        3600,
		}

		err := store.CreateMission(ctx, mission)
		if err != nil {
			t.Fatalf("failed to create mission: %v", err)
		}

		if mission.CreatedAt.IsZero() {
			t.Error("expected CreatedAt to be set")
		}
		if mission.Status != MissionStatusPending {
			t.Errorf("expected status pending, got %s", mission.Status)
		}

		got, err := store.GetMission(ctx, "mission-1")
		if err != nil {
			t.Fatalf("failed to get mission: %v", err)
		}

		if got.Name != "Test Mission" {
			t.Errorf("expected name 'Test Mission', got %s", got.Name)
		}
		if got.Scopes != "read:email write:profile" {
			t.Errorf("unexpected scopes: %s", got.Scopes)
		}
	})

	t.Run("get mission not found", func(t *testing.T) {
		_, err := store.GetMission(ctx, "nonexistent")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("approve mission", func(t *testing.T) {
		mission := &Mission{
			ID:              "approve-mission",
			AgentID:         "mission-agent",
			UserID:          "mission-user",
			Name:            "Approve Mission",
			Scopes:          "read:email",
			InteractionType: "supervised",
			Duration:        3600,
		}
		if err := store.CreateMission(ctx, mission); err != nil {
			t.Fatalf("failed to create mission: %v", err)
		}

		err := store.ApproveMission(ctx, "approve-mission", time.Hour)
		if err != nil {
			t.Fatalf("failed to approve mission: %v", err)
		}

		got, err := store.GetMission(ctx, "approve-mission")
		if err != nil {
			t.Fatalf("failed to get mission: %v", err)
		}

		if got.Status != MissionStatusApproved {
			t.Errorf("expected status approved, got %s", got.Status)
		}
		if got.ApprovedAt == nil {
			t.Error("expected ApprovedAt to be set")
		}
		if got.ExpiresAt == nil {
			t.Error("expected ExpiresAt to be set")
		}
		if !got.IsActive() {
			t.Error("expected mission to be active")
		}
	})

	t.Run("approve already processed mission", func(t *testing.T) {
		// Try to approve an already approved mission
		err := store.ApproveMission(ctx, "approve-mission", time.Hour)
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound for already processed mission, got %v", err)
		}
	})

	t.Run("deny mission", func(t *testing.T) {
		mission := &Mission{
			ID:              "deny-mission",
			AgentID:         "mission-agent",
			UserID:          "mission-user",
			Name:            "Deny Mission",
			Scopes:          "admin:*",
			InteractionType: "supervised",
			Duration:        3600,
		}
		if err := store.CreateMission(ctx, mission); err != nil {
			t.Fatalf("failed to create mission: %v", err)
		}

		err := store.DenyMission(ctx, "deny-mission", "Not trusted")
		if err != nil {
			t.Fatalf("failed to deny mission: %v", err)
		}

		got, err := store.GetMission(ctx, "deny-mission")
		if err != nil {
			t.Fatalf("failed to get mission: %v", err)
		}

		if got.Status != MissionStatusDenied {
			t.Errorf("expected status denied, got %s", got.Status)
		}
		if got.DeniedAt == nil {
			t.Error("expected DeniedAt to be set")
		}
		if got.DenialReason != "Not trusted" {
			t.Errorf("expected denial reason 'Not trusted', got %s", got.DenialReason)
		}
		if got.IsActive() {
			t.Error("expected mission to not be active")
		}
	})

	t.Run("list pending missions", func(t *testing.T) {
		missions, err := store.ListPendingMissions(ctx)
		if err != nil {
			t.Fatalf("failed to list pending missions: %v", err)
		}

		for _, m := range missions {
			if m.Status != MissionStatusPending {
				t.Errorf("expected only pending missions, got status %s", m.Status)
			}
		}
	})

	t.Run("list missions by user", func(t *testing.T) {
		missions, err := store.ListMissionsByUser(ctx, "mission-user")
		if err != nil {
			t.Fatalf("failed to list missions: %v", err)
		}

		if len(missions) < 3 {
			t.Errorf("expected at least 3 missions for user, got %d", len(missions))
		}

		for _, m := range missions {
			if m.UserID != "mission-user" {
				t.Errorf("expected user mission-user, got %s", m.UserID)
			}
		}
	})
}

func TestTokenOperations(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	t.Run("create and get token", func(t *testing.T) {
		token := &Token{
			ID:        "token-1",
			AgentID:   "agent-1",
			UserID:    "user-1",
			Scopes:    "read:email",
			Protocol:  "aauth",
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.CreateToken(ctx, token)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		if token.IssuedAt.IsZero() {
			t.Error("expected IssuedAt to be set")
		}
		if token.TokenType == "" {
			t.Error("expected TokenType to be set")
		}

		got, err := store.GetToken(ctx, "token-1")
		if err != nil {
			t.Fatalf("failed to get token: %v", err)
		}

		if got.Scopes != "read:email" {
			t.Errorf("expected scopes read:email, got %s", got.Scopes)
		}
		if got.Protocol != "aauth" {
			t.Errorf("expected protocol aauth, got %s", got.Protocol)
		}
		if !got.IsValid() {
			t.Error("expected token to be valid")
		}
	})

	t.Run("create token with auto-generated ID", func(t *testing.T) {
		token := &Token{
			AgentID:   "agent-1",
			UserID:    "user-1",
			Scopes:    "read:profile",
			ExpiresAt: time.Now().Add(time.Hour),
		}

		err := store.CreateToken(ctx, token)
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		if token.ID == "" {
			t.Error("expected ID to be auto-generated")
		}
	})

	t.Run("get token not found", func(t *testing.T) {
		_, err := store.GetToken(ctx, "nonexistent")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("revoke token", func(t *testing.T) {
		token := &Token{
			ID:        "revoke-token",
			AgentID:   "agent-1",
			UserID:    "user-1",
			Scopes:    "read:email",
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := store.CreateToken(ctx, token); err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		err := store.RevokeToken(ctx, "revoke-token")
		if err != nil {
			t.Fatalf("failed to revoke token: %v", err)
		}

		got, err := store.GetToken(ctx, "revoke-token")
		if err != nil {
			t.Fatalf("failed to get token: %v", err)
		}

		if got.RevokedAt == nil {
			t.Error("expected RevokedAt to be set")
		}
		if got.IsValid() {
			t.Error("expected token to be invalid after revocation")
		}
	})

	t.Run("revoke nonexistent token", func(t *testing.T) {
		err := store.RevokeToken(ctx, "nonexistent")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("expired token is invalid", func(t *testing.T) {
		token := &Token{
			ID:        "expired-token",
			AgentID:   "agent-1",
			UserID:    "user-1",
			Scopes:    "read:email",
			ExpiresAt: time.Now().Add(-time.Hour), // Expired
		}
		if err := store.CreateToken(ctx, token); err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		got, err := store.GetToken(ctx, "expired-token")
		if err != nil {
			t.Fatalf("failed to get token: %v", err)
		}

		if got.IsValid() {
			t.Error("expected expired token to be invalid")
		}
	})
}

func TestPreAuthorizationOperations(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	t.Run("create and get pre-authorization", func(t *testing.T) {
		preAuth := &PreAuthorization{
			UserID:  "user-1",
			AgentID: "agent-1",
			Scopes:  "read:email read:profile",
		}

		err := store.CreatePreAuthorization(ctx, preAuth)
		if err != nil {
			t.Fatalf("failed to create pre-authorization: %v", err)
		}

		if preAuth.ID == "" {
			t.Error("expected ID to be set")
		}
		if preAuth.CreatedAt.IsZero() {
			t.Error("expected CreatedAt to be set")
		}

		got, err := store.GetPreAuthorization(ctx, "user-1", "agent-1")
		if err != nil {
			t.Fatalf("failed to get pre-authorization: %v", err)
		}

		if got.Scopes != "read:email read:profile" {
			t.Errorf("expected scopes 'read:email read:profile', got %s", got.Scopes)
		}
	})

	t.Run("get pre-authorization not found", func(t *testing.T) {
		_, err := store.GetPreAuthorization(ctx, "nonexistent", "nonexistent")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("pre-authorization covers scopes", func(t *testing.T) {
		got, _ := store.GetPreAuthorization(ctx, "user-1", "agent-1")

		if !got.Covers([]string{"read:email"}) {
			t.Error("expected pre-auth to cover read:email")
		}
		if !got.Covers([]string{"read:profile"}) {
			t.Error("expected pre-auth to cover read:profile")
		}
		if !got.Covers([]string{"read:email", "read:profile"}) {
			t.Error("expected pre-auth to cover both scopes")
		}
		if got.Covers([]string{"write:profile"}) {
			t.Error("expected pre-auth to NOT cover write:profile")
		}
		if got.Covers([]string{"read:email", "write:profile"}) {
			t.Error("expected pre-auth to NOT cover mixed scopes")
		}
	})

	t.Run("expired pre-authorization", func(t *testing.T) {
		expiredTime := time.Now().Add(-time.Hour)
		preAuth := &PreAuthorization{
			UserID:    "user-2",
			AgentID:   "agent-2",
			Scopes:    "read:email",
			ExpiresAt: &expiredTime,
		}
		if err := store.CreatePreAuthorization(ctx, preAuth); err != nil {
			t.Fatalf("failed to create pre-auth: %v", err)
		}

		got, _ := store.GetPreAuthorization(ctx, "user-2", "agent-2")
		if got.Covers([]string{"read:email"}) {
			t.Error("expected expired pre-auth to not cover scopes")
		}
	})

	t.Run("upsert pre-authorization", func(t *testing.T) {
		// Create new pre-auth for same user/agent
		preAuth := &PreAuthorization{
			UserID:  "user-1",
			AgentID: "agent-1",
			Scopes:  "read:email write:profile admin:*",
		}
		err := store.CreatePreAuthorization(ctx, preAuth)
		if err != nil {
			t.Fatalf("failed to upsert pre-authorization: %v", err)
		}

		got, _ := store.GetPreAuthorization(ctx, "user-1", "agent-1")
		if got.Scopes != "read:email write:profile admin:*" {
			t.Errorf("expected updated scopes, got %s", got.Scopes)
		}
	})

	t.Run("delete pre-authorization", func(t *testing.T) {
		preAuth := &PreAuthorization{
			UserID:  "delete-user",
			AgentID: "delete-agent",
			Scopes:  "read:email",
		}
		if err := store.CreatePreAuthorization(ctx, preAuth); err != nil {
			t.Fatalf("failed to create pre-auth: %v", err)
		}

		err := store.DeletePreAuthorization(ctx, "delete-user", "delete-agent")
		if err != nil {
			t.Fatalf("failed to delete pre-auth: %v", err)
		}

		_, err = store.GetPreAuthorization(ctx, "delete-user", "delete-agent")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound after delete, got %v", err)
		}
	})
}

func TestScopePolicyOperations(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	t.Run("create and list scope policies", func(t *testing.T) {
		policies := []*StoredScopePolicy{
			{
				Pattern:     "read:*",
				Protocol:    "idjag",
				Description: "Read scopes",
				Priority:    100,
			},
			{
				Pattern:         "write:*",
				Protocol:        "aauth",
				InteractionType: "supervised",
				Description:     "Write scopes",
				Priority:        100,
			},
			{
				Pattern:  "admin:*",
				Protocol: "aauth",
				Priority: 200,
			},
		}

		for _, p := range policies {
			err := store.CreateScopePolicy(ctx, p)
			if err != nil {
				t.Fatalf("failed to create policy: %v", err)
			}
			if p.ID == "" {
				t.Error("expected ID to be set")
			}
		}

		got, err := store.ListScopePolicies(ctx)
		if err != nil {
			t.Fatalf("failed to list policies: %v", err)
		}

		if len(got) != 3 {
			t.Errorf("expected 3 policies, got %d", len(got))
		}

		// Should be ordered by priority DESC
		if got[0].Priority < got[1].Priority {
			t.Error("expected policies ordered by priority DESC")
		}
	})

	t.Run("upsert scope policy", func(t *testing.T) {
		policy := &StoredScopePolicy{
			Pattern:     "delete:*",
			Protocol:    "idjag",
			Description: "Original",
		}
		if err := store.CreateScopePolicy(ctx, policy); err != nil {
			t.Fatalf("failed to create policy: %v", err)
		}

		// Upsert with same pattern
		policy2 := &StoredScopePolicy{
			Pattern:     "delete:*",
			Protocol:    "aauth",
			Description: "Updated",
		}
		if err := store.CreateScopePolicy(ctx, policy2); err != nil {
			t.Fatalf("failed to upsert policy: %v", err)
		}

		got, _ := store.ListScopePolicies(ctx)
		var found *StoredScopePolicy
		for _, p := range got {
			if p.Pattern == "delete:*" {
				found = p
				break
			}
		}

		if found == nil {
			t.Fatal("expected to find delete:* policy")
		}
		if found.Protocol != "aauth" {
			t.Errorf("expected protocol aauth, got %s", found.Protocol)
		}
	})

	t.Run("delete scope policy", func(t *testing.T) {
		policy := &StoredScopePolicy{
			ID:       "delete-me",
			Pattern:  "temp:*",
			Protocol: "idjag",
		}
		if err := store.CreateScopePolicy(ctx, policy); err != nil {
			t.Fatalf("failed to create policy: %v", err)
		}

		err := store.DeleteScopePolicy(ctx, "delete-me")
		if err != nil {
			t.Fatalf("failed to delete policy: %v", err)
		}

		got, _ := store.ListScopePolicies(ctx)
		for _, p := range got {
			if p.ID == "delete-me" {
				t.Error("expected policy to be deleted")
			}
		}
	})
}

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"read:email", []string{"read:email"}},
		{"read:email write:profile", []string{"read:email", "write:profile"}},
		{"  read:email   write:profile  ", []string{"read:email", "write:profile"}},
		{"a b c", []string{"a", "b", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitScopes(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("splitScopes(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitScopes(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIsUniqueConstraintError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{ErrNotFound, false},
		{ErrAlreadyExists, false},
	}

	for _, tt := range tests {
		got := isUniqueConstraintError(tt.err)
		if got != tt.want {
			t.Errorf("isUniqueConstraintError(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
