package aauth

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMissionProposalJSON(t *testing.T) {
	proposal := &MissionProposal{
		ID:              "mission-123",
		AgentID:         "agent@example.com",
		Name:            "Test Mission",
		Description:     "A test mission",
		InteractionType: InteractionSupervised,
		Duration:        30 * time.Minute,
		ExpiresAt:       time.Now().Add(1 * time.Hour),
		Permissions: []Permission{
			{Action: "read", Resource: "https://api.example.com/data"},
			{Action: "write", Scope: "write:data"},
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(proposal)
	if err != nil {
		t.Fatalf("failed to marshal proposal: %v", err)
	}

	// Unmarshal back
	var decoded MissionProposal
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal proposal: %v", err)
	}

	if decoded.ID != proposal.ID {
		t.Errorf("ID mismatch: got %s, want %s", decoded.ID, proposal.ID)
	}
	if decoded.Name != proposal.Name {
		t.Errorf("Name mismatch: got %s, want %s", decoded.Name, proposal.Name)
	}
	if decoded.InteractionType != InteractionSupervised {
		t.Errorf("InteractionType mismatch: got %s, want %s", decoded.InteractionType, InteractionSupervised)
	}
	if len(decoded.Permissions) != 2 {
		t.Errorf("Permissions count mismatch: got %d, want 2", len(decoded.Permissions))
	}
}

func TestMissionApproval(t *testing.T) {
	t.Run("IsApproved", func(t *testing.T) {
		approval := &MissionApproval{Status: MissionStatusApproved}
		if !approval.IsApproved() {
			t.Error("expected approved status to be approved")
		}

		approval.Status = MissionStatusActive
		if !approval.IsApproved() {
			t.Error("expected active status to be approved")
		}

		approval.Status = MissionStatusRejected
		if approval.IsApproved() {
			t.Error("expected rejected status to not be approved")
		}
	})

	t.Run("IsRejected", func(t *testing.T) {
		approval := &MissionApproval{Status: MissionStatusRejected}
		if !approval.IsRejected() {
			t.Error("expected rejected status")
		}

		approval.Status = MissionStatusApproved
		if approval.IsRejected() {
			t.Error("expected approved status to not be rejected")
		}
	})

	t.Run("IsExpired", func(t *testing.T) {
		approval := &MissionApproval{
			Status:     MissionStatusApproved,
			ValidUntil: time.Now().Add(-1 * time.Hour),
		}
		if !approval.IsExpired() {
			t.Error("expected past ValidUntil to be expired")
		}

		approval.ValidUntil = time.Now().Add(1 * time.Hour)
		if approval.IsExpired() {
			t.Error("expected future ValidUntil to not be expired")
		}

		approval.ValidUntil = time.Time{} // Zero value
		if approval.IsExpired() {
			t.Error("expected zero ValidUntil to not be expired")
		}
	})

	t.Run("HasPermission", func(t *testing.T) {
		approval := &MissionApproval{
			ApprovedPermissions: []Permission{
				{Action: "read", Resource: "https://api.example.com/data"},
				{Action: "write"}, // Any resource
			},
		}

		if !approval.HasPermission("read", "https://api.example.com/data") {
			t.Error("expected to have read permission for specific resource")
		}
		if approval.HasPermission("read", "https://other.example.com") {
			t.Error("expected to not have read permission for different resource")
		}
		if !approval.HasPermission("write", "https://any.example.com") {
			t.Error("expected to have write permission for any resource")
		}
		if approval.HasPermission("delete", "https://api.example.com") {
			t.Error("expected to not have delete permission")
		}
	})
}

func TestMissionGovernor(t *testing.T) {
	t.Run("ProposeMission success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/propose" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Use raw JSON to avoid custom marshal/unmarshal issues
			_, _ = w.Write([]byte(`{
				"mission_id": "mission-123",
				"status": "approved",
				"valid_until": ` + fmt.Sprintf("%d", time.Now().Add(1*time.Hour).Unix()) + `,
				"access_token": "access-token-xyz"
			}`))
		}))
		defer server.Close()

		gov := NewMissionGovernor(server.URL)
		ctx := context.Background()

		approval, err := gov.ProposeMission(ctx, &MissionProposal{
			AgentID:         "agent@example.com",
			Name:            "Test Mission",
			InteractionType: InteractionAutonomous,
			Permissions: []Permission{
				{Action: "read", Scope: "read:data"},
			},
		})

		if err != nil {
			t.Fatalf("proposal failed: %v", err)
		}
		if approval.Status != MissionStatusApproved {
			t.Errorf("expected approved status, got %s", approval.Status)
		}
		if approval.AccessToken != "access-token-xyz" {
			t.Errorf("unexpected access token: %s", approval.AccessToken)
		}
	})

	t.Run("ProposeMission pending", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{
				"mission_id": "mission-456",
				"status": "proposed"
			}`))
		}))
		defer server.Close()

		gov := NewMissionGovernor(server.URL)
		ctx := context.Background()

		approval, err := gov.ProposeMission(ctx, &MissionProposal{
			AgentID: "agent@example.com",
			Name:    "Pending Mission",
		})

		if err != ErrMissionPending {
			t.Errorf("expected ErrMissionPending, got %v", err)
		}
		if approval == nil {
			t.Error("expected approval even when pending")
		}
	})

	t.Run("ProposeMission rejected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(MissionApproval{
				Status: MissionStatusRejected,
				Reason: "Insufficient permissions",
			})
		}))
		defer server.Close()

		gov := NewMissionGovernor(server.URL)
		ctx := context.Background()

		_, err := gov.ProposeMission(ctx, &MissionProposal{
			AgentID: "agent@example.com",
			Name:    "Rejected Mission",
		})

		if err != ErrMissionRejected {
			t.Errorf("expected ErrMissionRejected, got %v", err)
		}
	})

	t.Run("RequestPerCallPermission", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/permission" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PerCallApproval{
				RequestID:    "req-123",
				Approved:     true,
				OneTimeToken: "one-time-token",
				ValidFor:     5 * time.Minute,
			})
		}))
		defer server.Close()

		gov := NewMissionGovernor(server.URL)
		ctx := context.Background()

		approval, err := gov.RequestPerCallPermission(ctx, &PerCallPermission{
			Method:        "POST",
			Path:          "/api/data",
			Action:        "create",
			Justification: "Creating new record",
			RequestID:     "req-123",
		})

		if err != nil {
			t.Fatalf("permission request failed: %v", err)
		}
		if !approval.Approved {
			t.Error("expected approval")
		}
		if approval.OneTimeToken != "one-time-token" {
			t.Errorf("unexpected token: %s", approval.OneTimeToken)
		}
	})

	t.Run("HasActiveApproval", func(t *testing.T) {
		gov := NewMissionGovernor("https://example.com")

		if gov.HasActiveApproval() {
			t.Error("expected no active approval initially")
		}

		gov.currentApproval = &MissionApproval{
			Status:     MissionStatusApproved,
			ValidUntil: time.Now().Add(1 * time.Hour),
		}

		if !gov.HasActiveApproval() {
			t.Error("expected active approval")
		}

		gov.currentApproval.ValidUntil = time.Now().Add(-1 * time.Hour)
		if gov.HasActiveApproval() {
			t.Error("expected expired approval to not be active")
		}
	})
}

func TestInteractionTypes(t *testing.T) {
	tests := []struct {
		interaction InteractionType
		expected    string
	}{
		{InteractionAutonomous, "autonomous"},
		{InteractionSupervised, "supervised"},
		{InteractionAssisted, "assisted"},
		{InteractionHumanInLoop, "human_in_loop"},
	}

	for _, tt := range tests {
		if string(tt.interaction) != tt.expected {
			t.Errorf("interaction type %s: got %s, want %s", tt.interaction, string(tt.interaction), tt.expected)
		}
	}
}

func TestSelfAPClient(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	agentID, err := ParseAAuthID("aauth:agent@example.com")
	if err != nil {
		t.Fatalf("failed to parse agent ID: %v", err)
	}

	t.Run("NewSelfAPClient", func(t *testing.T) {
		client, err := NewSelfAPClient(agentID, keyPair.PrivateKey)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}

		if client.Metadata().SelfIssued != true {
			t.Error("expected self-issued to be true")
		}
	})

	t.Run("IssueAgentToken", func(t *testing.T) {
		client, _ := NewSelfAPClient(agentID, keyPair.PrivateKey)
		ctx := context.Background()

		tokenStr, err := client.IssueAgentToken(ctx, "https://resource.example.com")
		if err != nil {
			t.Fatalf("failed to issue agent token: %v", err)
		}
		if tokenStr == "" {
			t.Error("expected non-empty token")
		}

		// Parse and verify the token structure
		token, err := ParseAgentToken(tokenStr)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}
		if token.Subject != agentID.String() {
			t.Errorf("unexpected subject: %s", token.Subject)
		}
	})

	t.Run("IssueAuthToken", func(t *testing.T) {
		client, _ := NewSelfAPClient(agentID, keyPair.PrivateKey)
		ctx := context.Background()

		tokenStr, err := client.IssueAuthToken(ctx, "read write", "https://resource.example.com")
		if err != nil {
			t.Fatalf("failed to issue auth token: %v", err)
		}
		if tokenStr == "" {
			t.Error("expected non-empty token")
		}

		// Parse and verify the token structure
		token, err := ParseAuthToken(tokenStr)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}
		if token.Scope != "read write" {
			t.Errorf("unexpected scope: %s", token.Scope)
		}
	})

	t.Run("IssueMissionToken", func(t *testing.T) {
		client, _ := NewSelfAPClient(agentID, keyPair.PrivateKey)
		ctx := context.Background()

		mission := &MissionClaims{
			MissionID:       "mission-123",
			InteractionType: InteractionSupervised,
			Permissions: []Permission{
				{Action: "read", Scope: "read:data"},
				{Action: "write", Scope: "write:data"},
			},
		}

		tokenStr, err := client.IssueMissionToken(ctx, mission, "https://resource.example.com")
		if err != nil {
			t.Fatalf("failed to issue mission token: %v", err)
		}
		if tokenStr == "" {
			t.Error("expected non-empty token")
		}

		// Parse and verify the token structure
		token, err := ParseAuthToken(tokenStr)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}
		if token.Scope != "read:data write:data" {
			t.Errorf("unexpected scope: %s", token.Scope)
		}
		if token.InteractionType != InteractionSupervised {
			t.Errorf("unexpected interaction type: %s", token.InteractionType)
		}
	})

	t.Run("IssueDelegatedToken", func(t *testing.T) {
		client, _ := NewSelfAPClient(agentID, keyPair.PrivateKey)
		ctx := context.Background()

		tokenStr, err := client.IssueDelegatedToken(ctx, "delegate@example.com", "read", "https://resource.example.com")
		if err != nil {
			t.Fatalf("failed to issue delegated token: %v", err)
		}

		token, err := ParseAuthToken(tokenStr)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}
		if token.MayAct == nil {
			t.Error("expected may_act claim")
		} else if token.MayAct.Subject != "delegate@example.com" {
			t.Errorf("unexpected may_act subject: %s", token.MayAct.Subject)
		}
	})

	t.Run("JWKS", func(t *testing.T) {
		client, _ := NewSelfAPClient(agentID, keyPair.PrivateKey)

		jwks, err := client.JWKS()
		if err != nil {
			t.Fatalf("failed to get JWKS: %v", err)
		}
		if len(jwks.Keys) != 1 {
			t.Errorf("expected 1 key, got %d", len(jwks.Keys))
		}
		// Key ID is derived from agentID.Local
		if jwks.Keys[0].Kid != "agent" {
			t.Errorf("unexpected key ID: %s", jwks.Keys[0].Kid)
		}
	})
}
