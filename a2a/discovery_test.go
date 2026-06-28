package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryClientDiscoverAgent(t *testing.T) {
	card := &AgentCard{
		ID:          "test-agent",
		Name:        "Test Agent",
		Description: "A test agent",
		Version:     "1.0.0",
		Capabilities: []Capability{
			{
				ID:          "hello",
				Name:        "Say Hello",
				Description: "Returns a greeting",
			},
		},
		Authentication: &Authentication{ //nolint:gosec // G101: test data, not a credential
			Type:          "bearer",
			TokenEndpoint: "https://auth.example.com/token",
		},
		Endpoints: &Endpoints{
			Invoke: "https://agent.example.com/invoke",
			Status: "https://agent.example.com/status/{task_id}",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownPath {
			t.Errorf("expected %s, got %s", WellKnownPath, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(card)
	}))
	defer server.Close()

	client := NewDiscoveryClient()
	discovered, err := client.DiscoverAgent(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if discovered.ID != card.ID {
		t.Errorf("expected ID %s, got %s", card.ID, discovered.ID)
	}
	if discovered.Name != card.Name {
		t.Errorf("expected Name %s, got %s", card.Name, discovered.Name)
	}
	if len(discovered.Capabilities) != 1 {
		t.Errorf("expected 1 capability, got %d", len(discovered.Capabilities))
	}
}

func TestDiscoveryClientAgentNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewDiscoveryClient()
	_, err := client.DiscoverAgent(context.Background(), server.URL)
	if err != ErrAgentNotFound {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
}

func TestHasCapability(t *testing.T) {
	card := &AgentCard{
		Capabilities: []Capability{
			{ID: "read"},
			{ID: "write"},
		},
	}

	if !HasCapability(card, "read") {
		t.Error("expected to have 'read' capability")
	}
	if !HasCapability(card, "write") {
		t.Error("expected to have 'write' capability")
	}
	if HasCapability(card, "delete") {
		t.Error("expected not to have 'delete' capability")
	}
}

func TestGetCapability(t *testing.T) {
	card := &AgentCard{
		Capabilities: []Capability{
			{ID: "read", Name: "Read Resource"},
			{ID: "write", Name: "Write Resource"},
		},
	}

	cap := GetCapability(card, "read")
	if cap == nil {
		t.Fatal("expected to get 'read' capability")
	}
	if cap.Name != "Read Resource" {
		t.Errorf("expected name 'Read Resource', got %s", cap.Name)
	}

	cap = GetCapability(card, "delete")
	if cap != nil {
		t.Error("expected nil for non-existent capability")
	}
}

func TestSupportsAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		card     *AgentCard
		authType string
		want     bool
	}{
		{
			name: "bearer auth",
			card: &AgentCard{
				Authentication: &Authentication{Type: "bearer"},
			},
			authType: "bearer",
			want:     true,
		},
		{
			name: "mtls auth",
			card: &AgentCard{
				Authentication: &Authentication{Type: "mtls"},
			},
			authType: "mtls",
			want:     true,
		},
		{
			name: "wrong auth type",
			card: &AgentCard{
				Authentication: &Authentication{Type: "bearer"},
			},
			authType: "mtls",
			want:     false,
		},
		{
			name:     "no auth (nil)",
			card:     &AgentCard{},
			authType: "none",
			want:     true,
		},
		{
			name:     "no auth but expect bearer",
			card:     &AgentCard{},
			authType: "bearer",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SupportsAuthentication(tt.card, tt.authType)
			if got != tt.want {
				t.Errorf("SupportsAuthentication() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTaskStatusIsTerminal(t *testing.T) {
	tests := []struct {
		status TaskStatus
		want   bool
	}{
		{TaskStatusPending, false},
		{TaskStatusRunning, false},
		{TaskStatusCompleted, true},
		{TaskStatusFailed, true},
		{TaskStatusCanceled, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsTerminal(); got != tt.want {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}
