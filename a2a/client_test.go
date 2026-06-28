package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientInvoke(t *testing.T) {
	taskResp := &TaskResponse{
		TaskID: "task-123",
		Status: TaskStatusCompleted,
		Output: json.RawMessage(`{"greeting": "Hello, World!"}`),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/invoke" {
			t.Errorf("expected /invoke, got %s", r.URL.Path)
		}

		var req TaskRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if req.CapabilityID != "hello" {
			t.Errorf("expected capability 'hello', got %s", req.CapabilityID)
		}

		_ = json.NewEncoder(w).Encode(taskResp)
	}))
	defer server.Close()

	card := &AgentCard{
		ID: "test-agent",
		Capabilities: []Capability{
			{ID: "hello"},
		},
		Endpoints: &Endpoints{
			Invoke: server.URL + "/invoke",
		},
	}

	client, err := NewClient(card)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	resp, err := client.Invoke(context.Background(), &TaskRequest{
		CapabilityID: "hello",
		Input:        json.RawMessage(`{"name": "World"}`),
	})
	if err != nil {
		t.Fatalf("invoke failed: %v", err)
	}

	if resp.TaskID != taskResp.TaskID {
		t.Errorf("expected task ID %s, got %s", taskResp.TaskID, resp.TaskID)
	}
	if resp.Status != TaskStatusCompleted {
		t.Errorf("expected status completed, got %s", resp.Status)
	}
}

func TestClientInvokeUnknownCapability(t *testing.T) {
	card := &AgentCard{
		ID: "test-agent",
		Capabilities: []Capability{
			{ID: "hello"},
		},
		Endpoints: &Endpoints{
			Invoke: "https://example.com/invoke",
		},
	}

	client, err := NewClient(card)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.Invoke(context.Background(), &TaskRequest{
		CapabilityID: "unknown",
	})
	if err == nil {
		t.Error("expected error for unknown capability")
	}
}

func TestClientGetStatus(t *testing.T) {
	statusResp := &TaskStatusResponse{
		TaskID:   "task-123",
		Status:   TaskStatusRunning,
		Progress: intPtr(50),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/status/task-123" {
			t.Errorf("expected /status/task-123, got %s", r.URL.Path)
		}

		_ = json.NewEncoder(w).Encode(statusResp)
	}))
	defer server.Close()

	card := &AgentCard{
		ID: "test-agent",
		Capabilities: []Capability{
			{ID: "hello"},
		},
		Endpoints: &Endpoints{
			Invoke: server.URL + "/invoke",
			Status: server.URL + "/status/{task_id}",
		},
	}

	client, err := NewClient(card)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	resp, err := client.GetStatus(context.Background(), "task-123")
	if err != nil {
		t.Fatalf("get status failed: %v", err)
	}

	if resp.TaskID != "task-123" {
		t.Errorf("expected task ID task-123, got %s", resp.TaskID)
	}
	if resp.Status != TaskStatusRunning {
		t.Errorf("expected status running, got %s", resp.Status)
	}
	if resp.Progress == nil || *resp.Progress != 50 {
		t.Errorf("expected progress 50, got %v", resp.Progress)
	}
}

func TestClientInvokeAndWait(t *testing.T) {
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/invoke" {
			_ = json.NewEncoder(w).Encode(&TaskResponse{
				TaskID:    "task-123",
				Status:    TaskStatusPending,
				StatusURL: "/status/task-123",
			})
			return
		}

		if r.URL.Path == "/status/task-123" {
			callCount++
			status := TaskStatusRunning
			if callCount >= 2 {
				status = TaskStatusCompleted
			}
			_ = json.NewEncoder(w).Encode(&TaskStatusResponse{
				TaskID: "task-123",
				Status: status,
				Output: json.RawMessage(`{"result": "done"}`),
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	card := &AgentCard{
		ID:           "test-agent",
		Capabilities: []Capability{{ID: "test"}},
		Endpoints: &Endpoints{
			Invoke: server.URL + "/invoke",
			Status: server.URL + "/status/{task_id}",
		},
	}

	client, err := NewClient(card)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.InvokeAndWait(ctx, &TaskRequest{
		CapabilityID: "test",
	}, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("invoke and wait failed: %v", err)
	}

	if resp.Status != TaskStatusCompleted {
		t.Errorf("expected completed, got %s", resp.Status)
	}
}

func TestNewClientValidation(t *testing.T) {
	// Nil card
	_, err := NewClient(nil)
	if err == nil {
		t.Error("expected error for nil card")
	}

	// Missing invoke endpoint
	_, err = NewClient(&AgentCard{ID: "test"})
	if err == nil {
		t.Error("expected error for missing invoke endpoint")
	}

	// Empty endpoints
	_, err = NewClient(&AgentCard{
		ID:        "test",
		Endpoints: &Endpoints{},
	})
	if err == nil {
		t.Error("expected error for empty invoke endpoint")
	}
}

func TestClientWithOptions(t *testing.T) {
	card := &AgentCard{
		ID:           "test-agent",
		Capabilities: []Capability{{ID: "test"}},
		Endpoints:    &Endpoints{Invoke: "https://example.com/invoke"},
	}

	token := &DelegationToken{
		Token:     "delegation-token",
		TokenType: "Bearer",
	}

	client, err := NewClient(card,
		WithClientBearerToken("test-token"),
		WithClientHeader("X-Custom", "value"),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if client.headers.Get("Authorization") != "Bearer test-token" {
		t.Error("expected bearer token in headers")
	}
	if client.headers.Get("X-Custom") != "value" {
		t.Error("expected custom header")
	}

	// Test with delegation token
	client2, err := NewClient(card, WithDelegationToken(token))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	if client2.headers.Get("Authorization") != "Bearer delegation-token" {
		t.Error("expected delegation token in headers")
	}
}

func intPtr(i int) *int {
	return &i
}
