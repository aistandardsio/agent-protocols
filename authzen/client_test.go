package authzen

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientEvaluate(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse *EvaluationResponse
		serverStatus   int
		wantDecision   Decision
		wantErr        bool
	}{
		{
			name: "permit",
			serverResponse: &EvaluationResponse{
				Decision: DecisionPermit,
			},
			serverStatus: http.StatusOK,
			wantDecision: DecisionPermit,
		},
		{
			name: "deny",
			serverResponse: &EvaluationResponse{
				Decision: DecisionDeny,
			},
			serverStatus: http.StatusOK,
			wantDecision: DecisionDeny,
		},
		{
			name:         "server error",
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.URL.Path != "/access/v1/evaluation" {
					t.Errorf("expected /access/v1/evaluation, got %s", r.URL.Path)
				}

				// Verify request body
				var req EvaluationRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("failed to decode request: %v", err)
				}

				w.WriteHeader(tt.serverStatus)
				if tt.serverResponse != nil {
					_ = json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := NewClient(server.URL)
			resp, err := client.Evaluate(context.Background(), &EvaluationRequest{
				Subject: AgentSubject("test-agent",
					WithWorkloadID("spiffe://example.com/agent/test"),
					WithDelegator("user:alice"),
				),
				Resource: NewResource("repository", "acme/backend", nil),
				Action:   NewAction("read", nil),
			})

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Decision != tt.wantDecision {
				t.Errorf("expected decision %s, got %s", tt.wantDecision, resp.Decision)
			}
		})
	}
}

func TestClientIsAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req EvaluationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		// Allow read on repository, deny write
		decision := DecisionDeny
		if req.Action.Name == "read" {
			decision = DecisionPermit
		}

		_ = json.NewEncoder(w).Encode(&EvaluationResponse{
			Decision: decision,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	subject := AgentSubject("test-agent")
	resource := NewResource("repository", "acme/backend", nil)

	// Test read - should be allowed
	allowed, err := client.IsAllowed(context.Background(), subject, resource, NewAction("read", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("expected read to be allowed")
	}

	// Test write - should be denied
	allowed, err = client.IsAllowed(context.Background(), subject, resource, NewAction("write", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("expected write to be denied")
	}
}

func TestClientBatchEvaluate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/access/v1/evaluations" {
			t.Errorf("expected /access/v1/evaluations, got %s", r.URL.Path)
		}

		var req BatchEvaluationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		// Return decisions matching request count
		responses := make([]EvaluationResponse, len(req.Evaluations))
		for i := range responses {
			responses[i] = EvaluationResponse{Decision: DecisionPermit}
		}

		_ = json.NewEncoder(w).Encode(&BatchEvaluationResponse{
			Evaluations: responses,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	resp, err := client.EvaluateBatch(context.Background(), &BatchEvaluationRequest{
		Evaluations: []EvaluationRequest{
			{
				Subject:  AgentSubject("agent-1"),
				Resource: NewResource("repo", "a", nil),
				Action:   NewAction("read", nil),
			},
			{
				Subject:  AgentSubject("agent-2"),
				Resource: NewResource("repo", "b", nil),
				Action:   NewAction("write", nil),
			},
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Evaluations) != 2 {
		t.Errorf("expected 2 evaluations, got %d", len(resp.Evaluations))
	}
}

func TestAgentSubjectOptions(t *testing.T) {
	subject := AgentSubject("code-review-agent",
		WithWorkloadID("spiffe://example.com/agent/code-review"),
		WithDelegator("user:alice"),
		WithCapabilities([]string{"code-review", "security-scan"}),
		WithMission("code-review:pr-123"),
	)

	if subject.Type != "agent" {
		t.Errorf("expected type 'agent', got %s", subject.Type)
	}
	if subject.ID != "code-review-agent" {
		t.Errorf("expected ID 'code-review-agent', got %s", subject.ID)
	}
	if subject.Properties["workload_id"] != "spiffe://example.com/agent/code-review" {
		t.Errorf("unexpected workload_id: %v", subject.Properties["workload_id"])
	}
	if subject.Properties["delegator"] != "user:alice" {
		t.Errorf("unexpected delegator: %v", subject.Properties["delegator"])
	}
	if subject.Properties["mission"] != "code-review:pr-123" {
		t.Errorf("unexpected mission: %v", subject.Properties["mission"])
	}

	caps, ok := subject.Properties["capabilities"].([]string)
	if !ok {
		t.Fatalf("capabilities is not []string")
	}
	if len(caps) != 2 || caps[0] != "code-review" {
		t.Errorf("unexpected capabilities: %v", caps)
	}
}

func TestDecisionIsAllowed(t *testing.T) {
	tests := []struct {
		decision Decision
		want     bool
	}{
		{DecisionPermit, true},
		{DecisionDeny, false},
		{DecisionIndeterminate, false},
		{DecisionNotApplicable, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			if got := tt.decision.IsAllowed(); got != tt.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientWithOptions(t *testing.T) {
	client := NewClient("https://pdp.example.com",
		WithBearerToken("test-token"),
		WithHeader("X-Custom-Header", "custom-value"),
		WithEvaluationPath("/custom/eval"),
	)

	if client.baseURL != "https://pdp.example.com" {
		t.Errorf("unexpected baseURL: %s", client.baseURL)
	}
	if client.headers.Get("Authorization") != "Bearer test-token" {
		t.Errorf("unexpected Authorization header")
	}
	if client.headers.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("unexpected custom header")
	}
	if client.evaluationPath != "/custom/eval" {
		t.Errorf("unexpected evaluation path: %s", client.evaluationPath)
	}
}

func TestNewContext(t *testing.T) {
	ctx := NewContext()
	if _, ok := ctx["time"]; !ok {
		t.Error("expected time in context")
	}

	ctx = ctx.WithContextValue("mission", "test-mission")
	if ctx["mission"] != "test-mission" {
		t.Errorf("unexpected mission: %v", ctx["mission"])
	}
}

func TestErrorResponse(t *testing.T) {
	err := &ErrorResponse{
		Code:        "access_denied",
		Description: "Insufficient permissions",
	}

	expected := "access_denied: Insufficient permissions"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}

	// Without description
	err2 := &ErrorResponse{Code: "server_error"}
	if err2.Error() != "server_error" {
		t.Errorf("expected %q, got %q", "server_error", err2.Error())
	}
}
