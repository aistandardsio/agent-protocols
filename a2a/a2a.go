package a2a

import "encoding/json"

// AgentCard describes an agent's capabilities and endpoints.
// Published at /.well-known/agent.json
type AgentCard struct {
	// ID is the unique identifier for the agent.
	ID string `json:"id"`

	// Name is the human-readable agent name.
	Name string `json:"name"`

	// Description describes the agent's purpose.
	Description string `json:"description,omitempty"`

	// Version is the agent version.
	Version string `json:"version,omitempty"`

	// Capabilities lists what the agent can do.
	Capabilities []Capability `json:"capabilities,omitempty"`

	// Authentication describes how to authenticate to this agent.
	Authentication *Authentication `json:"authentication,omitempty"`

	// Endpoints contains the agent's API endpoints.
	Endpoints *Endpoints `json:"endpoints,omitempty"`

	// Provider identifies the organization providing the agent.
	Provider *Provider `json:"provider,omitempty"`

	// TrustDomain is the SPIFFE trust domain for the agent.
	TrustDomain string `json:"trust_domain,omitempty"`

	// Metadata contains additional agent metadata.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Capability describes something an agent can do.
type Capability struct {
	// ID is the unique identifier for the capability.
	ID string `json:"id"`

	// Name is the human-readable capability name.
	Name string `json:"name,omitempty"`

	// Description describes what this capability does.
	Description string `json:"description,omitempty"`

	// InputSchema is the JSON Schema for capability inputs.
	InputSchema json.RawMessage `json:"input_schema,omitempty"`

	// OutputSchema is the JSON Schema for capability outputs.
	OutputSchema json.RawMessage `json:"output_schema,omitempty"`

	// RequiredScopes lists OAuth scopes needed to invoke this capability.
	RequiredScopes []string `json:"required_scopes,omitempty"`

	// RateLimit describes rate limiting for this capability.
	RateLimit *RateLimit `json:"rate_limit,omitempty"`
}

// RateLimit describes rate limiting for a capability.
type RateLimit struct {
	// RequestsPerMinute is the maximum requests per minute.
	RequestsPerMinute int `json:"requests_per_minute,omitempty"`

	// RequestsPerHour is the maximum requests per hour.
	RequestsPerHour int `json:"requests_per_hour,omitempty"`
}

// Authentication describes how to authenticate to the agent.
type Authentication struct {
	// Type is the authentication type: "bearer", "mtls", "none".
	Type string `json:"type"`

	// TokenEndpoint is the OAuth token endpoint for bearer auth.
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// Scopes lists available OAuth scopes.
	Scopes []string `json:"scopes,omitempty"`

	// TrustBundle is the SPIFFE trust bundle URL for mTLS.
	TrustBundle string `json:"trust_bundle,omitempty"`
}

// Endpoints contains the agent's API endpoints.
type Endpoints struct {
	// Invoke is the URL for invoking agent capabilities.
	Invoke string `json:"invoke,omitempty"`

	// Status is the URL template for checking task status.
	// May contain {task_id} placeholder.
	Status string `json:"status,omitempty"`

	// Cancel is the URL template for canceling tasks.
	Cancel string `json:"cancel,omitempty"`

	// Health is the URL for health checks.
	Health string `json:"health,omitempty"`
}

// Provider identifies the organization providing the agent.
type Provider struct {
	// Name is the provider name.
	Name string `json:"name"`

	// URL is the provider's website.
	URL string `json:"url,omitempty"`
}

// TaskRequest is the request body for invoking an agent capability.
type TaskRequest struct {
	// CapabilityID is the capability to invoke.
	CapabilityID string `json:"capability_id"`

	// Input is the capability input data.
	Input json.RawMessage `json:"input"`

	// CallbackURL is an optional URL for async result delivery.
	CallbackURL string `json:"callback_url,omitempty"`

	// Context contains additional request context.
	Context map[string]any `json:"context,omitempty"`
}

// TaskResponse is the response from invoking an agent.
type TaskResponse struct {
	// TaskID is the unique identifier for the task.
	TaskID string `json:"task_id"`

	// Status is the task status.
	Status TaskStatus `json:"status"`

	// Output is the task output (if completed synchronously).
	Output json.RawMessage `json:"output,omitempty"`

	// Error is the error message (if failed).
	Error string `json:"error,omitempty"`

	// StatusURL is the URL to check task status.
	StatusURL string `json:"status_url,omitempty"`
}

// TaskStatus represents the status of a task.
type TaskStatus string

// Task status values.
const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCanceled  TaskStatus = "canceled"
)

// IsTerminal returns true if the status is terminal (completed, failed, canceled).
func (s TaskStatus) IsTerminal() bool {
	return s == TaskStatusCompleted || s == TaskStatusFailed || s == TaskStatusCanceled
}

// TaskStatusResponse is the response from checking task status.
type TaskStatusResponse struct {
	// TaskID is the task identifier.
	TaskID string `json:"task_id"`

	// Status is the current task status.
	Status TaskStatus `json:"status"`

	// Progress is optional progress information (0-100).
	Progress *int `json:"progress,omitempty"`

	// Output is the task output (if completed).
	Output json.RawMessage `json:"output,omitempty"`

	// Error is the error message (if failed).
	Error string `json:"error,omitempty"`

	// Logs contains task execution logs.
	Logs []LogEntry `json:"logs,omitempty"`
}

// LogEntry is a single log entry from task execution.
type LogEntry struct {
	// Timestamp is when the log entry was created.
	Timestamp string `json:"timestamp"`

	// Level is the log level (debug, info, warn, error).
	Level string `json:"level"`

	// Message is the log message.
	Message string `json:"message"`
}

// DelegationRequest is used when an orchestrator delegates to another agent.
type DelegationRequest struct {
	// DelegateTo is the ID of the agent to delegate to.
	DelegateTo string `json:"delegate_to"`

	// CapabilityID is the capability being delegated.
	CapabilityID string `json:"capability_id"`

	// Scope is the constrained scope for the delegation.
	Scope string `json:"scope"`

	// Constraints are additional delegation constraints.
	Constraints []string `json:"constraints,omitempty"`

	// ExpiresIn is how long the delegation is valid (seconds).
	ExpiresIn int `json:"expires_in,omitempty"`
}

// DelegationToken represents a delegation token for agent-to-agent calls.
type DelegationToken struct {
	// Token is the delegation token value.
	Token string `json:"token"`

	// TokenType is the token type (typically "Bearer").
	TokenType string `json:"token_type"`

	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int `json:"expires_in,omitempty"`

	// Scope is the delegated scope.
	Scope string `json:"scope,omitempty"`

	// ActorChain contains the delegation chain.
	// Format: ["user:alice", "agent:orchestrator", "agent:specialist"]
	ActorChain []string `json:"actor_chain,omitempty"`
}

// WellKnownPath is the standard path for agent cards.
const WellKnownPath = "/.well-known/agent.json"
