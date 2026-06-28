package authzen

import (
	"encoding/json"
	"fmt"
	"time"
)

// Decision represents an authorization decision from the PDP.
type Decision string

// Standard authorization decisions.
const (
	// DecisionPermit indicates the action is allowed.
	DecisionPermit Decision = "PERMIT"

	// DecisionDeny indicates the action is denied.
	DecisionDeny Decision = "DENY"

	// DecisionIndeterminate indicates the PDP could not make a decision.
	DecisionIndeterminate Decision = "INDETERMINATE"

	// DecisionNotApplicable indicates no policies apply to the request.
	DecisionNotApplicable Decision = "NOT_APPLICABLE"
)

// IsAllowed returns true if the decision permits the action.
func (d Decision) IsAllowed() bool {
	return d == DecisionPermit
}

// Subject represents the entity requesting access.
type Subject struct {
	// Type is the subject type (e.g., "user", "agent", "service").
	Type string `json:"type"`

	// ID is the unique identifier for the subject.
	ID string `json:"id"`

	// Properties contains additional subject attributes.
	Properties map[string]any `json:"properties,omitempty"`
}

// Resource represents the protected resource.
type Resource struct {
	// Type is the resource type (e.g., "repository", "document", "api").
	Type string `json:"type"`

	// ID is the unique identifier for the resource.
	ID string `json:"id"`

	// Properties contains additional resource attributes.
	Properties map[string]any `json:"properties,omitempty"`
}

// Action represents the requested action.
type Action struct {
	// Name is the action name (e.g., "read", "write", "delete").
	Name string `json:"name"`

	// Properties contains additional action attributes.
	Properties map[string]any `json:"properties,omitempty"`
}

// Context contains request context and environment.
type Context map[string]any

// EvaluationRequest is the request body for the evaluation API.
type EvaluationRequest struct {
	// Subject is the entity requesting access.
	Subject Subject `json:"subject"`

	// Resource is the protected resource.
	Resource Resource `json:"resource"`

	// Action is the requested action.
	Action Action `json:"action"`

	// Context contains additional request context.
	Context Context `json:"context,omitempty"`
}

// EvaluationResponse is the response from the evaluation API.
type EvaluationResponse struct {
	// Decision is the authorization decision.
	Decision Decision `json:"decision"`

	// Context contains additional response context from the PDP.
	Context map[string]any `json:"context,omitempty"`
}

// BatchEvaluationRequest contains multiple evaluation requests.
type BatchEvaluationRequest struct {
	// Evaluations is the list of individual requests.
	Evaluations []EvaluationRequest `json:"evaluations"`
}

// BatchEvaluationResponse contains multiple evaluation responses.
type BatchEvaluationResponse struct {
	// Evaluations is the list of individual responses.
	Evaluations []EvaluationResponse `json:"evaluations"`
}

// ErrorResponse represents an error from the PDP.
type ErrorResponse struct {
	// Code is the error code.
	Code string `json:"error"`

	// Description is a human-readable error description.
	Description string `json:"error_description,omitempty"`
}

// Error implements the error interface.
func (e *ErrorResponse) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// AgentSubject creates a Subject for an AI agent.
func AgentSubject(agentID string, opts ...SubjectOption) Subject {
	s := Subject{
		Type:       "agent",
		ID:         agentID,
		Properties: make(map[string]any),
	}
	for _, opt := range opts {
		opt(&s)
	}
	return s
}

// SubjectOption configures a Subject.
type SubjectOption func(*Subject)

// WithWorkloadID adds a SPIFFE workload ID to the subject.
func WithWorkloadID(spiffeID string) SubjectOption {
	return func(s *Subject) {
		s.Properties["workload_id"] = spiffeID
	}
}

// WithDelegator adds the delegating user to the subject.
func WithDelegator(userID string) SubjectOption {
	return func(s *Subject) {
		s.Properties["delegator"] = userID
	}
}

// WithCapabilities adds agent capabilities to the subject.
func WithCapabilities(capabilities []string) SubjectOption {
	return func(s *Subject) {
		s.Properties["capabilities"] = capabilities
	}
}

// WithMission adds the current mission scope to the subject.
func WithMission(mission string) SubjectOption {
	return func(s *Subject) {
		s.Properties["mission"] = mission
	}
}

// NewResource creates a Resource with the given type and ID.
func NewResource(resourceType, resourceID string, properties map[string]any) Resource {
	return Resource{
		Type:       resourceType,
		ID:         resourceID,
		Properties: properties,
	}
}

// NewAction creates an Action with the given name.
func NewAction(name string, properties map[string]any) Action {
	return Action{
		Name:       name,
		Properties: properties,
	}
}

// NewContext creates a Context with common fields.
func NewContext() Context {
	return Context{
		"time": time.Now().UTC().Format(time.RFC3339),
	}
}

// WithContextValue adds a value to the context.
func (c Context) WithContextValue(key string, value any) Context {
	c[key] = value
	return c
}

// MarshalJSON implements json.Marshaler for Decision.
func (d Decision) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(d))
}

// UnmarshalJSON implements json.Unmarshaler for Decision.
func (d *Decision) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*d = Decision(s)
	return nil
}
