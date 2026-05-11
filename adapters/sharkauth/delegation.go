package sharkauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DelegationGrant represents a SharkAuth may_act_grant for agent delegation.
type DelegationGrant struct {
	// GrantID is the unique identifier for this grant.
	GrantID string `json:"grant_id"`

	// ActorSubject is the subject that may act (e.g., "agent:calendar-bot").
	ActorSubject string `json:"actor_subject"`

	// UserSubject is the user who granted the delegation (e.g., "user:alice").
	UserSubject string `json:"user_subject"`

	// Scopes are the delegated scopes.
	Scopes []string `json:"scopes"`

	// ExpiresAt is when the grant expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// CreatedAt is when the grant was created.
	CreatedAt time.Time `json:"created_at"`

	// ParentGrantID links to a parent grant for cascade revocation.
	ParentGrantID string `json:"parent_grant_id,omitempty"`

	// Active indicates if the grant is currently active.
	Active bool `json:"active"`
}

// DelegationGrantRequest is the request to create a new delegation grant.
type DelegationGrantRequest struct {
	// ActorSubject is the agent that will act on behalf of the user.
	ActorSubject string `json:"actor_subject"`

	// UserSubject is the user delegating to the agent.
	UserSubject string `json:"user_subject"`

	// Scopes are the scopes to delegate.
	Scopes []string `json:"scopes"`

	// TTL is the time-to-live for the grant (optional).
	TTL time.Duration `json:"ttl,omitempty"`

	// ParentGrantID links to a parent grant for chain delegation.
	ParentGrantID string `json:"parent_grant_id,omitempty"`
}

// CreateDelegationGrant creates a new may_act_grant in SharkAuth.
func (c *Client) CreateDelegationGrant(ctx context.Context, req DelegationGrantRequest) (*DelegationGrant, error) {
	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/grants/delegation"

	payload := map[string]interface{}{
		"actor_subject": req.ActorSubject,
		"user_subject":  req.UserSubject,
		"scopes":        req.Scopes,
	}
	if req.TTL > 0 {
		payload["ttl_seconds"] = int(req.TTL.Seconds())
	}
	if req.ParentGrantID != "" {
		payload["parent_grant_id"] = req.ParentGrantID
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDelegationFailed, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDelegationFailed, err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if c.clientID != "" && c.clientSecret != "" {
		httpReq.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDelegationFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrDelegationFailed, err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp TokenErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%w: %s - %s", ErrDelegationFailed, errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("%w: status %d", ErrDelegationFailed, resp.StatusCode)
	}

	var grant DelegationGrant
	if err := json.Unmarshal(respBody, &grant); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrDelegationFailed, err)
	}

	return &grant, nil
}

// GetDelegationGrant retrieves a delegation grant by ID.
func (c *Client) GetDelegationGrant(ctx context.Context, grantID string) (*DelegationGrant, error) {
	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/grants/delegation/" + grantID

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDelegationFailed, err)
	}

	if c.clientID != "" && c.clientSecret != "" {
		httpReq.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDelegationFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: grant not found", ErrInvalidGrant)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrDelegationFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrDelegationFailed, resp.StatusCode)
	}

	var grant DelegationGrant
	if err := json.Unmarshal(respBody, &grant); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrDelegationFailed, err)
	}

	return &grant, nil
}

// RevokeDelegationGrant revokes a delegation grant and cascades to child grants.
func (c *Client) RevokeDelegationGrant(ctx context.Context, grantID string) error {
	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/grants/delegation/" + grantID

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRevocationFailed, err)
	}

	if c.clientID != "" && c.clientSecret != "" {
		httpReq.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRevocationFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp TokenErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			return fmt.Errorf("%w: %s - %s", ErrRevocationFailed, errResp.Error, errResp.ErrorDescription)
		}
		return fmt.Errorf("%w: status %d", ErrRevocationFailed, resp.StatusCode)
	}

	return nil
}

// ListDelegationGrants lists delegation grants for a user or actor.
func (c *Client) ListDelegationGrants(ctx context.Context, opts ...ListGrantsOption) ([]*DelegationGrant, error) {
	var listOpts listGrantsOptions
	for _, opt := range opts {
		opt(&listOpts)
	}

	endpoint := strings.TrimSuffix(c.baseURL, "/") + "/grants/delegation"

	// Add query parameters
	params := make([]string, 0)
	if listOpts.userSubject != "" {
		params = append(params, "user_subject="+listOpts.userSubject)
	}
	if listOpts.actorSubject != "" {
		params = append(params, "actor_subject="+listOpts.actorSubject)
	}
	if listOpts.activeOnly {
		params = append(params, "active=true")
	}
	if len(params) > 0 {
		endpoint += "?" + strings.Join(params, "&")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDelegationFailed, err)
	}

	if c.clientID != "" && c.clientSecret != "" {
		httpReq.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDelegationFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrDelegationFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrDelegationFailed, resp.StatusCode)
	}

	var grants []*DelegationGrant
	if err := json.Unmarshal(respBody, &grants); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrDelegationFailed, err)
	}

	return grants, nil
}

// ListGrantsOption configures grant listing.
type ListGrantsOption func(*listGrantsOptions)

type listGrantsOptions struct {
	userSubject  string
	actorSubject string
	activeOnly   bool
}

// WithUserSubject filters grants by user subject.
func WithUserSubject(subject string) ListGrantsOption {
	return func(o *listGrantsOptions) {
		o.userSubject = subject
	}
}

// WithActorSubject filters grants by actor subject.
func WithActorSubject(subject string) ListGrantsOption {
	return func(o *listGrantsOptions) {
		o.actorSubject = subject
	}
}

// WithActiveOnly filters to only active grants.
func WithActiveOnly() ListGrantsOption {
	return func(o *listGrantsOptions) {
		o.activeOnly = true
	}
}
