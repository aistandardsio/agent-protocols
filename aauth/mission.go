package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Mission governance errors.
var (
	// ErrMissionRejected indicates the mission proposal was rejected.
	ErrMissionRejected = errors.New("mission rejected")

	// ErrMissionExpired indicates the mission has expired.
	ErrMissionExpired = errors.New("mission expired")

	// ErrMissionPending indicates the mission is still pending approval.
	ErrMissionPending = errors.New("mission pending approval")

	// ErrPermissionDenied indicates a specific permission was denied.
	ErrPermissionDenied = errors.New("permission denied")
)

// InteractionType defines how an agent interacts with resources.
type InteractionType string

// Interaction types per AAuth specification.
const (
	// InteractionAutonomous indicates fully autonomous operation.
	InteractionAutonomous InteractionType = "autonomous"

	// InteractionSupervised indicates human supervision is active.
	InteractionSupervised InteractionType = "supervised"

	// InteractionAssisted indicates human-assisted operation.
	InteractionAssisted InteractionType = "assisted"

	// InteractionHumanInLoop indicates human approval for each action.
	InteractionHumanInLoop InteractionType = "human_in_loop"
)

// MissionStatus represents the current state of a mission.
type MissionStatus string

// Mission status values.
const (
	MissionStatusProposed MissionStatus = "proposed"
	MissionStatusApproved MissionStatus = "approved"
	MissionStatusRejected MissionStatus = "rejected"
	MissionStatusExpired  MissionStatus = "expired"
	MissionStatusActive   MissionStatus = "active"
	MissionStatusComplete MissionStatus = "complete"
)

// Permission represents a specific capability or action an agent can perform.
type Permission struct {
	// Resource is the resource URI this permission applies to.
	Resource string `json:"resource,omitempty"`

	// Action is the action being permitted (e.g., "read", "write", "execute").
	Action string `json:"action"`

	// Scope is the OAuth scope associated with this permission.
	Scope string `json:"scope,omitempty"`

	// Constraints are additional constraints on the permission.
	Constraints map[string]interface{} `json:"constraints,omitempty"`
}

// MissionProposal represents a request for agent authorization.
type MissionProposal struct {
	// ID is a unique identifier for this mission proposal.
	ID string `json:"id,omitempty"`

	// AgentID is the identifier of the proposing agent.
	AgentID string `json:"agent_id"`

	// Name is a human-readable name for the mission.
	Name string `json:"name"`

	// Description describes what the agent intends to do.
	Description string `json:"description,omitempty"`

	// InteractionType defines how the agent will operate.
	InteractionType InteractionType `json:"interaction_type"`

	// Permissions are the capabilities the agent is requesting.
	Permissions []Permission `json:"permissions"`

	// Duration is how long the mission should be authorized.
	Duration time.Duration `json:"duration,omitempty"`

	// ExpiresAt is when this proposal expires if not acted upon.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Metadata contains additional mission-specific data.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for MissionProposal.
func (p *MissionProposal) MarshalJSON() ([]byte, error) {
	type Alias MissionProposal
	return json.Marshal(&struct {
		Duration  int64 `json:"duration_seconds,omitempty"`
		ExpiresAt int64 `json:"expires_at,omitempty"`
		*Alias
	}{
		Duration:  int64(p.Duration.Seconds()),
		ExpiresAt: p.ExpiresAt.Unix(),
		Alias:     (*Alias)(p),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling for MissionProposal.
func (p *MissionProposal) UnmarshalJSON(data []byte) error {
	type Alias MissionProposal
	aux := &struct {
		Duration  int64 `json:"duration_seconds,omitempty"`
		ExpiresAt int64 `json:"expires_at,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	p.Duration = time.Duration(aux.Duration) * time.Second
	if aux.ExpiresAt > 0 {
		p.ExpiresAt = time.Unix(aux.ExpiresAt, 0)
	}
	return nil
}

// MissionApproval represents the response to a mission proposal.
type MissionApproval struct {
	// MissionID references the approved mission proposal.
	MissionID string `json:"mission_id"`

	// Status is the approval status.
	Status MissionStatus `json:"status"`

	// ApprovedPermissions are the permissions that were granted.
	// May be a subset of the requested permissions.
	ApprovedPermissions []Permission `json:"approved_permissions,omitempty"`

	// DeniedPermissions are permissions that were explicitly denied.
	DeniedPermissions []Permission `json:"denied_permissions,omitempty"`

	// GrantedScopes are the OAuth scopes that were granted.
	GrantedScopes []string `json:"granted_scopes,omitempty"`

	// ValidUntil is when this approval expires.
	ValidUntil time.Time `json:"valid_until,omitempty"`

	// AccessToken is the token for the approved mission (if issued inline).
	AccessToken string `json:"access_token,omitempty"`

	// RefreshToken for obtaining new access tokens.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Reason provides context for rejection or partial approval.
	Reason string `json:"reason,omitempty"`

	// ApprovedBy identifies who approved the mission.
	ApprovedBy string `json:"approved_by,omitempty"`

	// ApprovedAt is when the mission was approved.
	ApprovedAt time.Time `json:"approved_at,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for MissionApproval.
func (a *MissionApproval) MarshalJSON() ([]byte, error) {
	type Alias MissionApproval
	return json.Marshal(&struct {
		ValidUntil int64 `json:"valid_until,omitempty"`
		ApprovedAt int64 `json:"approved_at,omitempty"`
		*Alias
	}{
		ValidUntil: a.ValidUntil.Unix(),
		ApprovedAt: a.ApprovedAt.Unix(),
		Alias:      (*Alias)(a),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling for MissionApproval.
func (a *MissionApproval) UnmarshalJSON(data []byte) error {
	type Alias MissionApproval
	aux := &struct {
		ValidUntil int64 `json:"valid_until,omitempty"`
		ApprovedAt int64 `json:"approved_at,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.ValidUntil > 0 {
		a.ValidUntil = time.Unix(aux.ValidUntil, 0)
	}
	if aux.ApprovedAt > 0 {
		a.ApprovedAt = time.Unix(aux.ApprovedAt, 0)
	}
	return nil
}

// IsApproved returns true if the mission was approved.
func (a *MissionApproval) IsApproved() bool {
	return a.Status == MissionStatusApproved || a.Status == MissionStatusActive
}

// IsRejected returns true if the mission was rejected.
func (a *MissionApproval) IsRejected() bool {
	return a.Status == MissionStatusRejected
}

// IsExpired returns true if the approval has expired.
func (a *MissionApproval) IsExpired() bool {
	if a.ValidUntil.IsZero() {
		return false
	}
	return time.Now().After(a.ValidUntil)
}

// HasPermission checks if a specific permission was granted.
func (a *MissionApproval) HasPermission(action string, resource string) bool {
	for _, p := range a.ApprovedPermissions {
		if p.Action == action && (p.Resource == "" || p.Resource == resource) {
			return true
		}
	}
	return false
}

// MissionClaims represents mission-related claims in an AAuth token.
type MissionClaims struct {
	// MissionID is the approved mission identifier.
	MissionID string `json:"mission_id,omitempty"`

	// InteractionType defines how the agent operates.
	InteractionType InteractionType `json:"interaction_type,omitempty"`

	// Permissions are the granted permissions.
	Permissions []Permission `json:"permissions,omitempty"`

	// ValidUntil is when the mission authorization expires.
	ValidUntil int64 `json:"valid_until,omitempty"`
}

// PerCallPermission represents a permission request for a specific API call.
type PerCallPermission struct {
	// Method is the HTTP method.
	Method string `json:"method"`

	// Path is the request path.
	Path string `json:"path"`

	// Action is the action being performed.
	Action string `json:"action,omitempty"`

	// Justification explains why this permission is needed.
	Justification string `json:"justification,omitempty"`

	// RequestID correlates with the specific request.
	RequestID string `json:"request_id,omitempty"`
}

// PerCallApproval represents approval for a specific API call.
type PerCallApproval struct {
	// RequestID correlates with the permission request.
	RequestID string `json:"request_id"`

	// Approved indicates if the call was approved.
	Approved bool `json:"approved"`

	// Reason provides context for the decision.
	Reason string `json:"reason,omitempty"`

	// OneTimeToken is a token valid only for this specific call.
	OneTimeToken string `json:"one_time_token,omitempty"`

	// ValidFor is how long the approval is valid.
	ValidFor time.Duration `json:"valid_for,omitempty"`
}

// MissionGovernor manages mission proposals and approvals.
type MissionGovernor struct {
	// MissionEndpoint is the URL for mission governance operations.
	missionEndpoint string
	httpClient      *http.Client

	// Current mission state
	currentMission   *MissionProposal
	currentApproval  *MissionApproval
	pendingApprovals map[string]*PerCallApproval
}

// MissionGovernorOption configures a MissionGovernor.
type MissionGovernorOption func(*MissionGovernor)

// WithMissionHTTPClient sets a custom HTTP client.
func WithMissionHTTPClient(client *http.Client) MissionGovernorOption {
	return func(g *MissionGovernor) {
		g.httpClient = client
	}
}

// NewMissionGovernor creates a new mission governor.
func NewMissionGovernor(missionEndpoint string, opts ...MissionGovernorOption) *MissionGovernor {
	g := &MissionGovernor{
		missionEndpoint:  missionEndpoint,
		httpClient:       http.DefaultClient,
		pendingApprovals: make(map[string]*PerCallApproval),
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// ProposeMission submits a mission proposal for approval.
func (g *MissionGovernor) ProposeMission(ctx context.Context, proposal *MissionProposal) (*MissionApproval, error) {
	body, err := json.Marshal(proposal)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proposal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.missionEndpoint+"/propose", bytesReaderFromSlice(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to submit proposal: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Handle different response statuses
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var approval MissionApproval
		if err := json.Unmarshal(respBody, &approval); err != nil {
			return nil, fmt.Errorf("failed to parse approval: %w", err)
		}
		g.currentMission = proposal
		g.currentApproval = &approval
		return &approval, nil

	case http.StatusAccepted:
		// Mission needs async approval
		var approval MissionApproval
		if err := json.Unmarshal(respBody, &approval); err != nil {
			return nil, fmt.Errorf("failed to parse pending approval: %w", err)
		}
		g.currentMission = proposal
		g.currentApproval = &approval
		return &approval, ErrMissionPending

	case http.StatusForbidden:
		var approval MissionApproval
		if json.Unmarshal(respBody, &approval) == nil {
			return &approval, ErrMissionRejected
		}
		return nil, ErrMissionRejected

	default:
		return nil, fmt.Errorf("mission proposal failed with status %d", resp.StatusCode)
	}
}

// CheckMissionStatus checks the current status of a pending mission.
func (g *MissionGovernor) CheckMissionStatus(ctx context.Context, missionID string) (*MissionApproval, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.missionEndpoint+"/status/"+missionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to check status: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var approval MissionApproval
	if err := json.Unmarshal(body, &approval); err != nil {
		return nil, fmt.Errorf("failed to parse status: %w", err)
	}

	g.currentApproval = &approval
	return &approval, nil
}

// RequestPerCallPermission requests approval for a specific API call.
func (g *MissionGovernor) RequestPerCallPermission(ctx context.Context, perm *PerCallPermission) (*PerCallApproval, error) {
	body, err := json.Marshal(perm)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal permission request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.missionEndpoint+"/permission", bytesReaderFromSlice(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request permission: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			return nil, ErrPermissionDenied
		}
		return nil, fmt.Errorf("permission request failed with status %d", resp.StatusCode)
	}

	var approval PerCallApproval
	if err := json.Unmarshal(respBody, &approval); err != nil {
		return nil, fmt.Errorf("failed to parse approval: %w", err)
	}

	g.pendingApprovals[perm.RequestID] = &approval
	return &approval, nil
}

// CurrentApproval returns the current mission approval.
func (g *MissionGovernor) CurrentApproval() *MissionApproval {
	return g.currentApproval
}

// HasActiveApproval returns true if there's a valid, unexpired approval.
func (g *MissionGovernor) HasActiveApproval() bool {
	if g.currentApproval == nil {
		return false
	}
	return g.currentApproval.IsApproved() && !g.currentApproval.IsExpired()
}

// bytesReaderFromSlice wraps a byte slice as an io.Reader.
func bytesReaderFromSlice(b []byte) io.Reader {
	return &sliceReader{data: b}
}

type sliceReader struct {
	data []byte
	pos  int
}

func (r *sliceReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
