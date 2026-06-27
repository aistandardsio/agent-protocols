package agents

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aistandardsio/agent-protocols/scimext/internal/api"
)

// Service provides operations for managing Agent resources.
type Service struct {
	apiClient *api.Client
}

// New creates a new agents service.
func New(apiClient *api.Client) *Service {
	return &Service{apiClient: apiClient}
}

// Agent represents an AI agent resource.
type Agent struct {
	ID           string
	ExternalID   string
	Name         string
	DisplayName  string
	Description  string
	AgentType    string
	Active       bool
	Subject      string
	Groups       []GroupRef
	Entitlements []Entitlement
	Roles        []Role
	X509Certs    []X509Certificate
	Applications []ApplicationRef
	Protocols    []Protocol
	Parent       *Reference
	Owners       []Reference
	Meta         *Meta
}

// Meta contains SCIM resource metadata.
type Meta struct {
	ResourceType string
	Created      string
	LastModified string
	Location     string
	Version      string
}

// Reference represents a reference to another SCIM resource.
type Reference struct {
	Value   string
	Ref     string
	Display string
}

// GroupRef represents a group membership reference.
type GroupRef struct {
	Reference
	Type string // "direct" or "indirect"
}

// ApplicationRef represents an application reference.
type ApplicationRef struct {
	Reference
	Type string
}

// Entitlement represents an entitlement granted to an agent.
type Entitlement struct {
	Value   string
	Display string
	Type    string
	Primary bool
}

// Role represents a role assigned to an agent.
type Role struct {
	Value   string
	Display string
	Type    string
	Primary bool
}

// X509Certificate represents an X.509 certificate.
type X509Certificate struct {
	Value   string // Base64-encoded DER
	Display string
	Type    string
	Primary bool
}

// Protocol represents a communication protocol supported by an agent.
type Protocol struct {
	Type             string // "A2A", "OpenAPI", "MCP-Server"
	SpecificationURL string
}

// CreateRequest contains the data for creating a new agent.
type CreateRequest struct {
	ExternalID   string
	Name         string // Required
	DisplayName  string
	Description  string
	AgentType    string
	Active       bool
	Subject      string
	Entitlements []Entitlement
	Roles        []Role
	X509Certs    []X509Certificate
	Protocols    []Protocol
	Parent       *Reference
	Owners       []Reference
}

// Validate validates the create request.
func (r *CreateRequest) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

// ListOptions contains options for listing agents.
type ListOptions struct {
	Filter             string
	StartIndex         int
	Count              int
	SortBy             string
	SortOrder          string // "ascending" or "descending"
	Attributes         string
	ExcludedAttributes string
}

// ListResponse contains the response from listing agents.
type ListResponse struct {
	TotalResults int
	StartIndex   int
	ItemsPerPage int
	Resources    []*Agent
}

// Create creates a new agent.
func (s *Service) Create(ctx context.Context, req *CreateRequest) (*Agent, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	apiReq := &api.AgentCreate{
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:Agent"},
		Name:    req.Name,
	}

	// Set optional fields
	if req.ExternalID != "" {
		apiReq.ExternalId = api.NewOptString(req.ExternalID)
	}
	if req.DisplayName != "" {
		apiReq.DisplayName = api.NewOptString(req.DisplayName)
	}
	if req.Description != "" {
		apiReq.Description = api.NewOptString(req.Description)
	}
	if req.AgentType != "" {
		apiReq.AgentType = api.NewOptString(req.AgentType)
	}
	apiReq.Active = api.NewOptBool(req.Active)
	if req.Subject != "" {
		apiReq.Subject = api.NewOptString(req.Subject)
	}

	// Set protocols
	if len(req.Protocols) > 0 {
		protocols := make([]api.Protocol, len(req.Protocols))
		for i, p := range req.Protocols {
			protocols[i] = api.Protocol{}
			if p.Type != "" {
				protocols[i].Type = api.NewOptProtocolType(api.ProtocolType(p.Type))
			}
			if p.SpecificationURL != "" {
				protocols[i].SpecificationUrl = api.NewOptURI(mustParseURL(p.SpecificationURL))
			}
		}
		apiReq.Protocols = protocols
	}

	resp, err := s.apiClient.CreateAgent(ctx, apiReq)
	if err != nil {
		return nil, err
	}

	// Handle response types
	switch r := resp.(type) {
	case *api.Agent:
		return agentFromAPI(r), nil
	default:
		return nil, fmt.Errorf("unexpected response type: %T", resp)
	}
}

// Get retrieves an agent by ID.
func (s *Service) Get(ctx context.Context, id string) (*Agent, error) {
	resp, err := s.apiClient.GetAgent(ctx, api.GetAgentParams{ID: id})
	if err != nil {
		return nil, err
	}

	switch r := resp.(type) {
	case *api.Agent:
		return agentFromAPI(r), nil
	default:
		return nil, fmt.Errorf("unexpected response type: %T", resp)
	}
}

// List retrieves a list of agents.
func (s *Service) List(ctx context.Context, opts *ListOptions) (*ListResponse, error) {
	params := api.ListAgentsParams{}

	if opts != nil {
		if opts.Filter != "" {
			params.Filter = api.NewOptString(opts.Filter)
		}
		if opts.StartIndex > 0 {
			params.StartIndex = api.NewOptInt(opts.StartIndex)
		}
		if opts.Count > 0 {
			params.Count = api.NewOptInt(opts.Count)
		}
		if opts.SortBy != "" {
			params.SortBy = api.NewOptString(opts.SortBy)
		}
		if opts.SortOrder != "" {
			params.SortOrder = api.NewOptSortOrder(api.SortOrder(opts.SortOrder))
		}
		if opts.Attributes != "" {
			params.Attributes = api.NewOptString(opts.Attributes)
		}
		if opts.ExcludedAttributes != "" {
			params.ExcludedAttributes = api.NewOptString(opts.ExcludedAttributes)
		}
	}

	resp, err := s.apiClient.ListAgents(ctx, params)
	if err != nil {
		return nil, err
	}

	switch r := resp.(type) {
	case *api.AgentListResponse:
		return listResponseFromAPI(r), nil
	default:
		return nil, fmt.Errorf("unexpected response type: %T", resp)
	}
}

// Replace replaces an existing agent entirely.
func (s *Service) Replace(ctx context.Context, id string, req *CreateRequest) (*Agent, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	apiReq := &api.AgentCreate{
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:Agent"},
		Name:    req.Name,
	}

	// Set optional fields (same as Create)
	if req.ExternalID != "" {
		apiReq.ExternalId = api.NewOptString(req.ExternalID)
	}
	if req.DisplayName != "" {
		apiReq.DisplayName = api.NewOptString(req.DisplayName)
	}
	if req.Description != "" {
		apiReq.Description = api.NewOptString(req.Description)
	}
	if req.AgentType != "" {
		apiReq.AgentType = api.NewOptString(req.AgentType)
	}
	apiReq.Active = api.NewOptBool(req.Active)

	resp, err := s.apiClient.ReplaceAgent(ctx, apiReq, api.ReplaceAgentParams{ID: id})
	if err != nil {
		return nil, err
	}

	switch r := resp.(type) {
	case *api.Agent:
		return agentFromAPI(r), nil
	default:
		return nil, fmt.Errorf("unexpected response type: %T", resp)
	}
}

// Delete deletes an agent.
func (s *Service) Delete(ctx context.Context, id string) error {
	resp, err := s.apiClient.DeleteAgent(ctx, api.DeleteAgentParams{ID: id})
	if err != nil {
		return err
	}

	switch resp.(type) {
	case *api.DeleteAgentNoContent:
		return nil
	default:
		return fmt.Errorf("unexpected response type: %T", resp)
	}
}

// agentFromAPI converts an API agent to a service agent.
func agentFromAPI(a *api.Agent) *Agent {
	agent := &Agent{
		Name: a.Name,
	}

	if a.ID.IsSet() {
		agent.ID = a.ID.Value
	}
	if a.ExternalId.IsSet() {
		agent.ExternalID = a.ExternalId.Value
	}
	if a.DisplayName.IsSet() {
		agent.DisplayName = a.DisplayName.Value
	}
	if a.Description.IsSet() {
		agent.Description = a.Description.Value
	}
	if a.AgentType.IsSet() {
		agent.AgentType = a.AgentType.Value
	}
	if a.Active.IsSet() {
		agent.Active = a.Active.Value
	}
	if a.Subject.IsSet() {
		agent.Subject = a.Subject.Value
	}

	// Convert groups
	for _, g := range a.Groups {
		ref := GroupRef{}
		if g.Value.IsSet() {
			ref.Value = g.Value.Value
		}
		if g.Ref.IsSet() {
			ref.Ref = g.Ref.Value.String()
		}
		if g.Display.IsSet() {
			ref.Display = g.Display.Value
		}
		if g.Type.IsSet() {
			ref.Type = string(g.Type.Value)
		}
		agent.Groups = append(agent.Groups, ref)
	}

	// Convert protocols
	for _, p := range a.Protocols {
		proto := Protocol{}
		if p.Type.IsSet() {
			proto.Type = string(p.Type.Value)
		}
		if p.SpecificationUrl.IsSet() {
			proto.SpecificationURL = p.SpecificationUrl.Value.String()
		}
		agent.Protocols = append(agent.Protocols, proto)
	}

	// Convert meta
	if a.Meta.IsSet() {
		agent.Meta = &Meta{}
		m := a.Meta.Value
		if m.ResourceType.IsSet() {
			agent.Meta.ResourceType = m.ResourceType.Value
		}
		if m.Created.IsSet() {
			agent.Meta.Created = m.Created.Value.String()
		}
		if m.LastModified.IsSet() {
			agent.Meta.LastModified = m.LastModified.Value.String()
		}
		if m.Location.IsSet() {
			agent.Meta.Location = m.Location.Value.String()
		}
		if m.Version.IsSet() {
			agent.Meta.Version = m.Version.Value
		}
	}

	return agent
}

// listResponseFromAPI converts an API list response to a service list response.
func listResponseFromAPI(r *api.AgentListResponse) *ListResponse {
	resp := &ListResponse{
		TotalResults: r.TotalResults,
	}

	if r.StartIndex.IsSet() {
		resp.StartIndex = r.StartIndex.Value
	}
	if r.ItemsPerPage.IsSet() {
		resp.ItemsPerPage = r.ItemsPerPage.Value
	}

	for _, a := range r.Resources {
		resp.Resources = append(resp.Resources, agentFromAPI(&a))
	}

	return resp
}

// mustParseURL parses a URL string, returning an empty URL on error.
func mustParseURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil || u == nil {
		return url.URL{}
	}
	return *u
}
