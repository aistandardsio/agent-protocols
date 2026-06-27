package applications

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aistandardsio/agent-protocols/scimext/internal/api"
)

// Service provides operations for managing AgenticApplication resources.
type Service struct {
	apiClient *api.Client
}

// New creates a new applications service.
func New(apiClient *api.Client) *Service {
	return &Service{apiClient: apiClient}
}

// AgenticApplication represents an agentic application resource.
type AgenticApplication struct {
	ID                  string
	ExternalID          string
	Name                string
	DisplayName         string
	Description         string
	Active              bool
	ApplicationURLs     []ApplicationURL
	LastAccessed        string
	OAuthConfigurations []OAuthConfiguration
	Agents              []AgentRef
	ExternalIdentifiers []ExternalIdentifier
	Meta                *Meta
}

// Meta contains SCIM resource metadata.
type Meta struct {
	ResourceType string
	Created      string
	LastModified string
	Location     string
	Version      string
}

// ApplicationURL represents a URL associated with an application.
type ApplicationURL struct {
	Type        string // "ssoEndpoint", "loginPage", "api", "homepage"
	Primary     bool
	Value       string
	Description string
}

// OAuthConfiguration represents OAuth client configuration.
type OAuthConfiguration struct {
	ClientID     string
	Description  string
	AudienceURI  string
	IssuerURI    string
	RedirectURIs []string
}

// AgentRef represents a reference to an agent.
type AgentRef struct {
	Value   string
	Ref     string
	Display string
	Type    string // "owned", "authorized", "guest"
}

// ExternalIdentifier represents an external identifier.
type ExternalIdentifier struct {
	Type   string
	Value  string
	System string
}

// CreateRequest contains the data for creating a new agentic application.
type CreateRequest struct {
	ExternalID          string
	Name                string // Required
	DisplayName         string
	Description         string
	Active              bool
	ApplicationURLs     []ApplicationURL
	OAuthConfigurations []OAuthConfiguration
	Agents              []AgentRef
	ExternalIdentifiers []ExternalIdentifier
}

// Validate validates the create request.
func (r *CreateRequest) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

// ListOptions contains options for listing agentic applications.
type ListOptions struct {
	Filter             string
	StartIndex         int
	Count              int
	SortBy             string
	SortOrder          string // "ascending" or "descending"
	Attributes         string
	ExcludedAttributes string
}

// ListResponse contains the response from listing agentic applications.
type ListResponse struct {
	TotalResults int
	StartIndex   int
	ItemsPerPage int
	Resources    []*AgenticApplication
}

// Create creates a new agentic application.
func (s *Service) Create(ctx context.Context, req *CreateRequest) (*AgenticApplication, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	apiReq := &api.AgenticApplicationCreate{
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:AgenticApplication"},
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
	apiReq.Active = api.NewOptBool(req.Active)

	// Set application URLs
	if len(req.ApplicationURLs) > 0 {
		urls := make([]api.ApplicationUrl, len(req.ApplicationURLs))
		for i, u := range req.ApplicationURLs {
			urls[i] = api.ApplicationUrl{}
			if u.Type != "" {
				urls[i].Type = api.NewOptApplicationUrlType(api.ApplicationUrlType(u.Type))
			}
			urls[i].Primary = api.NewOptBool(u.Primary)
			if u.Value != "" {
				urls[i].Value = api.NewOptURI(mustParseURL(u.Value))
			}
			if u.Description != "" {
				urls[i].Description = api.NewOptString(u.Description)
			}
		}
		apiReq.ApplicationUrls = urls
	}

	resp, err := s.apiClient.CreateAgenticApplication(ctx, apiReq)
	if err != nil {
		return nil, err
	}

	switch r := resp.(type) {
	case *api.AgenticApplication:
		return applicationFromAPI(r), nil
	default:
		return nil, fmt.Errorf("unexpected response type: %T", resp)
	}
}

// Get retrieves an agentic application by ID.
func (s *Service) Get(ctx context.Context, id string) (*AgenticApplication, error) {
	resp, err := s.apiClient.GetAgenticApplication(ctx, api.GetAgenticApplicationParams{ID: id})
	if err != nil {
		return nil, err
	}

	switch r := resp.(type) {
	case *api.AgenticApplication:
		return applicationFromAPI(r), nil
	default:
		return nil, fmt.Errorf("unexpected response type: %T", resp)
	}
}

// List retrieves a list of agentic applications.
func (s *Service) List(ctx context.Context, opts *ListOptions) (*ListResponse, error) {
	params := api.ListAgenticApplicationsParams{}

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

	resp, err := s.apiClient.ListAgenticApplications(ctx, params)
	if err != nil {
		return nil, err
	}

	switch r := resp.(type) {
	case *api.AgenticApplicationListResponse:
		return listResponseFromAPI(r), nil
	default:
		return nil, fmt.Errorf("unexpected response type: %T", resp)
	}
}

// Replace replaces an existing agentic application entirely.
func (s *Service) Replace(ctx context.Context, id string, req *CreateRequest) (*AgenticApplication, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	apiReq := &api.AgenticApplicationCreate{
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:AgenticApplication"},
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
	apiReq.Active = api.NewOptBool(req.Active)

	resp, err := s.apiClient.ReplaceAgenticApplication(ctx, apiReq, api.ReplaceAgenticApplicationParams{ID: id})
	if err != nil {
		return nil, err
	}

	switch r := resp.(type) {
	case *api.AgenticApplication:
		return applicationFromAPI(r), nil
	default:
		return nil, fmt.Errorf("unexpected response type: %T", resp)
	}
}

// Delete deletes an agentic application.
func (s *Service) Delete(ctx context.Context, id string) error {
	resp, err := s.apiClient.DeleteAgenticApplication(ctx, api.DeleteAgenticApplicationParams{ID: id})
	if err != nil {
		return err
	}

	switch resp.(type) {
	case *api.DeleteAgenticApplicationNoContent:
		return nil
	default:
		return fmt.Errorf("unexpected response type: %T", resp)
	}
}

// applicationFromAPI converts an API agentic application to a service application.
func applicationFromAPI(a *api.AgenticApplication) *AgenticApplication {
	app := &AgenticApplication{
		Name: a.Name,
	}

	if a.ID.IsSet() {
		app.ID = a.ID.Value
	}
	if a.ExternalId.IsSet() {
		app.ExternalID = a.ExternalId.Value
	}
	if a.DisplayName.IsSet() {
		app.DisplayName = a.DisplayName.Value
	}
	if a.Description.IsSet() {
		app.Description = a.Description.Value
	}
	if a.Active.IsSet() {
		app.Active = a.Active.Value
	}
	if a.LastAccessed.IsSet() {
		app.LastAccessed = a.LastAccessed.Value.String()
	}

	// Convert application URLs
	for _, u := range a.ApplicationUrls {
		url := ApplicationURL{}
		if u.Type.IsSet() {
			url.Type = string(u.Type.Value)
		}
		if u.Primary.IsSet() {
			url.Primary = u.Primary.Value
		}
		if u.Value.IsSet() {
			url.Value = u.Value.Value.String()
		}
		if u.Description.IsSet() {
			url.Description = u.Description.Value
		}
		app.ApplicationURLs = append(app.ApplicationURLs, url)
	}

	// Convert OAuth configurations
	for _, o := range a.OAuthConfiguration {
		cfg := OAuthConfiguration{}
		if o.ClientId.IsSet() {
			cfg.ClientID = o.ClientId.Value
		}
		if o.Description.IsSet() {
			cfg.Description = o.Description.Value
		}
		if o.AudienceUri.IsSet() {
			cfg.AudienceURI = o.AudienceUri.Value.String()
		}
		if o.IssuerUri.IsSet() {
			cfg.IssuerURI = o.IssuerUri.Value.String()
		}
		for _, r := range o.RedirectUri {
			cfg.RedirectURIs = append(cfg.RedirectURIs, r.String())
		}
		app.OAuthConfigurations = append(app.OAuthConfigurations, cfg)
	}

	// Convert agents
	for _, ag := range a.Agents {
		ref := AgentRef{}
		if ag.Value.IsSet() {
			ref.Value = ag.Value.Value
		}
		if ag.Ref.IsSet() {
			ref.Ref = ag.Ref.Value.String()
		}
		if ag.Display.IsSet() {
			ref.Display = ag.Display.Value
		}
		if ag.Type.IsSet() {
			ref.Type = string(ag.Type.Value)
		}
		app.Agents = append(app.Agents, ref)
	}

	// Convert external identifiers
	for _, e := range a.ExternalIdentifiers {
		ext := ExternalIdentifier{}
		if e.Type.IsSet() {
			ext.Type = e.Type.Value
		}
		if e.Value.IsSet() {
			ext.Value = e.Value.Value
		}
		if e.System.IsSet() {
			ext.System = e.System.Value
		}
		app.ExternalIdentifiers = append(app.ExternalIdentifiers, ext)
	}

	// Convert meta
	if a.Meta.IsSet() {
		app.Meta = &Meta{}
		m := a.Meta.Value
		if m.ResourceType.IsSet() {
			app.Meta.ResourceType = m.ResourceType.Value
		}
		if m.Created.IsSet() {
			app.Meta.Created = m.Created.Value.String()
		}
		if m.LastModified.IsSet() {
			app.Meta.LastModified = m.LastModified.Value.String()
		}
		if m.Location.IsSet() {
			app.Meta.Location = m.Location.Value.String()
		}
		if m.Version.IsSet() {
			app.Meta.Version = m.Version.Value
		}
	}

	return app
}

// listResponseFromAPI converts an API list response to a service list response.
func listResponseFromAPI(r *api.AgenticApplicationListResponse) *ListResponse {
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
		resp.Resources = append(resp.Resources, applicationFromAPI(&a))
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
