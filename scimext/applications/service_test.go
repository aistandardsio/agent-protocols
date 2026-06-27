package applications

import (
	"testing"
)

func TestCreateRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		req     *CreateRequest
		wantErr bool
	}{
		{
			name: "valid request with name only",
			req: &CreateRequest{
				Name: "test-app",
			},
			wantErr: false,
		},
		{
			name: "valid request with all fields",
			req: &CreateRequest{
				Name:        "test-app",
				DisplayName: "Test Application",
				Description: "A test agentic application",
				Active:      true,
				ApplicationURLs: []ApplicationURL{
					{Type: "homepage", Primary: true, Value: "https://example.com"},
					{Type: "api", Value: "https://api.example.com"},
				},
				OAuthConfigurations: []OAuthConfiguration{
					{
						ClientID:     "client-123",
						AudienceURI:  "https://api.example.com",
						IssuerURI:    "https://idp.example.com",
						RedirectURIs: []string{"https://example.com/callback"},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid request with empty name",
			req:     &CreateRequest{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAgenticApplicationTypes(t *testing.T) {
	app := &AgenticApplication{
		ID:          "test-id",
		ExternalID:  "ext-id",
		Name:        "test-app",
		DisplayName: "Test Application",
		Description: "A test agentic application",
		Active:      true,
		ApplicationURLs: []ApplicationURL{
			{Type: "homepage", Primary: true, Value: "https://example.com", Description: "Main site"},
			{Type: "api", Value: "https://api.example.com", Description: "API endpoint"},
			{Type: "ssoEndpoint", Value: "https://sso.example.com"},
			{Type: "loginPage", Value: "https://example.com/login"},
		},
		LastAccessed: "2024-01-15T10:30:00Z",
		OAuthConfigurations: []OAuthConfiguration{
			{
				ClientID:     "client-123",
				Description:  "Production client",
				AudienceURI:  "https://api.example.com",
				IssuerURI:    "https://idp.example.com",
				RedirectURIs: []string{"https://example.com/callback"},
			},
		},
		Agents: []AgentRef{
			{Value: "agent-1", Display: "Agent 1", Type: "owned"},
			{Value: "agent-2", Display: "Agent 2", Type: "authorized"},
			{Value: "agent-3", Display: "Agent 3", Type: "guest"},
		},
		ExternalIdentifiers: []ExternalIdentifier{
			{Type: "ssoTenantId", Value: "tenant-123", System: "https://idp.example.com"},
		},
		Meta: &Meta{
			ResourceType: "AgenticApplication",
			Created:      "2024-01-01T00:00:00Z",
			LastModified: "2024-01-02T00:00:00Z",
			Location:     "https://scim.example.com/v2/AgenticApplications/test-id",
			Version:      "W/\"1\"",
		},
	}

	if app.ID != "test-id" {
		t.Errorf("AgenticApplication.ID = %v, want %v", app.ID, "test-id")
	}
	if app.Name != "test-app" {
		t.Errorf("AgenticApplication.Name = %v, want %v", app.Name, "test-app")
	}
	if !app.Active {
		t.Error("AgenticApplication.Active should be true")
	}
	if len(app.ApplicationURLs) != 4 {
		t.Errorf("len(AgenticApplication.ApplicationURLs) = %v, want %v", len(app.ApplicationURLs), 4)
	}
	if len(app.Agents) != 3 {
		t.Errorf("len(AgenticApplication.Agents) = %v, want %v", len(app.Agents), 3)
	}
}

func TestApplicationURLTypes(t *testing.T) {
	urls := []ApplicationURL{
		{Type: "homepage", Primary: true, Value: "https://example.com"},
		{Type: "api", Value: "https://api.example.com"},
		{Type: "ssoEndpoint", Value: "https://sso.example.com"},
		{Type: "loginPage", Value: "https://example.com/login"},
	}

	expectedTypes := []string{"homepage", "api", "ssoEndpoint", "loginPage"}
	for i, u := range urls {
		if u.Type != expectedTypes[i] {
			t.Errorf("ApplicationURL[%d].Type = %v, want %v", i, u.Type, expectedTypes[i])
		}
	}

	// Check primary flag
	if !urls[0].Primary {
		t.Error("First URL should be primary")
	}
	for i := 1; i < len(urls); i++ {
		if urls[i].Primary {
			t.Errorf("URL[%d] should not be primary", i)
		}
	}
}

func TestAgentRefTypes(t *testing.T) {
	refs := []AgentRef{
		{Value: "1", Display: "Agent 1", Type: "owned"},
		{Value: "2", Display: "Agent 2", Type: "authorized"},
		{Value: "3", Display: "Agent 3", Type: "guest"},
	}

	expectedTypes := []string{"owned", "authorized", "guest"}
	for i, r := range refs {
		if r.Type != expectedTypes[i] {
			t.Errorf("AgentRef[%d].Type = %v, want %v", i, r.Type, expectedTypes[i])
		}
	}
}

func TestListOptions(t *testing.T) {
	opts := &ListOptions{
		Filter:             "name eq 'test'",
		StartIndex:         1,
		Count:              10,
		SortBy:             "name",
		SortOrder:          "ascending",
		Attributes:         "name,displayName",
		ExcludedAttributes: "agents",
	}

	if opts.Filter != "name eq 'test'" {
		t.Errorf("ListOptions.Filter = %v, want %v", opts.Filter, "name eq 'test'")
	}
	if opts.Count != 10 {
		t.Errorf("ListOptions.Count = %v, want %v", opts.Count, 10)
	}
}

func TestListResponse(t *testing.T) {
	resp := &ListResponse{
		TotalResults: 50,
		StartIndex:   1,
		ItemsPerPage: 10,
		Resources: []*AgenticApplication{
			{ID: "1", Name: "app-1"},
			{ID: "2", Name: "app-2"},
		},
	}

	if resp.TotalResults != 50 {
		t.Errorf("ListResponse.TotalResults = %v, want %v", resp.TotalResults, 50)
	}
	if len(resp.Resources) != 2 {
		t.Errorf("len(ListResponse.Resources) = %v, want %v", len(resp.Resources), 2)
	}
}

func TestOAuthConfiguration(t *testing.T) {
	cfg := OAuthConfiguration{
		ClientID:    "client-123",
		Description: "Production OAuth client",
		AudienceURI: "https://api.example.com",
		IssuerURI:   "https://idp.example.com",
		RedirectURIs: []string{
			"https://example.com/callback",
			"https://example.com/oauth/callback",
		},
	}

	if cfg.ClientID != "client-123" {
		t.Errorf("OAuthConfiguration.ClientID = %v, want %v", cfg.ClientID, "client-123")
	}
	if len(cfg.RedirectURIs) != 2 {
		t.Errorf("len(OAuthConfiguration.RedirectURIs) = %v, want %v", len(cfg.RedirectURIs), 2)
	}
}
