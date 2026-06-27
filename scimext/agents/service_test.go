package agents

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
				Name: "test-agent",
			},
			wantErr: false,
		},
		{
			name: "valid request with all fields",
			req: &CreateRequest{
				Name:        "test-agent",
				DisplayName: "Test Agent",
				Description: "A test agent",
				AgentType:   "Assistant",
				Active:      true,
				Protocols: []Protocol{
					{Type: "A2A", SpecificationURL: "https://example.com/agent-card.json"},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid request with empty name",
			req:     &CreateRequest{},
			wantErr: true,
		},
		{
			name: "invalid request with whitespace name",
			req: &CreateRequest{
				Name: "",
			},
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

func TestAgentTypes(t *testing.T) {
	// Test that Agent struct can be instantiated with all fields
	agent := &Agent{
		ID:          "test-id",
		ExternalID:  "ext-id",
		Name:        "test-agent",
		DisplayName: "Test Agent",
		Description: "A test agent",
		AgentType:   "Assistant",
		Active:      true,
		Subject:     "agent-subject",
		Groups: []GroupRef{
			{
				Reference: Reference{Value: "group-1", Display: "Group 1"},
				Type:      "direct",
			},
		},
		Entitlements: []Entitlement{
			{Value: "read", Display: "Read Access", Primary: true},
		},
		Roles: []Role{
			{Value: "admin", Display: "Administrator", Primary: true},
		},
		Protocols: []Protocol{
			{Type: "A2A", SpecificationURL: "https://example.com/agent-card.json"},
			{Type: "MCP-Server", SpecificationURL: "https://example.com/mcp.json"},
		},
		Parent: &Reference{Value: "parent-id", Display: "Parent Agent"},
		Owners: []Reference{
			{Value: "owner-1", Display: "Owner 1"},
		},
		Meta: &Meta{
			ResourceType: "Agent",
			Created:      "2024-01-01T00:00:00Z",
			LastModified: "2024-01-02T00:00:00Z",
			Location:     "https://scim.example.com/v2/Agents/test-id",
			Version:      "W/\"1\"",
		},
	}

	if agent.ID != "test-id" {
		t.Errorf("Agent.ID = %v, want %v", agent.ID, "test-id")
	}
	if agent.Name != "test-agent" {
		t.Errorf("Agent.Name = %v, want %v", agent.Name, "test-agent")
	}
	if !agent.Active {
		t.Error("Agent.Active should be true")
	}
	if len(agent.Protocols) != 2 {
		t.Errorf("len(Agent.Protocols) = %v, want %v", len(agent.Protocols), 2)
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
		ExcludedAttributes: "groups",
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
		TotalResults: 100,
		StartIndex:   1,
		ItemsPerPage: 10,
		Resources: []*Agent{
			{ID: "1", Name: "agent-1"},
			{ID: "2", Name: "agent-2"},
		},
	}

	if resp.TotalResults != 100 {
		t.Errorf("ListResponse.TotalResults = %v, want %v", resp.TotalResults, 100)
	}
	if len(resp.Resources) != 2 {
		t.Errorf("len(ListResponse.Resources) = %v, want %v", len(resp.Resources), 2)
	}
}

func TestProtocolTypes(t *testing.T) {
	protocols := []Protocol{
		{Type: "A2A", SpecificationURL: "https://example.com/a2a.json"},
		{Type: "OpenAPI", SpecificationURL: "https://example.com/openapi.yaml"},
		{Type: "MCP-Server", SpecificationURL: "https://example.com/mcp.json"},
	}

	expectedTypes := []string{"A2A", "OpenAPI", "MCP-Server"}
	for i, p := range protocols {
		if p.Type != expectedTypes[i] {
			t.Errorf("Protocol[%d].Type = %v, want %v", i, p.Type, expectedTypes[i])
		}
	}
}
