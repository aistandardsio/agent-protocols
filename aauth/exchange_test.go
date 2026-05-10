package aauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestParseTokenExchangeRequest(t *testing.T) {
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", "test-subject-token")
	form.Set("subject_token_type", TokenTypeURIAgentJWT)
	form.Set("scope", "read write")
	form.Add("audience", "https://resource1.example.com")
	form.Add("audience", "https://resource2.example.com")

	req := httptest.NewRequest("POST", "/token", nil)
	req.Form = form

	exchangeReq, err := ParseTokenExchangeRequest(req)
	if err != nil {
		t.Fatalf("failed to parse request: %v", err)
	}

	if exchangeReq.GrantType != GrantTypeTokenExchange {
		t.Errorf("expected grant_type %s, got %s", GrantTypeTokenExchange, exchangeReq.GrantType)
	}
	if exchangeReq.SubjectToken != "test-subject-token" {
		t.Errorf("expected subject_token 'test-subject-token', got %s", exchangeReq.SubjectToken)
	}
	if exchangeReq.SubjectTokenType != TokenTypeURIAgentJWT {
		t.Errorf("expected subject_token_type %s, got %s", TokenTypeURIAgentJWT, exchangeReq.SubjectTokenType)
	}
	if exchangeReq.Scope != "read write" {
		t.Errorf("expected scope 'read write', got %s", exchangeReq.Scope)
	}
	if len(exchangeReq.Audience) != 2 {
		t.Errorf("expected 2 audiences, got %d", len(exchangeReq.Audience))
	}
}

func TestTokenExchangeRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     *TokenExchangeRequest
		wantErr bool
	}{
		{
			name: "valid agent token exchange",
			req: &TokenExchangeRequest{
				GrantType:        GrantTypeTokenExchange,
				SubjectToken:     "test-token",
				SubjectTokenType: TokenTypeURIAgentJWT,
			},
			wantErr: false,
		},
		{
			name: "valid resource token exchange",
			req: &TokenExchangeRequest{
				GrantType:        GrantTypeTokenExchange,
				SubjectToken:     "test-token",
				SubjectTokenType: TokenTypeURIResourceJWT,
			},
			wantErr: false,
		},
		{
			name: "invalid grant type",
			req: &TokenExchangeRequest{
				GrantType:        "invalid",
				SubjectToken:     "test-token",
				SubjectTokenType: TokenTypeURIAgentJWT,
			},
			wantErr: true,
		},
		{
			name: "missing subject token",
			req: &TokenExchangeRequest{
				GrantType:        GrantTypeTokenExchange,
				SubjectTokenType: TokenTypeURIAgentJWT,
			},
			wantErr: true,
		},
		{
			name: "missing subject token type",
			req: &TokenExchangeRequest{
				GrantType:    GrantTypeTokenExchange,
				SubjectToken: "test-token",
			},
			wantErr: true,
		},
		{
			name: "invalid subject token type",
			req: &TokenExchangeRequest{
				GrantType:        GrantTypeTokenExchange,
				SubjectToken:     "test-token",
				SubjectTokenType: "invalid",
			},
			wantErr: true,
		},
		{
			name: "actor token without type",
			req: &TokenExchangeRequest{
				GrantType:        GrantTypeTokenExchange,
				SubjectToken:     "test-token",
				SubjectTokenType: TokenTypeURIAgentJWT,
				ActorToken:       "actor-token",
			},
			wantErr: true,
		},
		{
			name: "valid delegation request",
			req: &TokenExchangeRequest{
				GrantType:        GrantTypeTokenExchange,
				SubjectToken:     "test-token",
				SubjectTokenType: TokenTypeURIAgentJWT,
				ActorToken:       "actor-token",
				ActorTokenType:   TokenTypeURIAgentJWT,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestTokenExchangeRequest_ToFormValues(t *testing.T) {
	req := &TokenExchangeRequest{
		GrantType:          GrantTypeTokenExchange,
		SubjectToken:       "subject-token",
		SubjectTokenType:   TokenTypeURIAgentJWT,
		ActorToken:         "actor-token",
		ActorTokenType:     TokenTypeURIAgentJWT,
		RequestedTokenType: TokenTypeURIAuthJWT,
		Audience:           []string{"aud1", "aud2"},
		Scope:              "read",
		Resource:           []string{"res1"},
	}

	values := req.ToFormValues()

	if values.Get("grant_type") != GrantTypeTokenExchange {
		t.Errorf("expected grant_type %s, got %s", GrantTypeTokenExchange, values.Get("grant_type"))
	}
	if values.Get("subject_token") != "subject-token" {
		t.Errorf("expected subject_token 'subject-token', got %s", values.Get("subject_token"))
	}
	if values.Get("actor_token") != "actor-token" {
		t.Errorf("expected actor_token 'actor-token', got %s", values.Get("actor_token"))
	}
	if audiences := values["audience"]; len(audiences) != 2 {
		t.Errorf("expected 2 audiences, got %d", len(audiences))
	}
	if values.Get("scope") != "read" {
		t.Errorf("expected scope 'read', got %s", values.Get("scope"))
	}
}

func TestDetermineFlowType(t *testing.T) {
	tests := []struct {
		name     string
		req      *TokenExchangeRequest
		expected ExchangeFlowType
	}{
		{
			name: "delegation flow",
			req: &TokenExchangeRequest{
				GrantType:        GrantTypeTokenExchange,
				SubjectToken:     "subject",
				SubjectTokenType: TokenTypeURIAgentJWT,
				ActorToken:       "actor",
				ActorTokenType:   TokenTypeURIAgentJWT,
			},
			expected: FlowDelegation,
		},
		{
			name: "resource managed flow",
			req: &TokenExchangeRequest{
				GrantType:        GrantTypeTokenExchange,
				SubjectToken:     "resource-token",
				SubjectTokenType: TokenTypeURIResourceJWT,
			},
			expected: FlowResourceManaged,
		},
		{
			name: "PS asserted flow",
			req: &TokenExchangeRequest{
				GrantType:        GrantTypeTokenExchange,
				SubjectToken:     "agent-token",
				SubjectTokenType: TokenTypeURIAgentJWT,
			},
			expected: FlowPSAsserted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetermineFlowType(tt.req)
			if got != tt.expected {
				t.Errorf("DetermineFlowType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewResourceManagedExchangeRequest(t *testing.T) {
	req := NewResourceManagedExchangeRequest(
		"resource-token",
		[]string{"https://resource.example.com"},
		"read",
	)

	if req.GrantType != GrantTypeTokenExchange {
		t.Errorf("expected grant_type %s, got %s", GrantTypeTokenExchange, req.GrantType)
	}
	if req.SubjectToken != "resource-token" {
		t.Errorf("expected subject_token 'resource-token', got %s", req.SubjectToken)
	}
	if req.SubjectTokenType != TokenTypeURIResourceJWT {
		t.Errorf("expected subject_token_type %s, got %s", TokenTypeURIResourceJWT, req.SubjectTokenType)
	}
	if req.RequestedTokenType != TokenTypeURIAuthJWT {
		t.Errorf("expected requested_token_type %s, got %s", TokenTypeURIAuthJWT, req.RequestedTokenType)
	}
}

func TestNewPSAssertedExchangeRequest(t *testing.T) {
	req := NewPSAssertedExchangeRequest(
		"agent-token",
		[]string{"https://resource.example.com"},
		"read",
	)

	if req.SubjectTokenType != TokenTypeURIAgentJWT {
		t.Errorf("expected subject_token_type %s, got %s", TokenTypeURIAgentJWT, req.SubjectTokenType)
	}
}

func TestNewDelegationExchangeRequest(t *testing.T) {
	req := NewDelegationExchangeRequest(
		"human-token",
		"agent-token",
		[]string{"https://resource.example.com"},
		"read",
	)

	if req.SubjectToken != "human-token" {
		t.Errorf("expected subject_token 'human-token', got %s", req.SubjectToken)
	}
	if req.ActorToken != "agent-token" {
		t.Errorf("expected actor_token 'agent-token', got %s", req.ActorToken)
	}
	if req.ActorTokenType != TokenTypeURIAgentJWT {
		t.Errorf("expected actor_token_type %s, got %s", TokenTypeURIAgentJWT, req.ActorTokenType)
	}
}

func TestNewExchangeClient(t *testing.T) {
	client := NewExchangeClient("https://ps.example.com/token", nil)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.httpClient == nil {
		t.Error("expected default HTTP client")
	}
}

func TestExchangeClient_Exchange(t *testing.T) {
	// Create a mock token server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"access_token": "test-auth-token",
			"issued_token_type": "urn:ietf:params:oauth:token-type:aa-auth+jwt",
			"token_type": "Bearer",
			"expires_in": 3600,
			"scope": "read"
		}`))
	}))
	defer server.Close()

	client := NewExchangeClient(server.URL, nil)

	req := NewPSAssertedExchangeRequest(
		"test-agent-token",
		[]string{"https://resource.example.com"},
		"read",
	)

	resp, err := client.Exchange(req)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}

	if resp.AccessToken != "test-auth-token" {
		t.Errorf("expected access_token 'test-auth-token', got %s", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token_type 'Bearer', got %s", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("expected expires_in 3600, got %d", resp.ExpiresIn)
	}
}

func TestExchangeClient_Exchange_Error(t *testing.T) {
	// Create a mock token server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{
			"error": "invalid_grant",
			"error_description": "Token expired"
		}`))
	}))
	defer server.Close()

	client := NewExchangeClient(server.URL, nil)

	req := NewPSAssertedExchangeRequest(
		"test-agent-token",
		[]string{"https://resource.example.com"},
		"read",
	)

	_, err := client.Exchange(req)
	if err == nil {
		t.Error("expected error, got nil")
	}
}
