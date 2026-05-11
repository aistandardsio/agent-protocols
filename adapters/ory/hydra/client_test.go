package hydra

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient("https://hydra.example.com")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.PublicURL() != "https://hydra.example.com" {
		t.Errorf("PublicURL() = %v, want https://hydra.example.com", client.PublicURL())
	}

	if client.TokenURL() != "https://hydra.example.com/oauth2/token" {
		t.Errorf("TokenURL() = %v, want https://hydra.example.com/oauth2/token", client.TokenURL())
	}
}

func TestNewClientEmptyURL(t *testing.T) {
	_, err := NewClient("")
	if err == nil {
		t.Fatal("Expected error for empty URL")
	}
}

func TestNewClientWithOptions(t *testing.T) {
	customClient := &http.Client{}
	client, err := NewClient("https://hydra.example.com",
		WithAdminURL("https://hydra-admin.example.com"),
		WithHTTPClient(customClient),
		WithClientCredentials("client-id", "client-secret"),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.AdminURL() != "https://hydra-admin.example.com" {
		t.Errorf("AdminURL() = %v, want https://hydra-admin.example.com", client.AdminURL())
	}
}

func TestTokenExchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if r.URL.Path != "/oauth2/token" {
			t.Errorf("Expected /oauth2/token, got %s", r.URL.Path)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}

		if r.Form.Get("grant_type") != GrantTypeTokenExchange {
			t.Errorf("grant_type = %v, want %v", r.Form.Get("grant_type"), GrantTypeTokenExchange)
		}

		resp := TokenResponse{
			AccessToken:     "access-token-123",
			TokenType:       "Bearer",
			ExpiresIn:       3600,
			IssuedTokenType: TokenTypeAccessToken,
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock response for testing
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	resp, err := client.TokenExchange(context.Background(), "subject-token", TokenTypeJWT,
		WithScope("read write"),
		WithAudience("https://api.example.com"),
	)
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}

	if resp.AccessToken != "access-token-123" {
		t.Errorf("AccessToken = %v, want access-token-123", resp.AccessToken)
	}
}

func TestExchangeIDJAG(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}

		if r.Form.Get("subject_token_type") != TokenTypeIDJAG {
			t.Errorf("subject_token_type = %v, want %v", r.Form.Get("subject_token_type"), TokenTypeIDJAG)
		}

		resp := TokenResponse{
			AccessToken: "idjag-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock response for testing
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	resp, err := client.ExchangeIDJAG(context.Background(), "idjag-assertion")
	if err != nil {
		t.Fatalf("ExchangeIDJAG() error = %v", err)
	}

	if resp.AccessToken != "idjag-access-token" {
		t.Errorf("AccessToken = %v, want idjag-access-token", resp.AccessToken)
	}
}

func TestExchangeAAuthToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}

		if r.Form.Get("subject_token_type") != TokenTypeAAuthAgent {
			t.Errorf("subject_token_type = %v, want %v", r.Form.Get("subject_token_type"), TokenTypeAAuthAgent)
		}

		resp := TokenResponse{
			AccessToken: "aauth-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock response for testing
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	resp, err := client.ExchangeAAuthToken(context.Background(), "aauth-agent-token")
	if err != nil {
		t.Fatalf("ExchangeAAuthToken() error = %v", err)
	}

	if resp.AccessToken != "aauth-access-token" {
		t.Errorf("AccessToken = %v, want aauth-access-token", resp.AccessToken)
	}
}

func TestJWTBearerGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}

		if r.Form.Get("grant_type") != GrantTypeJWTBearer {
			t.Errorf("grant_type = %v, want %v", r.Form.Get("grant_type"), GrantTypeJWTBearer)
		}

		if r.Form.Get("assertion") == "" {
			t.Error("Expected assertion parameter")
		}

		//nolint:gosec // G101: Test data, not real credentials
		resp := TokenResponse{
			AccessToken: "jwt-bearer-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock response for testing
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	resp, err := client.JWTBearerGrant(context.Background(), "jwt-assertion")
	if err != nil {
		t.Fatalf("JWTBearerGrant() error = %v", err)
	}

	if resp.AccessToken != "jwt-bearer-token" {
		t.Errorf("AccessToken = %v, want jwt-bearer-token", resp.AccessToken)
	}
}

func TestTokenExchangeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		resp := TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "Token expired",
		}
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock response for testing
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	_, err := client.TokenExchange(context.Background(), "expired-token", TokenTypeJWT)
	if err == nil {
		t.Fatal("Expected error for invalid grant")
	}
}

func TestIntrospectToken(t *testing.T) {
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/oauth2/introspect" {
			t.Errorf("Expected /admin/oauth2/introspect, got %s", r.URL.Path)
		}

		resp := IntrospectionResponse{
			Active:   true,
			Sub:      "user-123",
			Iss:      "https://hydra.example.com",
			Aud:      []string{"https://api.example.com"},
			ClientID: "client-123",
			Scope:    "read write",
			Exp:      1700000000,
			Iat:      1699000000,
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock response for testing
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer adminServer.Close()

	client, _ := NewClient("https://public.example.com",
		WithAdminURL(adminServer.URL),
	)

	resp, err := client.IntrospectToken(context.Background(), "access-token")
	if err != nil {
		t.Fatalf("IntrospectToken() error = %v", err)
	}

	if !resp.Active {
		t.Error("Expected active token")
	}

	if resp.Sub != "user-123" {
		t.Errorf("Sub = %v, want user-123", resp.Sub)
	}
}

func TestIntrospectTokenWithActorAndCnf(t *testing.T) {
	adminServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := IntrospectionResponse{
			Active: true,
			Sub:    "agent-123",
			Act: &ActorClaim{
				Sub: "user-456",
				Iss: "https://users.example.com",
			},
			Cnf: &CnfClaim{
				Kid: "key-1",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock response for testing
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer adminServer.Close()

	client, _ := NewClient("https://public.example.com",
		WithAdminURL(adminServer.URL),
	)

	resp, err := client.IntrospectToken(context.Background(), "access-token")
	if err != nil {
		t.Fatalf("IntrospectToken() error = %v", err)
	}

	if resp.Act == nil {
		t.Fatal("Expected act claim")
	}

	if resp.Act.Sub != "user-456" {
		t.Errorf("Act.Sub = %v, want user-456", resp.Act.Sub)
	}

	if resp.Cnf == nil {
		t.Fatal("Expected cnf claim")
	}

	if resp.Cnf.Kid != "key-1" {
		t.Errorf("Cnf.Kid = %v, want key-1", resp.Cnf.Kid)
	}
}

func TestIntrospectTokenNoAdminURL(t *testing.T) {
	client, _ := NewClient("https://public.example.com")

	_, err := client.IntrospectToken(context.Background(), "access-token")
	if err == nil {
		t.Fatal("Expected error when admin URL not configured")
	}
}

func TestWithActorToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}

		if r.Form.Get("actor_token") == "" {
			t.Error("Expected actor_token parameter")
		}

		if r.Form.Get("actor_token_type") == "" {
			t.Error("Expected actor_token_type parameter")
		}

		resp := TokenResponse{
			AccessToken: "delegated-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock response for testing
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	resp, err := client.TokenExchange(context.Background(), "subject-token", TokenTypeJWT,
		WithActorToken("actor-token", TokenTypeJWT),
	)
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}

	if resp.AccessToken != "delegated-token" {
		t.Errorf("AccessToken = %v, want delegated-token", resp.AccessToken)
	}
}
