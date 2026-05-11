package sharkauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient("https://auth.example.com")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.BaseURL() != "https://auth.example.com" {
		t.Errorf("BaseURL() = %v, want %v", client.BaseURL(), "https://auth.example.com")
	}

	if client.TokenURL() != "https://auth.example.com/oauth/token" {
		t.Errorf("TokenURL() = %v, want %v", client.TokenURL(), "https://auth.example.com/oauth/token")
	}
}

func TestNewClientWithOptions(t *testing.T) {
	customClient := &http.Client{}
	client, err := NewClient("https://auth.example.com",
		WithHTTPClient(customClient),
		WithStaticTokenEndpoint("https://auth.example.com/custom/token"),
		WithClientCredentials("client-id", "client-secret"),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.TokenURL() != "https://auth.example.com/custom/token" {
		t.Errorf("TokenURL() = %v, want %v", client.TokenURL(), "https://auth.example.com/custom/token")
	}
}

func TestExchangeAAuthToken(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}

		// Verify required parameters
		if r.Form.Get("grant_type") != GrantTypeTokenExchange {
			t.Errorf("grant_type = %v, want %v", r.Form.Get("grant_type"), GrantTypeTokenExchange)
		}

		if r.Form.Get("subject_token_type") != TokenTypeAAuthAgent {
			t.Errorf("subject_token_type = %v, want %v", r.Form.Get("subject_token_type"), TokenTypeAAuthAgent)
		}

		// Return mock response
		resp := TokenResponse{
			AccessToken:     "mock-access-token",
			IssuedTokenType: TokenTypeAccessToken,
			TokenType:       "Bearer",
			ExpiresIn:       3600,
			GrantID:         "grant-123",
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock response for testing
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	resp, err := client.ExchangeAAuthToken(context.Background(), "mock-aauth-token",
		WithScope("api:read"),
		WithAudience("https://api.example.com"),
	)
	if err != nil {
		t.Fatalf("ExchangeAAuthToken() error = %v", err)
	}

	if resp.AccessToken != "mock-access-token" {
		t.Errorf("AccessToken = %v, want %v", resp.AccessToken, "mock-access-token")
	}

	if resp.GrantID != "grant-123" {
		t.Errorf("GrantID = %v, want %v", resp.GrantID, "grant-123")
	}
}

func TestExchangeAAuthTokenError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		resp := TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "token expired",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	_, err = client.ExchangeAAuthToken(context.Background(), "expired-token")
	if err == nil {
		t.Fatal("ExchangeAAuthToken() expected error, got nil")
	}
}

func TestExchangeWithDPoP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify DPoP header is present
		dpop := r.Header.Get("DPoP")
		if dpop == "" {
			t.Error("Expected DPoP header")
		}

		resp := TokenResponse{
			AccessToken:     "dpop-bound-token",
			IssuedTokenType: TokenTypeAccessToken,
			TokenType:       "DPoP",
			ExpiresIn:       3600,
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Mock response for testing
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	resp, err := client.Exchange(context.Background(), "some-token", TokenTypeJWT,
		WithDPoP("mock-dpop-proof"),
	)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}

	if resp.TokenType != "DPoP" {
		t.Errorf("TokenType = %v, want DPoP", resp.TokenType)
	}
}
