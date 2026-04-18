package idjag

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenExchangeClient_Exchange(t *testing.T) {
	t.Run("successful exchange", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse form: %v", err)
			}

			if r.FormValue("grant_type") != GrantTypeTokenExchange {
				t.Errorf("wrong grant_type: %s", r.FormValue("grant_type"))
			}
			if r.FormValue("subject_token") == "" {
				t.Error("missing subject_token")
			}
			if r.FormValue("subject_token_type") != TokenTypeJWT {
				t.Errorf("wrong subject_token_type: %s", r.FormValue("subject_token_type"))
			}

			resp := TokenExchangeResponse{
				AccessToken:     "access-token-123",
				IssuedTokenType: TokenTypeAccessToken,
				TokenType:       "Bearer",
				ExpiresIn:       3600,
				Scope:           "read:data",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		client := NewTokenExchangeClient(server.URL)
		resp, err := client.Exchange(context.Background(), &TokenExchangeRequest{
			SubjectToken:     "test-assertion",
			SubjectTokenType: TokenTypeJWT,
			Scope:            "read:data",
		})

		if err != nil {
			t.Fatalf("exchange failed: %v", err)
		}
		if resp.AccessToken != "access-token-123" {
			t.Errorf("expected access-token-123, got %s", resp.AccessToken)
		}
		if resp.TokenType != "Bearer" {
			t.Errorf("expected Bearer, got %s", resp.TokenType)
		}
		if resp.ExpiresIn != 3600 {
			t.Errorf("expected 3600, got %d", resp.ExpiresIn)
		}
	})

	t.Run("error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			resp := TokenErrorResponse{
				Error:            ErrorInvalidGrant,
				ErrorDescription: "assertion expired",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		client := NewTokenExchangeClient(server.URL)
		_, err := client.Exchange(context.Background(), &TokenExchangeRequest{
			SubjectToken:     "expired-assertion",
			SubjectTokenType: TokenTypeJWT,
		})

		if err == nil {
			t.Error("expected error for invalid grant")
		}
	})

	t.Run("missing required fields", func(t *testing.T) {
		client := NewTokenExchangeClient("http://example.com/token")

		// Missing subject_token
		_, err := client.Exchange(context.Background(), &TokenExchangeRequest{
			SubjectTokenType: TokenTypeJWT,
		})
		if err == nil {
			t.Error("expected error for missing subject_token")
		}

		// Missing subject_token_type
		_, err = client.Exchange(context.Background(), &TokenExchangeRequest{
			SubjectToken: "test",
		})
		if err == nil {
			t.Error("expected error for missing subject_token_type")
		}

		// Actor token without type
		_, err = client.Exchange(context.Background(), &TokenExchangeRequest{
			SubjectToken:     "test",
			SubjectTokenType: TokenTypeJWT,
			ActorToken:       "actor",
		})
		if err == nil {
			t.Error("expected error for missing actor_token_type")
		}
	})

	t.Run("with credentials", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok {
				t.Error("expected basic auth")
			}
			if user != "client-id" || pass != "client-secret" {
				t.Errorf("wrong credentials: %s:%s", user, pass)
			}

			resp := TokenExchangeResponse{AccessToken: "token"}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		client := NewTokenExchangeClient(server.URL).
			WithCredentials("client-id", "client-secret")

		_, err := client.Exchange(context.Background(), &TokenExchangeRequest{
			SubjectToken:     "test",
			SubjectTokenType: TokenTypeJWT,
		})
		if err != nil {
			t.Fatalf("exchange failed: %v", err)
		}
	})
}

func TestTokenExchangeClient_ExchangeAssertion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		if r.FormValue("subject_token_type") != TokenTypeJWT {
			t.Errorf("expected JWT token type, got %s", r.FormValue("subject_token_type"))
		}

		resp := TokenExchangeResponse{AccessToken: "token"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client := NewTokenExchangeClient(server.URL)
	resp, err := client.ExchangeAssertion(context.Background(), "assertion", "scope")

	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.AccessToken != "token" {
		t.Errorf("expected 'token', got %s", resp.AccessToken)
	}
}

func TestJWTBearerClient_Exchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		if r.FormValue("grant_type") != GrantTypeJWTBearer {
			t.Errorf("expected JWT bearer grant type, got %s", r.FormValue("grant_type"))
		}
		if r.FormValue("assertion") == "" {
			t.Error("missing assertion")
		}

		resp := TokenExchangeResponse{
			AccessToken: "access-token",
			TokenType:   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client := NewJWTBearerClient(server.URL)
	client.ClientID = "test-client"

	resp, err := client.Exchange(context.Background(), "test-assertion", "read:data")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.AccessToken != "access-token" {
		t.Errorf("expected access-token, got %s", resp.AccessToken)
	}
}
