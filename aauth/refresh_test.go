package aauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefreshableToken(t *testing.T) {
	t.Run("Not expired", func(t *testing.T) {
		token := &RefreshableToken{
			AccessToken: "access-token",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		}

		if token.IsExpired(0) {
			t.Error("token should not be expired")
		}
		if token.IsExpired(5 * time.Minute) {
			t.Error("token should not be expired with 5 minute threshold")
		}
	})

	t.Run("Expired", func(t *testing.T) {
		token := &RefreshableToken{
			AccessToken: "access-token",
			ExpiresAt:   time.Now().Add(-1 * time.Minute),
		}

		if !token.IsExpired(0) {
			t.Error("token should be expired")
		}
	})

	t.Run("Expires within threshold", func(t *testing.T) {
		token := &RefreshableToken{
			AccessToken: "access-token",
			ExpiresAt:   time.Now().Add(3 * time.Minute),
		}

		if token.IsExpired(0) {
			t.Error("token should not be expired with 0 threshold")
		}
		if !token.IsExpired(5 * time.Minute) {
			t.Error("token should be expired with 5 minute threshold")
		}
	})
}

func TestTokenRefreshClient(t *testing.T) {
	t.Run("Successful refresh", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}

			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse form: %v", err)
			}

			if r.FormValue("grant_type") != GrantTypeRefreshToken {
				t.Errorf("expected grant_type %s, got %s", GrantTypeRefreshToken, r.FormValue("grant_type"))
			}

			if r.FormValue("refresh_token") != "refresh-token-123" {
				t.Errorf("unexpected refresh_token: %s", r.FormValue("refresh_token"))
			}

			w.Header().Set("Content-Type", "application/json")
			//nolint:gosec // G117 false positive: test data
			_ = json.NewEncoder(w).Encode(TokenExchangeResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				Scope:        "read write",
			})
		}))
		defer server.Close()

		var refreshedToken *RefreshableToken
		client := NewTokenRefreshClient(server.URL,
			WithRefreshThreshold(5*time.Minute),
			WithTokenRefreshCallback(func(token *RefreshableToken) {
				refreshedToken = token
			}),
		)
		client.SetRefreshToken("refresh-token-123")

		ctx := context.Background()
		resp, err := client.Refresh(ctx)
		if err != nil {
			t.Fatalf("refresh failed: %v", err)
		}

		if resp.AccessToken != "new-access-token" {
			t.Errorf("unexpected access token: %s", resp.AccessToken)
		}
		if resp.RefreshToken != "new-refresh-token" {
			t.Errorf("unexpected refresh token: %s", resp.RefreshToken)
		}

		// Check callback was called
		if refreshedToken == nil {
			t.Error("refresh callback not called")
		} else if refreshedToken.AccessToken != "new-access-token" {
			t.Errorf("callback received wrong token: %s", refreshedToken.AccessToken)
		}
	})

	t.Run("No refresh token", func(t *testing.T) {
		client := NewTokenRefreshClient("https://example.com/token")

		ctx := context.Background()
		_, err := client.Refresh(ctx)
		if err == nil {
			t.Error("expected error for missing refresh token")
		}
		if err != ErrNoRefreshToken {
			t.Errorf("expected ErrNoRefreshToken, got %v", err)
		}
	})

	t.Run("Invalid grant error clears refresh token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(TokenErrorResponse{
				Error:            "invalid_grant",
				ErrorDescription: "Refresh token expired",
			})
		}))
		defer server.Close()

		client := NewTokenRefreshClient(server.URL)
		client.SetRefreshToken("expired-refresh-token")

		if !client.HasRefreshToken() {
			t.Error("should have refresh token before refresh")
		}

		ctx := context.Background()
		_, err := client.Refresh(ctx)
		if err == nil {
			t.Error("expected error for invalid grant")
		}

		if client.HasRefreshToken() {
			t.Error("refresh token should be cleared after invalid_grant error")
		}
	})

	t.Run("CurrentToken returns cached token", func(t *testing.T) {
		var refreshCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&refreshCount, 1)
			w.Header().Set("Content-Type", "application/json")
			//nolint:gosec // G117 false positive: test data
			_ = json.NewEncoder(w).Encode(TokenExchangeResponse{
				AccessToken:  "refreshed-token",
				RefreshToken: "new-refresh",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			})
		}))
		defer server.Close()

		client := NewTokenRefreshClient(server.URL,
			WithRefreshThreshold(5*time.Minute),
		)

		// Set a valid token
		client.SetToken(&RefreshableToken{
			AccessToken:  "valid-token",
			RefreshToken: "refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		})

		ctx := context.Background()
		token, err := client.CurrentToken(ctx)
		if err != nil {
			t.Fatalf("failed to get current token: %v", err)
		}

		if token.AccessToken != "valid-token" {
			t.Errorf("expected cached token, got %s", token.AccessToken)
		}

		if atomic.LoadInt32(&refreshCount) != 0 {
			t.Error("should not have called refresh for valid token")
		}
	})

	t.Run("CurrentToken refreshes expired token", func(t *testing.T) {
		var refreshCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&refreshCount, 1)
			w.Header().Set("Content-Type", "application/json")
			//nolint:gosec // G117 false positive: test data
			_ = json.NewEncoder(w).Encode(TokenExchangeResponse{
				AccessToken:  "refreshed-token",
				RefreshToken: "new-refresh",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			})
		}))
		defer server.Close()

		client := NewTokenRefreshClient(server.URL,
			WithRefreshThreshold(5*time.Minute),
		)

		// Set an expired token
		client.SetToken(&RefreshableToken{
			AccessToken:  "expired-token",
			RefreshToken: "refresh-token",
			ExpiresAt:    time.Now().Add(-1 * time.Minute),
		})

		ctx := context.Background()
		token, err := client.CurrentToken(ctx)
		if err != nil {
			t.Fatalf("failed to get current token: %v", err)
		}

		if token.AccessToken != "refreshed-token" {
			t.Errorf("expected refreshed token, got %s", token.AccessToken)
		}

		if atomic.LoadInt32(&refreshCount) != 1 {
			t.Errorf("expected 1 refresh call, got %d", atomic.LoadInt32(&refreshCount))
		}
	})
}

func TestRefreshAwareTransport(t *testing.T) {
	// Token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117 false positive: test data
		_ = json.NewEncoder(w).Encode(TokenExchangeResponse{
			AccessToken:  "refreshed-token",
			RefreshToken: "new-refresh",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	}))
	defer tokenServer.Close()

	t.Run("Adds authorization header", func(t *testing.T) {
		var receivedAuth string
		apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer apiServer.Close()

		refreshClient := NewTokenRefreshClient(tokenServer.URL)
		refreshClient.SetToken(&RefreshableToken{
			AccessToken: "my-access-token",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		})

		transport := &RefreshAwareTransport{
			RefreshClient: refreshClient,
		}

		client := &http.Client{Transport: transport}
		resp, err := client.Get(apiServer.URL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()

		if receivedAuth != "Bearer my-access-token" {
			t.Errorf("unexpected authorization header: %s", receivedAuth)
		}
	})

	t.Run("Retries on 401 with refresh", func(t *testing.T) {
		var requestCount int32
		apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := atomic.AddInt32(&requestCount, 1)
			auth := r.Header.Get("Authorization")

			if count == 1 {
				// First request returns 401
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Second request should have new token
			if auth != "Bearer refreshed-token" {
				t.Errorf("expected refreshed token, got %s", auth)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer apiServer.Close()

		refreshClient := NewTokenRefreshClient(tokenServer.URL)
		refreshClient.SetToken(&RefreshableToken{
			AccessToken:  "old-token",
			RefreshToken: "refresh-token",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		})

		transport := &RefreshAwareTransport{
			RefreshClient: refreshClient,
		}

		client := &http.Client{Transport: transport}
		resp, err := client.Get(apiServer.URL)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}

		if atomic.LoadInt32(&requestCount) != 2 {
			t.Errorf("expected 2 requests, got %d", atomic.LoadInt32(&requestCount))
		}
	})
}
