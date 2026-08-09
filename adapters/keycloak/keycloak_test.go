package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRealmIssuer(t *testing.T) {
	got := RealmIssuer("https://kc.example/", "agents")
	want := "https://kc.example/realms/agents"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func newMockKeycloak(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parsing form: %v", err)
		}
		if r.Form.Get("grant_type") != "password" || r.Form.Get("client_id") != "admin-cli" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "admin-token", "expires_in": 60})
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer admin-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/realms/agents/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OIDCConfig{
			Issuer:              server.URL + "/realms/agents",
			TokenEndpoint:       server.URL + "/realms/agents/protocol/openid-connect/token",
			JWKSURI:             server.URL + "/realms/agents/protocol/openid-connect/certs",
			GrantTypesSupported: []string{"authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
		})
	})
	mux.HandleFunc("/realms/agents/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parsing form: %v", err)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "mcp-google" || pass != "secret" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || r.Form.Get("assertion") == "" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "issued-access-token",
			"token_type":   "Bearer",
			"expires_in":   300,
			"scope":        r.Form.Get("scope"),
		})
	})

	return server, &paths
}

func TestBootstrapReceiver(t *testing.T) {
	server, paths := newMockKeycloak(t)

	admin := NewAdminClient(server.URL, "admin", "admin")
	err := admin.BootstrapReceiver(context.Background(), "agents",
		ExternalIssuer{
			Alias:     "corp-idp",
			IssuerURL: "https://idp.example",
			JWKSURL:   "https://idp.example/.well-known/jwks.json",
		},
		ReceiverClient{ClientID: "mcp-google", ClientSecret: "secret"},
	)
	if err != nil {
		t.Fatalf("BootstrapReceiver: %v", err)
	}

	want := []string{
		"/admin/realms",
		"/admin/realms/agents/identity-provider/instances",
		"/admin/realms/agents/clients",
	}
	if len(*paths) != len(want) {
		t.Fatalf("expected %d admin calls, got %d: %v", len(want), len(*paths), *paths)
	}
	for i, p := range want {
		if (*paths)[i] != p {
			t.Errorf("call %d: expected %s, got %s", i, p, (*paths)[i])
		}
	}
}

func TestDiscoverRealmAndExchange(t *testing.T) {
	server, _ := newMockKeycloak(t)
	ctx := context.Background()

	config, err := DiscoverRealm(ctx, nil, server.URL, "agents")
	if err != nil {
		t.Fatalf("DiscoverRealm: %v", err)
	}
	if !config.SupportsJWTBearer() {
		t.Fatal("expected realm to advertise jwt-bearer grant")
	}

	exchanger, err := NewExchanger(ctx, server.URL, "agents", "mcp-google", "secret")
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}

	resp, err := exchanger.Exchange(ctx, "signed-id-jag-assertion", "docs:read")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken != "issued-access-token" {
		t.Errorf("unexpected access token: %q", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("unexpected token type: %q", resp.TokenType)
	}
}

func TestExchange_InvalidClient(t *testing.T) {
	server, _ := newMockKeycloak(t)

	exchanger, err := NewExchanger(context.Background(), server.URL, "agents", "mcp-google", "wrong-secret")
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	_, err = exchanger.Exchange(context.Background(), "signed-id-jag-assertion")
	if err == nil {
		t.Fatal("expected error for invalid client")
	}
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("expected invalid_client in error, got %v", err)
	}
}

// TestIntegration_RealKeycloak exercises a live Keycloak started with
// --features=identity-assertion-jwt. Skipped unless KEYCLOAK_URL is set
// (e.g. KEYCLOAK_URL=http://localhost:8081 KEYCLOAK_ADMIN=admin
// KEYCLOAK_ADMIN_PASSWORD=admin go test ./adapters/keycloak/ -run Integration).
func TestIntegration_RealKeycloak(t *testing.T) {
	baseURL := os.Getenv("KEYCLOAK_URL")
	if baseURL == "" {
		t.Skip("KEYCLOAK_URL not set; skipping live Keycloak integration test")
	}

	admin := NewAdminClient(baseURL, envOr("KEYCLOAK_ADMIN", "admin"), envOr("KEYCLOAK_ADMIN_PASSWORD", "admin"))
	ctx := context.Background()

	err := admin.BootstrapReceiver(ctx, "agents",
		ExternalIssuer{
			Alias:     "corp-idp",
			IssuerURL: envOr("IDJAG_ISSUER", "http://localhost:18081"),
			JWKSURL:   envOr("IDJAG_JWKS_URL", "http://localhost:18081/.well-known/jwks.json"),
		},
		ReceiverClient{ClientID: "mcp-google", ClientSecret: "integration-secret"},
	)
	if err != nil {
		t.Fatalf("BootstrapReceiver against live Keycloak: %v", err)
	}

	config, err := DiscoverRealm(ctx, nil, baseURL, "agents")
	if err != nil {
		t.Fatalf("DiscoverRealm: %v", err)
	}
	if !config.SupportsJWTBearer() {
		t.Error("realm does not advertise jwt-bearer grant; is --features=identity-assertion-jwt enabled?")
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
