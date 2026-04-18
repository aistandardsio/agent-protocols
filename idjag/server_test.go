package idjag

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthorizationServer_TokenExchange(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	issuer := "https://issuer.example.com"
	serverIssuer := "https://auth.example.com"
	keyID := "test-key"

	verifier := NewStaticKeyVerifier(publicKey, keyID, VerifierOptions{
		ExpectedIssuer:   issuer,
		ExpectedAudience: serverIssuer,
	})

	authServer := NewAuthorizationServer(
		verifier,
		jwt.SigningMethodRS256,
		privateKey,
		keyID,
		serverIssuer,
	)
	authServer.TokenTTL = 1 * time.Hour

	t.Run("successful token exchange", func(t *testing.T) {
		// Create and sign assertion
		assertion := NewAssertion(issuer, "agent:test", []string{serverIssuer}, 5*time.Minute)
		signed, err := assertion.Sign(jwt.SigningMethodRS256, privateKey, keyID)
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}

		// Make token exchange request
		data := url.Values{}
		data.Set("grant_type", GrantTypeTokenExchange)
		data.Set("subject_token", signed)
		data.Set("subject_token_type", TokenTypeJWT)
		data.Set("scope", "read:data")

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		authServer.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp TokenExchangeResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected non-empty access token")
		}
		if resp.TokenType != "Bearer" {
			t.Errorf("expected Bearer, got %s", resp.TokenType)
		}
		if resp.ExpiresIn != 3600 {
			t.Errorf("expected 3600, got %d", resp.ExpiresIn)
		}
	})

	t.Run("invalid grant type", func(t *testing.T) {
		data := url.Values{}
		data.Set("grant_type", "invalid")

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		authServer.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("missing subject token", func(t *testing.T) {
		data := url.Values{}
		data.Set("grant_type", GrantTypeTokenExchange)
		data.Set("subject_token_type", TokenTypeJWT)

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		authServer.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("invalid assertion", func(t *testing.T) {
		data := url.Values{}
		data.Set("grant_type", GrantTypeTokenExchange)
		data.Set("subject_token", "invalid-jwt")
		data.Set("subject_token_type", TokenTypeJWT)

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		authServer.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		rec := httptest.NewRecorder()

		authServer.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rec.Code)
		}
	})
}

func TestAuthorizationServer_JWTBearer(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	issuer := "https://issuer.example.com"
	serverIssuer := "https://auth.example.com"
	keyID := "test-key"

	verifier := NewStaticKeyVerifier(publicKey, keyID, VerifierOptions{
		ExpectedIssuer:   issuer,
		ExpectedAudience: serverIssuer,
	})

	authServer := NewAuthorizationServer(
		verifier,
		jwt.SigningMethodRS256,
		privateKey,
		keyID,
		serverIssuer,
	)

	// Create and sign assertion
	assertion := NewAssertion(issuer, "agent:test", []string{serverIssuer}, 5*time.Minute)
	signed, err := assertion.Sign(jwt.SigningMethodRS256, privateKey, keyID)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	data := url.Values{}
	data.Set("grant_type", GrantTypeJWTBearer)
	data.Set("assertion", signed)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	authServer.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp TokenExchangeResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
}

func TestAuthorizationServer_ScopeValidation(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	issuer := "https://issuer.example.com"
	serverIssuer := "https://auth.example.com"
	keyID := "test-key"

	verifier := NewStaticKeyVerifier(publicKey, keyID, VerifierOptions{
		ExpectedIssuer:   issuer,
		ExpectedAudience: serverIssuer,
	})

	authServer := NewAuthorizationServer(
		verifier,
		jwt.SigningMethodRS256,
		privateKey,
		keyID,
		serverIssuer,
	)
	authServer.AllowedScopes = []string{"read:data", "write:data"}

	assertion := NewAssertion(issuer, "agent:test", []string{serverIssuer}, 5*time.Minute)
	signed, _ := assertion.Sign(jwt.SigningMethodRS256, privateKey, keyID)

	t.Run("allowed scope", func(t *testing.T) {
		data := url.Values{}
		data.Set("grant_type", GrantTypeTokenExchange)
		data.Set("subject_token", signed)
		data.Set("subject_token_type", TokenTypeJWT)
		data.Set("scope", "read:data")

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		authServer.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("disallowed scope", func(t *testing.T) {
		data := url.Values{}
		data.Set("grant_type", GrantTypeTokenExchange)
		data.Set("subject_token", signed)
		data.Set("subject_token_type", TokenTypeJWT)
		data.Set("scope", "admin:all")

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		authServer.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rec.Code)
		}
	})
}

func TestResourceServer_Middleware(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	issuer := "https://auth.example.com"
	keyID := "test-key"

	verifier := NewStaticKeyVerifier(publicKey, keyID, VerifierOptions{
		ExpectedIssuer: issuer,
	})

	resourceServer := NewResourceServer(verifier)

	// Create handler that checks assertion in context
	handler := resourceServer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertion := AssertionFromContext(r.Context())
		if assertion == nil {
			http.Error(w, "no assertion", http.StatusInternalServerError)
			return
		}
		if _, err := w.Write([]byte("ok: " + assertion.Subject)); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}))

	t.Run("valid token", func(t *testing.T) {
		// Create access token
		claims := jwt.MapClaims{
			ClaimIssuer:         issuer,
			ClaimSubject:        "agent:test",
			ClaimIssuedAt:       jwt.NewNumericDate(time.Now()),
			ClaimExpirationTime: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = keyID
		signed, _ := token.SignedString(privateKey)

		req := httptest.NewRequest(http.MethodGet, "/data", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "agent:test") {
			t.Errorf("expected subject in response, got %s", rec.Body.String())
		}
	})

	t.Run("missing authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/data", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/data", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})
}

func TestContextFunctions(t *testing.T) {
	ctx := context.Background()

	// No assertion in context
	a1 := AssertionFromContext(ctx)
	if a1 != nil {
		t.Error("expected nil assertion from empty context")
	}

	// With assertion
	assertion := &Assertion{Subject: "test"}
	ctx2 := ContextWithAssertion(ctx, assertion)

	a2 := AssertionFromContext(ctx2)
	if a2 == nil {
		t.Fatal("expected assertion in context")
	}
	if a2.Subject != "test" {
		t.Errorf("expected subject 'test', got %s", a2.Subject)
	}
}

func TestJWKSHandler(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	jwks := &JWKS{
		Keys: []JWK{
			NewJWKFromRSAPublicKey(publicKey, "key-1", AlgorithmRS256),
		},
	}

	handler := NewJWKSHandler(jwks)

	t.Run("GET request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}

		if rec.Header().Get("Content-Type") != ContentTypeJSON {
			t.Errorf("expected JSON content type, got %s", rec.Header().Get("Content-Type"))
		}

		var respJWKS JWKS
		if err := json.NewDecoder(rec.Body).Decode(&respJWKS); err != nil {
			t.Fatalf("failed to decode JWKS: %v", err)
		}

		if len(respJWKS.Keys) != 1 {
			t.Errorf("expected 1 key, got %d", len(respJWKS.Keys))
		}
		if respJWKS.Keys[0].KeyID != "key-1" {
			t.Errorf("expected key-1, got %s", respJWKS.Keys[0].KeyID)
		}
	})

	t.Run("POST request rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rec.Code)
		}
	})
}
