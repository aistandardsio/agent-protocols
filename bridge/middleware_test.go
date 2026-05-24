package bridge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/aims"
	"github.com/aistandardsio/agent-protocols/idjag"
)

// Mock verifiers for testing

type mockIDJAGVerifier struct {
	assertion *idjag.Assertion
	err       error
}

func (m *mockIDJAGVerifier) Verify(_ context.Context, _ string) (*idjag.Assertion, error) {
	return m.assertion, m.err
}

type mockWITVerifier struct {
	wit *aims.WorkloadIdentityToken
	err error
}

func (m *mockWITVerifier) Verify(_ string) (*aims.WorkloadIdentityToken, error) {
	return m.wit, m.err
}

type mockAAuthVerifier struct {
	token *aauth.AgentToken
	err   error
}

func (m *mockAAuthVerifier) VerifyAgentToken(_ context.Context, _ string) (*aauth.AgentToken, error) {
	return m.token, m.err
}

func TestMultiProtocolMiddleware_NoToken(t *testing.T) {
	handler := MultiProtocolMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestMultiProtocolMiddleware_IDJAG(t *testing.T) {
	assertion := &idjag.Assertion{
		Issuer:    "https://issuer.example.com",
		Subject:   "user@example.com",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-123",
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		JWTID:     "jti-123",
	}

	verifier := &mockIDJAGVerifier{assertion: assertion}

	var capturedIdentity *Identity
	var capturedProtocol Protocol

	handler := MultiProtocolMiddleware(
		WithIDJAGVerifier(verifier),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIdentity, _ = IdentityFromContext(r.Context())
		capturedProtocol = ProtocolFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Create a token with ID-JAG typ header
	idjagToken := createTestJWT(
		map[string]any{"typ": TypIDJAG, "alg": "ES256"},
		map[string]any{"sub": "user@example.com", "client_id": "client-123"},
	)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+idjagToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	if capturedIdentity == nil {
		t.Fatal("expected identity in context")
	}
	if capturedIdentity.Subject != assertion.Subject {
		t.Errorf("expected subject %s, got %s", assertion.Subject, capturedIdentity.Subject)
	}
	if capturedProtocol != ProtocolIDJAG {
		t.Errorf("expected protocol %s, got %s", ProtocolIDJAG, capturedProtocol)
	}
}

func TestMultiProtocolMiddleware_VerificationFailed(t *testing.T) {
	verifier := &mockIDJAGVerifier{err: errors.New("invalid signature")}

	handler := MultiProtocolMiddleware(
		WithIDJAGVerifier(verifier),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	idjagToken := createTestJWT(
		map[string]any{"typ": TypIDJAG, "alg": "ES256"},
		map[string]any{"sub": "user@example.com", "client_id": "client-123"},
	)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+idjagToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestMultiProtocolMiddleware_NoVerifier(t *testing.T) {
	// No verifiers configured
	handler := MultiProtocolMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	idjagToken := createTestJWT(
		map[string]any{"typ": TypIDJAG, "alg": "ES256"},
		map[string]any{"sub": "user@example.com", "client_id": "client-123"},
	)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+idjagToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (no verifier), got %d", rec.Code)
	}
}

func TestMultiProtocolMiddleware_AllowedProtocols(t *testing.T) {
	assertion := &idjag.Assertion{
		Issuer:    "https://issuer.example.com",
		Subject:   "user@example.com",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-123",
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	verifier := &mockIDJAGVerifier{assertion: assertion}

	// Only allow AIMS protocol
	handler := MultiProtocolMiddleware(
		WithIDJAGVerifier(verifier),
		WithAllowedProtocols(ProtocolAIMS),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	idjagToken := createTestJWT(
		map[string]any{"typ": TypIDJAG, "alg": "ES256"},
		map[string]any{"sub": "user@example.com", "client_id": "client-123"},
	)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+idjagToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should be rejected because ID-JAG is not in allowed protocols
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (protocol not allowed), got %d", rec.Code)
	}
}

func TestMultiProtocolMiddleware_RequireKeyBinding(t *testing.T) {
	// Assertion without key binding
	assertion := &idjag.Assertion{
		Issuer:    "https://issuer.example.com",
		Subject:   "user@example.com",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-123",
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	verifier := &mockIDJAGVerifier{assertion: assertion}

	handler := MultiProtocolMiddleware(
		WithIDJAGVerifier(verifier),
		WithRequireKeyBinding(),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	idjagToken := createTestJWT(
		map[string]any{"typ": TypIDJAG, "alg": "ES256"},
		map[string]any{"sub": "user@example.com", "client_id": "client-123"},
	)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+idjagToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should be rejected because no key binding
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (no key binding), got %d", rec.Code)
	}
}

func TestMultiProtocolMiddleware_CustomErrorHandler(t *testing.T) {
	var capturedError error

	handler := MultiProtocolMiddleware(
		WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
			capturedError = err
			w.WriteHeader(http.StatusForbidden)
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 (custom handler), got %d", rec.Code)
	}
	if capturedError != ErrNoToken {
		t.Errorf("expected ErrNoToken, got %v", capturedError)
	}
}

func TestIdentityFromContext_Missing(t *testing.T) {
	ctx := context.Background()
	identity, ok := IdentityFromContext(ctx)
	if ok || identity != nil {
		t.Error("expected no identity in empty context")
	}
}

func TestProtocolFromContext_Missing(t *testing.T) {
	ctx := context.Background()
	protocol := ProtocolFromContext(ctx)
	if protocol != ProtocolUnknown {
		t.Errorf("expected ProtocolUnknown, got %s", protocol)
	}
}

func TestWithOptions(t *testing.T) {
	config := &MiddlewareConfig{}

	// Test each option
	WithIDJAGVerifier(&mockIDJAGVerifier{})(config)
	if config.IDJAGVerifier == nil {
		t.Error("WithIDJAGVerifier did not set verifier")
	}

	WithWITVerifier(&mockWITVerifier{})(config)
	if config.WITVerifier == nil {
		t.Error("WithWITVerifier did not set verifier")
	}

	WithAAuthVerifier(&mockAAuthVerifier{})(config)
	if config.AAuthVerifier == nil {
		t.Error("WithAAuthVerifier did not set verifier")
	}

	WithRequireKeyBinding()(config)
	if !config.RequireKeyBinding {
		t.Error("WithRequireKeyBinding did not set flag")
	}

	WithAllowedProtocols(ProtocolIDJAG, ProtocolAIMS)(config)
	if len(config.AllowedProtocols) != 2 {
		t.Errorf("expected 2 allowed protocols, got %d", len(config.AllowedProtocols))
	}
}
