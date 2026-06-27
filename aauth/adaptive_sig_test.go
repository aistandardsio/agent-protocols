package aauth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdaptiveComponentSelector(t *testing.T) {
	t.Run("SelectComponents for GET request", func(t *testing.T) {
		selector := NewAdaptiveComponentSelector(DefaultAdaptiveConfig())
		req := httptest.NewRequest("GET", "/api/data", nil)

		components := selector.SelectComponents(req)

		// Should have base components
		if !containsComponent(components, "@method") {
			t.Error("expected @method component")
		}
		if !containsComponent(components, "@target-uri") {
			t.Error("expected @target-uri component")
		}

		// Should not have content components for GET
		if containsComponent(components, "content-digest") {
			t.Error("did not expect content-digest for GET request")
		}
	})

	t.Run("SelectComponents for POST request with body", func(t *testing.T) {
		selector := NewAdaptiveComponentSelector(DefaultAdaptiveConfig())
		req := httptest.NewRequest("POST", "/api/data", strings.NewReader(`{"key":"value"}`))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = 15

		components := selector.SelectComponents(req)

		// Should have base components
		if !containsComponent(components, "@method") {
			t.Error("expected @method component")
		}

		// Should have content components for POST with body
		if !containsComponent(components, "content-type") {
			t.Error("expected content-type component")
		}
	})

	t.Run("SelectComponents with auth headers", func(t *testing.T) {
		selector := NewAdaptiveComponentSelector(DefaultAdaptiveConfig())
		req := httptest.NewRequest("GET", "/api/data", nil)
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("Signature-Key", "scheme=jwt token")

		components := selector.SelectComponents(req)

		// Should have auth components
		if !containsComponent(components, "authorization") {
			t.Error("expected authorization component")
		}
		if !containsComponent(components, "signature-key") {
			t.Error("expected signature-key component")
		}
	})

	t.Run("SelectComponents with optional headers", func(t *testing.T) {
		selector := NewAdaptiveComponentSelector(DefaultAdaptiveConfig())
		req := httptest.NewRequest("GET", "/api/data", nil)
		req.Header.Set("X-Request-ID", "req-123")
		req.Header.Set("Date", "Mon, 01 Jan 2024 00:00:00 GMT")

		components := selector.SelectComponents(req)

		// Should include present optional headers
		if !containsComponent(components, "x-request-id") {
			t.Error("expected x-request-id component")
		}
		if !containsComponent(components, "date") {
			t.Error("expected date component")
		}
	})

	t.Run("SelectComponents respects MaxComponents", func(t *testing.T) {
		config := &AdaptiveSignatureConfig{
			BaseComponents:    []string{"@method", "@target-uri"},
			ContentComponents: []string{"content-type", "content-length", "content-digest"},
			MaxComponents:     3,
			MinComponents:     1,
		}
		selector := NewAdaptiveComponentSelector(config)
		req := httptest.NewRequest("POST", "/api/data", strings.NewReader(`data`))
		req.ContentLength = 4

		components := selector.SelectComponents(req)

		if len(components) > 3 {
			t.Errorf("expected max 3 components, got %d", len(components))
		}
	})

	t.Run("StrictAdaptiveConfig", func(t *testing.T) {
		config := StrictAdaptiveConfig()
		selector := NewAdaptiveComponentSelector(config)
		req := httptest.NewRequest("GET", "/api/data", nil)

		components := selector.SelectComponents(req)

		// Strict config has more base components
		if !containsComponent(components, "@authority") {
			t.Error("expected @authority in strict config")
		}
		if !containsComponent(components, "@scheme") {
			t.Error("expected @scheme in strict config")
		}
	})

	t.Run("MinimalAdaptiveConfig", func(t *testing.T) {
		config := MinimalAdaptiveConfig()
		selector := NewAdaptiveComponentSelector(config)
		req := httptest.NewRequest("GET", "/api/data", nil)

		components := selector.SelectComponents(req)

		// Minimal config should have few components
		if len(components) > 5 {
			t.Errorf("expected max 5 components for minimal config, got %d", len(components))
		}
	})
}

func TestSignaturePolicy(t *testing.T) {
	t.Run("ValidateSignedComponents success", func(t *testing.T) {
		policy := DefaultSignaturePolicy()
		req := httptest.NewRequest("GET", "/api/data", nil)
		req.Header.Set("Signature-Key", "scheme=jwt token")

		components := []string{"@method", "@target-uri", "signature-key"}
		err := policy.ValidateSignedComponents(components, req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("ValidateSignedComponents missing required", func(t *testing.T) {
		policy := DefaultSignaturePolicy()
		req := httptest.NewRequest("GET", "/api/data", nil)

		// Missing @method
		components := []string{"@target-uri", "signature-key"}
		err := policy.ValidateSignedComponents(components, req)
		if err == nil {
			t.Error("expected error for missing required component")
		}
	})

	t.Run("ValidateSignedComponents conditional for POST", func(t *testing.T) {
		policy := DefaultSignaturePolicy()
		req := httptest.NewRequest("POST", "/api/data", strings.NewReader(`data`))
		req.ContentLength = 4

		// POST should require content-digest per default policy
		components := []string{"@method", "@target-uri", "signature-key"}
		err := policy.ValidateSignedComponents(components, req)
		if err == nil {
			t.Error("expected error for missing content-digest on POST")
		}

		// Add content-digest
		components = append(components, "content-digest")
		err = policy.ValidateSignedComponents(components, req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestMatchesPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		match   bool
	}{
		{"/api", "/api", true},
		{"/api", "/api/users", false},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/users/123", false},
		{"/api/**", "/api/users/123", true},
		{"/api/**", "/api", true},
		{"", "/api", false},
		{"/*/users", "/api/users", true},
		{"/*/users", "/v2/users", true},
		{"/*/users", "/api/admins", false},
	}

	for _, tt := range tests {
		result := matchesPath(tt.pattern, tt.path)
		if result != tt.match {
			t.Errorf("matchesPath(%q, %q) = %v, want %v", tt.pattern, tt.path, result, tt.match)
		}
	}
}

func TestSignatureValidationError(t *testing.T) {
	err := &SignatureValidationError{
		Component: "@method",
		Message:   "required component not signed",
	}

	expected := "signature validation failed for @method: required component not signed"
	if err.Error() != expected {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func containsComponent(components []string, component string) bool {
	for _, c := range components {
		if c == component {
			return true
		}
	}
	return false
}

func BenchmarkAdaptiveComponentSelector(b *testing.B) {
	selector := NewAdaptiveComponentSelector(DefaultAdaptiveConfig())
	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(`{"key":"value"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("X-Request-ID", "req-123")
	req.ContentLength = 15

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		selector.SelectComponents(req)
	}
}
