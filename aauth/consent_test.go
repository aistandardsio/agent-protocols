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

func TestParseDeferredConsentResponse(t *testing.T) {
	t.Run("Valid response", func(t *testing.T) {
		body := []byte(`{
			"status_uri": "https://example.com/consent/123/status",
			"consent_uri": "https://example.com/consent/123",
			"interval": 5,
			"expires_in": 300,
			"message": "User consent required"
		}`)

		consent, err := ParseDeferredConsentResponse(body)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if consent.StatusURI != "https://example.com/consent/123/status" {
			t.Errorf("unexpected status_uri: %s", consent.StatusURI)
		}
		if consent.ConsentURI != "https://example.com/consent/123" {
			t.Errorf("unexpected consent_uri: %s", consent.ConsentURI)
		}
		if consent.Interval != 5 {
			t.Errorf("unexpected interval: %d", consent.Interval)
		}
		if consent.ExpiresIn != 300 {
			t.Errorf("unexpected expires_in: %d", consent.ExpiresIn)
		}
		if consent.Message != "User consent required" {
			t.Errorf("unexpected message: %s", consent.Message)
		}
	})

	t.Run("Missing status_uri", func(t *testing.T) {
		body := []byte(`{"consent_uri": "https://example.com/consent/123"}`)
		_, err := ParseDeferredConsentResponse(body)
		if err == nil {
			t.Error("expected error for missing status_uri")
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		body := []byte(`{invalid json}`)
		_, err := ParseDeferredConsentResponse(body)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestIsDeferredConsent(t *testing.T) {
	t.Run("202 Accepted", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusAccepted}
		if !IsDeferredConsent(resp) {
			t.Error("expected 202 to be deferred consent")
		}
	})

	t.Run("200 OK", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusOK}
		if IsDeferredConsent(resp) {
			t.Error("expected 200 to not be deferred consent")
		}
	})

	t.Run("401 Unauthorized", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusUnauthorized}
		if IsDeferredConsent(resp) {
			t.Error("expected 401 to not be deferred consent")
		}
	})
}

func TestConsentPoller(t *testing.T) {
	t.Run("Immediate approval", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			//nolint:gosec // G117 false positive: test data, not a real secret
			_ = json.NewEncoder(w).Encode(ConsentStatusResponse{
				Status:      ConsentStatusApproved,
				AccessToken: "access-token-123",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				Scope:       "read write",
			})
		}))
		defer server.Close()

		poller := NewConsentPoller(
			WithInitialBackoff(10*time.Millisecond),
			WithMaxWaitTime(5*time.Second),
		)

		ctx := context.Background()
		status, err := poller.Poll(ctx, server.URL, 0)
		if err != nil {
			t.Fatalf("poll failed: %v", err)
		}

		if status.Status != ConsentStatusApproved {
			t.Errorf("expected approved status, got %s", status.Status)
		}
		if status.AccessToken != "access-token-123" {
			t.Errorf("unexpected access token: %s", status.AccessToken)
		}
	})

	t.Run("Approval after pending", func(t *testing.T) {
		var callCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := atomic.AddInt32(&callCount, 1)
			w.Header().Set("Content-Type", "application/json")

			if count < 3 {
				//nolint:gosec // G117 false positive: test data, not a real secret
				_ = json.NewEncoder(w).Encode(ConsentStatusResponse{
					Status: ConsentStatusPending,
				})
			} else {
				//nolint:gosec // G117 false positive: test data, not a real secret
				_ = json.NewEncoder(w).Encode(ConsentStatusResponse{
					Status:      ConsentStatusApproved,
					AccessToken: "access-token-456",
				})
			}
		}))
		defer server.Close()

		var statusChanges []ConsentStatus
		poller := NewConsentPoller(
			WithInitialBackoff(10*time.Millisecond),
			WithMaxBackoff(50*time.Millisecond),
			WithMaxWaitTime(5*time.Second),
			WithStatusChangeCallback(func(status ConsentStatus) {
				statusChanges = append(statusChanges, status)
			}),
		)

		ctx := context.Background()
		status, err := poller.Poll(ctx, server.URL, 0)
		if err != nil {
			t.Fatalf("poll failed: %v", err)
		}

		if status.Status != ConsentStatusApproved {
			t.Errorf("expected approved status, got %s", status.Status)
		}

		// Should have seen pending then approved
		if len(statusChanges) < 2 {
			t.Errorf("expected at least 2 status changes, got %d", len(statusChanges))
		}
	})

	t.Run("Consent denied", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			//nolint:gosec // G117 false positive: test data
			_ = json.NewEncoder(w).Encode(ConsentStatusResponse{
				Status:           ConsentStatusDenied,
				Error:            "access_denied",
				ErrorDescription: "User denied the request",
			})
		}))
		defer server.Close()

		poller := NewConsentPoller(
			WithInitialBackoff(10 * time.Millisecond),
		)

		ctx := context.Background()
		_, err := poller.Poll(ctx, server.URL, 0)
		if err == nil {
			t.Error("expected error for denied consent")
		}
		if err != ErrConsentDenied {
			t.Errorf("expected ErrConsentDenied, got %v", err)
		}
	})

	t.Run("Consent expired", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			//nolint:gosec // G117 false positive: test data
			_ = json.NewEncoder(w).Encode(ConsentStatusResponse{
				Status: ConsentStatusExpired,
			})
		}))
		defer server.Close()

		poller := NewConsentPoller(
			WithInitialBackoff(10 * time.Millisecond),
		)

		ctx := context.Background()
		_, err := poller.Poll(ctx, server.URL, 0)
		if err == nil {
			t.Error("expected error for expired consent")
		}
		if err != ErrConsentExpired {
			t.Errorf("expected ErrConsentExpired, got %v", err)
		}
	})

	t.Run("Context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			//nolint:gosec // G117 false positive: test data
			_ = json.NewEncoder(w).Encode(ConsentStatusResponse{
				Status: ConsentStatusPending,
			})
		}))
		defer server.Close()

		poller := NewConsentPoller(
			WithInitialBackoff(100 * time.Millisecond),
		)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := poller.Poll(ctx, server.URL, 0)
		if err == nil {
			t.Error("expected error for context cancellation")
		}
	})

	t.Run("Timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			//nolint:gosec // G117 false positive: test data
			_ = json.NewEncoder(w).Encode(ConsentStatusResponse{
				Status: ConsentStatusPending,
			})
		}))
		defer server.Close()

		poller := NewConsentPoller(
			WithInitialBackoff(10*time.Millisecond),
			WithMaxWaitTime(50*time.Millisecond),
		)

		ctx := context.Background()
		_, err := poller.Poll(ctx, server.URL, 0)
		if err == nil {
			t.Error("expected timeout error")
		}
		if err != ErrConsentTimeout {
			t.Errorf("expected ErrConsentTimeout, got %v", err)
		}
	})
}

func TestDeferredConsentError(t *testing.T) {
	consent := &DeferredConsentResponse{
		StatusURI:  "https://example.com/status",
		ConsentURI: "https://example.com/consent",
		Message:    "Please approve the request",
	}

	err := &DeferredConsentError{Consent: consent}

	t.Run("Error message with Message", func(t *testing.T) {
		expected := "deferred consent required: Please approve the request"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("Error message without Message", func(t *testing.T) {
		err2 := &DeferredConsentError{Consent: &DeferredConsentResponse{StatusURI: "https://example.com"}}
		expected := "deferred consent required"
		if err2.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err2.Error())
		}
	})

	t.Run("Is ErrConsentPending", func(t *testing.T) {
		if !err.Is(ErrConsentPending) {
			t.Error("expected DeferredConsentError to match ErrConsentPending")
		}
	})
}
