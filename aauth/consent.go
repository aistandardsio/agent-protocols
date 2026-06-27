package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Deferred consent errors.
var (
	// ErrConsentPending indicates consent is still pending approval.
	ErrConsentPending = errors.New("consent pending")

	// ErrConsentDenied indicates consent was denied by the user.
	ErrConsentDenied = errors.New("consent denied")

	// ErrConsentExpired indicates the consent request has expired.
	ErrConsentExpired = errors.New("consent request expired")

	// ErrConsentTimeout indicates polling timed out waiting for consent.
	ErrConsentTimeout = errors.New("consent polling timeout")
)

// ConsentStatus represents the current state of a consent request.
type ConsentStatus string

// Consent status values.
const (
	ConsentStatusPending  ConsentStatus = "pending"
	ConsentStatusApproved ConsentStatus = "approved"
	ConsentStatusDenied   ConsentStatus = "denied"
	ConsentStatusExpired  ConsentStatus = "expired"
)

// DeferredConsentResponse represents a 202 Accepted response indicating
// that user consent is required before the request can proceed.
type DeferredConsentResponse struct {
	// ConsentURI is the URI for the user to provide consent.
	// The agent should direct the user to this URL.
	ConsentURI string `json:"consent_uri,omitempty"`

	// StatusURI is the URI to poll for consent status.
	StatusURI string `json:"status_uri"`

	// Interval is the recommended polling interval in seconds.
	Interval int `json:"interval,omitempty"`

	// ExpiresIn is the number of seconds until the consent request expires.
	ExpiresIn int `json:"expires_in,omitempty"`

	// Message is an optional human-readable message about the consent request.
	Message string `json:"message,omitempty"`

	// Scopes are the requested scopes requiring consent.
	Scopes []string `json:"scopes,omitempty"`
}

// ConsentStatusResponse represents the response from polling the status URI.
type ConsentStatusResponse struct {
	// Status is the current consent status.
	Status ConsentStatus `json:"status"`

	// AccessToken is the access token, present when status is "approved".
	AccessToken string `json:"access_token,omitempty"`

	// TokenType is the token type (usually "Bearer").
	TokenType string `json:"token_type,omitempty"`

	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int `json:"expires_in,omitempty"`

	// Scope is the granted scope.
	Scope string `json:"scope,omitempty"`

	// Error is set when status indicates failure.
	Error string `json:"error,omitempty"`

	// ErrorDescription provides more details about the error.
	ErrorDescription string `json:"error_description,omitempty"`
}

// ConsentPoller polls for consent approval with exponential backoff.
type ConsentPoller struct {
	httpClient     *http.Client
	initialBackoff time.Duration
	maxBackoff     time.Duration
	maxWaitTime    time.Duration

	// Callback for status updates
	onStatusChange func(status ConsentStatus)
}

// ConsentPollerOption configures a ConsentPoller.
type ConsentPollerOption func(*ConsentPoller)

// WithConsentHTTPClient sets a custom HTTP client.
func WithConsentHTTPClient(client *http.Client) ConsentPollerOption {
	return func(p *ConsentPoller) {
		p.httpClient = client
	}
}

// WithInitialBackoff sets the initial polling backoff duration.
func WithInitialBackoff(d time.Duration) ConsentPollerOption {
	return func(p *ConsentPoller) {
		p.initialBackoff = d
	}
}

// WithMaxBackoff sets the maximum polling backoff duration.
func WithMaxBackoff(d time.Duration) ConsentPollerOption {
	return func(p *ConsentPoller) {
		p.maxBackoff = d
	}
}

// WithMaxWaitTime sets the maximum total wait time for consent.
func WithMaxWaitTime(d time.Duration) ConsentPollerOption {
	return func(p *ConsentPoller) {
		p.maxWaitTime = d
	}
}

// WithStatusChangeCallback sets a callback for consent status changes.
func WithStatusChangeCallback(fn func(status ConsentStatus)) ConsentPollerOption {
	return func(p *ConsentPoller) {
		p.onStatusChange = fn
	}
}

// NewConsentPoller creates a new consent poller.
func NewConsentPoller(opts ...ConsentPollerOption) *ConsentPoller {
	p := &ConsentPoller{
		httpClient:     http.DefaultClient,
		initialBackoff: 2 * time.Second,
		maxBackoff:     30 * time.Second,
		maxWaitTime:    5 * time.Minute,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Poll polls the status URI until consent is granted, denied, or times out.
// Returns the final ConsentStatusResponse or an error.
func (p *ConsentPoller) Poll(ctx context.Context, statusURI string, interval int) (*ConsentStatusResponse, error) {
	// Use server-provided interval if available
	backoff := p.initialBackoff
	if interval > 0 {
		backoff = time.Duration(interval) * time.Second
	}

	deadline := time.Now().Add(p.maxWaitTime)
	var lastStatus ConsentStatus

	for {
		// Check context and deadline
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if time.Now().After(deadline) {
			return nil, ErrConsentTimeout
		}

		// Poll the status URI
		status, err := p.checkStatus(ctx, statusURI)
		if err != nil {
			return nil, err
		}

		// Notify callback if status changed
		if status.Status != lastStatus && p.onStatusChange != nil {
			p.onStatusChange(status.Status)
		}
		lastStatus = status.Status

		// Handle terminal states
		switch status.Status {
		case ConsentStatusApproved:
			return status, nil
		case ConsentStatusDenied:
			return status, ErrConsentDenied
		case ConsentStatusExpired:
			return status, ErrConsentExpired
		case ConsentStatusPending:
			// Continue polling
		default:
			return nil, fmt.Errorf("unknown consent status: %s", status.Status)
		}

		// Wait before next poll with exponential backoff
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}

		// Increase backoff for next iteration
		backoff = time.Duration(float64(backoff) * 1.5)
		if backoff > p.maxBackoff {
			backoff = p.maxBackoff
		}
	}
}

// checkStatus performs a single status check.
func (p *ConsentPoller) checkStatus(ctx context.Context, statusURI string) (*ConsentStatusResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to check consent status: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64KB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read status response: %w", err)
	}

	// Handle HTTP errors
	if resp.StatusCode >= 400 {
		var errResp TokenErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("status check failed with HTTP %d", resp.StatusCode)
	}

	var status ConsentStatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("failed to parse status response: %w", err)
	}

	return &status, nil
}

// IsDeferredConsent checks if an HTTP response indicates deferred consent.
func IsDeferredConsent(resp *http.Response) bool {
	return resp.StatusCode == http.StatusAccepted
}

// ParseDeferredConsentResponse parses a 202 Accepted response body.
func ParseDeferredConsentResponse(body []byte) (*DeferredConsentResponse, error) {
	var consent DeferredConsentResponse
	if err := json.Unmarshal(body, &consent); err != nil {
		return nil, fmt.Errorf("failed to parse deferred consent response: %w", err)
	}

	if consent.StatusURI == "" {
		return nil, fmt.Errorf("deferred consent response missing status_uri")
	}

	return &consent, nil
}

// ConsentAwareTransport wraps an http.RoundTripper to handle deferred consent.
type ConsentAwareTransport struct {
	// Base transport to use for requests
	Base http.RoundTripper

	// Poller for handling consent polling
	Poller *ConsentPoller

	// ConsentHandler is called when user consent is required.
	// It receives the consent URI and should direct the user to approve.
	// Return nil to continue polling, or an error to abort.
	ConsentHandler func(ctx context.Context, consent *DeferredConsentResponse) error

	// AutoPoll enables automatic polling after deferred consent.
	// If false, returns ErrConsentPending and the caller must handle polling.
	AutoPoll bool
}

// RoundTrip implements http.RoundTripper with deferred consent handling.
func (t *ConsentAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	resp, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Check for deferred consent (202 Accepted)
	if !IsDeferredConsent(resp) {
		return resp, nil
	}

	// Read and parse the consent response
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read deferred consent body: %w", err)
	}

	consent, err := ParseDeferredConsentResponse(body)
	if err != nil {
		return nil, err
	}

	// Call the consent handler if provided
	if t.ConsentHandler != nil {
		if err := t.ConsentHandler(req.Context(), consent); err != nil {
			return nil, err
		}
	}

	// If auto-poll is disabled, return an error for manual handling
	if !t.AutoPoll {
		return nil, &DeferredConsentError{
			Consent: consent,
		}
	}

	// Poll for consent approval
	poller := t.Poller
	if poller == nil {
		poller = NewConsentPoller()
	}

	status, err := poller.Poll(req.Context(), consent.StatusURI, consent.Interval)
	if err != nil {
		return nil, err
	}

	// If we got a token, we could retry the original request with it
	// For now, return a synthetic response with the token
	return synthesizeTokenResponse(status), nil
}

// DeferredConsentError wraps a deferred consent response for manual handling.
type DeferredConsentError struct {
	Consent *DeferredConsentResponse
}

func (e *DeferredConsentError) Error() string {
	if e.Consent.Message != "" {
		return fmt.Sprintf("deferred consent required: %s", e.Consent.Message)
	}
	return "deferred consent required"
}

// Is implements errors.Is for DeferredConsentError.
func (e *DeferredConsentError) Is(target error) bool {
	return errors.Is(target, ErrConsentPending)
}

// synthesizeTokenResponse creates an http.Response from a successful consent.
func synthesizeTokenResponse(status *ConsentStatusResponse) *http.Response {
	// nolint:gosec // G117 false positive: this is not a secret, just a token structure
	body, _ := json.Marshal(TokenExchangeResponse{
		AccessToken:     status.AccessToken,
		TokenType:       status.TokenType,
		ExpiresIn:       status.ExpiresIn,
		Scope:           status.Scope,
		IssuedTokenType: TokenTypeURIAuthJWT,
	})

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(bytesReader(body)),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}
}

// bytesReader is a minimal bytes.Reader for response body.
type bytesReader []byte

func (b bytesReader) Read(p []byte) (n int, err error) {
	n = copy(p, b)
	if n < len(b) {
		return n, nil
	}
	return n, io.EOF
}
