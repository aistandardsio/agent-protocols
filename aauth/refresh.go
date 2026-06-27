package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Token refresh errors.
var (
	// ErrRefreshFailed indicates the token refresh failed.
	ErrRefreshFailed = errors.New("token refresh failed")

	// ErrNoRefreshToken indicates no refresh token is available.
	ErrNoRefreshToken = errors.New("no refresh token available")

	// ErrRefreshNotSupported indicates the server doesn't support refresh.
	ErrRefreshNotSupported = errors.New("token refresh not supported")
)

// Grant types for token refresh.
const (
	// GrantTypeRefreshToken is the standard OAuth 2.0 refresh token grant.
	GrantTypeRefreshToken = "refresh_token"
)

// TokenRefresher handles automatic token refresh.
type TokenRefresher interface {
	// Refresh exchanges a refresh token for new access and refresh tokens.
	Refresh(ctx context.Context) (*TokenExchangeResponse, error)

	// SetRefreshToken updates the current refresh token.
	SetRefreshToken(token string)

	// HasRefreshToken returns true if a refresh token is available.
	HasRefreshToken() bool
}

// RefreshableToken holds an access token with refresh capability.
type RefreshableToken struct {
	// AccessToken is the current access token.
	AccessToken string

	// RefreshToken is the refresh token for obtaining new access tokens.
	RefreshToken string

	// ExpiresAt is when the access token expires.
	ExpiresAt time.Time

	// Scope is the granted scope.
	Scope string

	// TokenType is the token type (usually "Bearer").
	TokenType string
}

// IsExpired returns true if the access token has expired or will expire soon.
func (t *RefreshableToken) IsExpired(threshold time.Duration) bool {
	return time.Now().Add(threshold).After(t.ExpiresAt)
}

// TokenRefreshClient handles token refresh requests to an auth server.
type TokenRefreshClient struct {
	tokenEndpoint string
	httpClient    *http.Client

	mu           sync.RWMutex
	refreshToken string
	currentToken *RefreshableToken

	// Callback for token updates
	onTokenRefresh func(token *RefreshableToken)

	// Configuration
	refreshThreshold time.Duration // Refresh when token expires within this duration
	autoRefresh      bool          // Automatically refresh before expiry
}

// TokenRefreshOption configures a TokenRefreshClient.
type TokenRefreshOption func(*TokenRefreshClient)

// WithRefreshHTTPClient sets a custom HTTP client.
func WithRefreshHTTPClient(client *http.Client) TokenRefreshOption {
	return func(c *TokenRefreshClient) {
		c.httpClient = client
	}
}

// WithRefreshThreshold sets the threshold for proactive refresh.
// The token will be refreshed when it expires within this duration.
func WithRefreshThreshold(d time.Duration) TokenRefreshOption {
	return func(c *TokenRefreshClient) {
		c.refreshThreshold = d
	}
}

// WithAutoRefresh enables automatic token refresh before expiry.
func WithAutoRefresh(enabled bool) TokenRefreshOption {
	return func(c *TokenRefreshClient) {
		c.autoRefresh = enabled
	}
}

// WithTokenRefreshCallback sets a callback for when tokens are refreshed.
func WithTokenRefreshCallback(fn func(token *RefreshableToken)) TokenRefreshOption {
	return func(c *TokenRefreshClient) {
		c.onTokenRefresh = fn
	}
}

// NewTokenRefreshClient creates a new token refresh client.
func NewTokenRefreshClient(tokenEndpoint string, opts ...TokenRefreshOption) *TokenRefreshClient {
	c := &TokenRefreshClient{
		tokenEndpoint:    tokenEndpoint,
		httpClient:       http.DefaultClient,
		refreshThreshold: 5 * time.Minute,
		autoRefresh:      true,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SetToken sets the current token and refresh token.
func (c *TokenRefreshClient) SetToken(token *RefreshableToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentToken = token
	c.refreshToken = token.RefreshToken
}

// SetRefreshToken updates the current refresh token.
func (c *TokenRefreshClient) SetRefreshToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshToken = token
}

// HasRefreshToken returns true if a refresh token is available.
func (c *TokenRefreshClient) HasRefreshToken() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.refreshToken != ""
}

// CurrentToken returns the current token, refreshing if necessary.
func (c *TokenRefreshClient) CurrentToken(ctx context.Context) (*RefreshableToken, error) {
	c.mu.RLock()
	token := c.currentToken
	needsRefresh := token == nil || token.IsExpired(c.refreshThreshold)
	c.mu.RUnlock()

	if !needsRefresh {
		return token, nil
	}

	// Need to refresh
	resp, err := c.Refresh(ctx)
	if err != nil {
		// Return existing token if refresh fails and token isn't fully expired
		if token != nil && !token.IsExpired(0) {
			return token, nil
		}
		return nil, err
	}

	return &RefreshableToken{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second),
		Scope:        resp.Scope,
		TokenType:    resp.TokenType,
	}, nil
}

// Refresh exchanges the refresh token for new tokens.
func (c *TokenRefreshClient) Refresh(ctx context.Context) (*TokenExchangeResponse, error) {
	c.mu.RLock()
	refreshToken := c.refreshToken
	c.mu.RUnlock()

	if refreshToken == "" {
		return nil, ErrNoRefreshToken
	}

	// Build the refresh request
	data := url.Values{}
	data.Set("grant_type", GrantTypeRefreshToken)
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			// Check for specific error types
			if errResp.Error == "invalid_grant" {
				// Refresh token is no longer valid
				c.mu.Lock()
				c.refreshToken = ""
				c.mu.Unlock()
			}
			return nil, fmt.Errorf("%w: %s - %s", ErrRefreshFailed, errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("%w: HTTP %d", ErrRefreshFailed, resp.StatusCode)
	}

	var tokenResp TokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	// Update stored tokens
	c.mu.Lock()
	if tokenResp.RefreshToken != "" {
		c.refreshToken = tokenResp.RefreshToken
	}
	c.currentToken = &RefreshableToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: c.refreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Scope:        tokenResp.Scope,
		TokenType:    tokenResp.TokenType,
	}
	token := c.currentToken
	c.mu.Unlock()

	// Notify callback
	if c.onTokenRefresh != nil {
		c.onTokenRefresh(token)
	}

	return &tokenResp, nil
}

// RefreshAwareTransport wraps an http.RoundTripper to handle automatic token refresh.
type RefreshAwareTransport struct {
	// Base transport to use for requests
	Base http.RoundTripper

	// RefreshClient handles token refresh
	RefreshClient *TokenRefreshClient

	// AuthorizationHeader is the header to use for the token (default: "Authorization")
	AuthorizationHeader string

	// TokenPrefix is the prefix for the token value (default: "Bearer ")
	TokenPrefix string
}

// RoundTrip implements http.RoundTripper with automatic token refresh.
func (t *RefreshAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	authHeader := t.AuthorizationHeader
	if authHeader == "" {
		authHeader = HeaderAuthorization
	}

	tokenPrefix := t.TokenPrefix
	if tokenPrefix == "" {
		tokenPrefix = "Bearer "
	}

	// Get current token, refreshing if necessary
	token, err := t.RefreshClient.CurrentToken(req.Context())
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Clone the request and add the token
	reqClone := req.Clone(req.Context())
	reqClone.Header.Set(authHeader, tokenPrefix+token.AccessToken)

	// Make the request
	resp, err := base.RoundTrip(reqClone)
	if err != nil {
		return nil, err
	}

	// If we get a 401, try refreshing and retrying once
	if resp.StatusCode == http.StatusUnauthorized && t.RefreshClient.HasRefreshToken() {
		resp.Body.Close()

		// Force refresh
		newToken, err := t.RefreshClient.Refresh(req.Context())
		if err != nil {
			// Return original 401 response
			return base.RoundTrip(reqClone)
		}

		// Retry with new token
		reqClone = req.Clone(req.Context())
		reqClone.Header.Set(authHeader, tokenPrefix+newToken.AccessToken)
		return base.RoundTrip(reqClone)
	}

	return resp, nil
}

// AgentTokenRefresher handles agent token refresh using the agent's signing key.
type AgentTokenRefresher struct {
	agent     *Agent
	exchanger *ExchangeClient
}

// NewAgentTokenRefresher creates a token refresher for an agent.
func NewAgentTokenRefresher(agent *Agent, tokenEndpoint string) *AgentTokenRefresher {
	return &AgentTokenRefresher{
		agent:     agent,
		exchanger: NewExchangeClient(tokenEndpoint, agent.Client()),
	}
}

// RefreshAgentToken creates a fresh agent token.
// Unlike OAuth refresh, this creates a new signed agent token.
func (r *AgentTokenRefresher) RefreshAgentToken(audience ...string) (string, error) {
	// Clear cached token to force creation of a new one
	r.agent.mu.Lock()
	r.agent.cachedToken = ""
	r.agent.tokenExpiry = time.Time{}
	r.agent.mu.Unlock()

	return r.agent.SignAgentToken(audience...)
}

// ExchangeForAuthToken exchanges the agent token for an auth token.
func (r *AgentTokenRefresher) ExchangeForAuthToken(ctx context.Context, audience []string, scope string) (*TokenExchangeResponse, error) {
	agentToken, err := r.agent.GetOrCreateAgentToken(audience...)
	if err != nil {
		return nil, err
	}

	req := NewPSAssertedExchangeRequest(agentToken, audience, scope)
	return r.exchanger.ExchangeWithAgent(r.agent, req)
}
