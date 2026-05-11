// Package hydra provides a client for Ory Hydra's APIs with agent token support.
package hydra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Grant type constants.
//
//nolint:gosec // G101: These are OAuth grant type URIs, not credentials.
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantTypeJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// Token type constants.
//
//nolint:gosec // G101: These are OAuth token type URIs, not credentials.
const (
	TokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeIDJAG       = "urn:ietf:params:oauth:token-type:id-jag"
	TokenTypeAAuthAgent  = "urn:ietf:params:oauth:token-type:aa-agent+jwt"
)

// Error definitions.
var (
	ErrHydraRequest    = errors.New("hydra: request failed")
	ErrInvalidResponse = errors.New("hydra: invalid response")
	ErrTokenExchange   = errors.New("hydra: token exchange failed")
)

// Client is an Ory Hydra client with agent token support.
type Client struct {
	publicURL    string
	adminURL     string
	httpClient   *http.Client
	clientID     string
	clientSecret string
}

// Option configures the Hydra client.
type Option func(*Client)

// NewClient creates a new Hydra client.
func NewClient(publicURL string, opts ...Option) (*Client, error) {
	if publicURL == "" {
		return nil, fmt.Errorf("public URL is required")
	}

	c := &Client{
		publicURL:  strings.TrimSuffix(publicURL, "/"),
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// WithAdminURL sets the Hydra admin API URL.
func WithAdminURL(url string) Option {
	return func(c *Client) {
		c.adminURL = strings.TrimSuffix(url, "/")
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithClientCredentials sets OAuth client credentials.
func WithClientCredentials(clientID, clientSecret string) Option {
	return func(c *Client) {
		c.clientID = clientID
		c.clientSecret = clientSecret
	}
}

// TokenResponse represents an OAuth token response.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	Scope           string `json:"scope,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// TokenErrorResponse represents an OAuth error response.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ExchangeOption configures a token exchange request.
type ExchangeOption func(url.Values)

// WithScope sets the requested scope.
func WithScope(scope string) ExchangeOption {
	return func(v url.Values) {
		v.Set("scope", scope)
	}
}

// WithAudience sets the requested audience.
func WithAudience(audience string) ExchangeOption {
	return func(v url.Values) {
		v.Set("audience", audience)
	}
}

// WithResource sets the requested resource.
func WithResource(resource string) ExchangeOption {
	return func(v url.Values) {
		v.Set("resource", resource)
	}
}

// WithActorToken adds an actor token for delegation.
func WithActorToken(token, tokenType string) ExchangeOption {
	return func(v url.Values) {
		v.Set("actor_token", token)
		v.Set("actor_token_type", tokenType)
	}
}

// TokenExchange performs an RFC 8693 token exchange.
func (c *Client) TokenExchange(ctx context.Context, subjectToken, subjectTokenType string, opts ...ExchangeOption) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":         {GrantTypeTokenExchange},
		"subject_token":      {subjectToken},
		"subject_token_type": {subjectTokenType},
	}

	for _, opt := range opts {
		opt(data)
	}

	return c.tokenRequest(ctx, data)
}

// ExchangeIDJAG exchanges an ID-JAG assertion for an access token.
func (c *Client) ExchangeIDJAG(ctx context.Context, assertion string, opts ...ExchangeOption) (*TokenResponse, error) {
	return c.TokenExchange(ctx, assertion, TokenTypeIDJAG, opts...)
}

// ExchangeAAuthToken exchanges an AAuth agent token for an access token.
func (c *Client) ExchangeAAuthToken(ctx context.Context, agentToken string, opts ...ExchangeOption) (*TokenResponse, error) {
	return c.TokenExchange(ctx, agentToken, TokenTypeAAuthAgent, opts...)
}

// JWTBearerGrant performs a JWT Bearer grant (RFC 7523).
func (c *Client) JWTBearerGrant(ctx context.Context, assertion string, opts ...ExchangeOption) (*TokenResponse, error) {
	data := url.Values{
		"grant_type": {GrantTypeJWTBearer},
		"assertion":  {assertion},
	}

	for _, opt := range opts {
		opt(data)
	}

	return c.tokenRequest(ctx, data)
}

// tokenRequest performs a token endpoint request.
func (c *Client) tokenRequest(ctx context.Context, data url.Values) (*TokenResponse, error) {
	tokenURL := c.publicURL + "/oauth2/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHydraRequest, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if c.clientID != "" && c.clientSecret != "" {
		req.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHydraRequest, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrHydraRequest, err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%w: %s - %s", ErrTokenExchange, errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("%w: status %d", ErrTokenExchange, resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	return &tokenResp, nil
}

// IntrospectToken introspects an access token using Hydra's admin API.
func (c *Client) IntrospectToken(ctx context.Context, token string) (*IntrospectionResponse, error) {
	if c.adminURL == "" {
		return nil, fmt.Errorf("%w: admin URL not configured", ErrHydraRequest)
	}

	introspectURL := c.adminURL + "/admin/oauth2/introspect"

	data := url.Values{
		"token": {token},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHydraRequest, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHydraRequest, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrHydraRequest, err)
	}

	var introspectResp IntrospectionResponse
	if err := json.Unmarshal(body, &introspectResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	return &introspectResp, nil
}

// IntrospectionResponse represents a token introspection response.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Sub       string   `json:"sub,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	// Agent extension claims
	Act *ActorClaim `json:"act,omitempty"`
	Cnf *CnfClaim   `json:"cnf,omitempty"`
}

// ActorClaim represents the RFC 8693 act claim.
type ActorClaim struct {
	Sub string      `json:"sub"`
	Iss string      `json:"iss,omitempty"`
	Act *ActorClaim `json:"act,omitempty"`
}

// CnfClaim represents the RFC 7800 cnf claim.
type CnfClaim struct {
	JWK json.RawMessage `json:"jwk,omitempty"`
	Jku string          `json:"jku,omitempty"`
	Kid string          `json:"kid,omitempty"`
}

// ExpiresAt returns the expiration time.
func (r *IntrospectionResponse) ExpiresAt() time.Time {
	if r.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(r.Exp, 0)
}

// IssuedAt returns the issuance time.
func (r *IntrospectionResponse) IssuedAt() time.Time {
	if r.Iat == 0 {
		return time.Time{}
	}
	return time.Unix(r.Iat, 0)
}

// PublicURL returns the Hydra public API URL.
func (c *Client) PublicURL() string {
	return c.publicURL
}

// AdminURL returns the Hydra admin API URL.
func (c *Client) AdminURL() string {
	return c.adminURL
}

// TokenURL returns the token endpoint URL.
func (c *Client) TokenURL() string {
	return c.publicURL + "/oauth2/token"
}
