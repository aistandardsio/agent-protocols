package sharkauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Grant types and token types per RFC 8693.
//
//nolint:gosec // G101: OAuth URNs per RFC 8693, not credentials
const (
	// GrantTypeTokenExchange is the OAuth 2.0 token exchange grant type.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// TokenTypeJWT is the JWT token type.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// TokenTypeAccessToken is the access token type.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// TokenTypeAAuthAgent is the AAuth agent token type.
	TokenTypeAAuthAgent = "urn:ietf:params:oauth:token-type:aa-agent+jwt"

	// TokenTypeAAuthAuth is the AAuth auth token type.
	TokenTypeAAuthAuth = "urn:ietf:params:oauth:token-type:aa-auth+jwt"
)

// Client provides access to SharkAuth APIs.
type Client struct {
	baseURL      string
	tokenURL     string
	httpClient   *http.Client
	clientID     string
	clientSecret string
}

// ClientOption configures a Client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	httpClient    *http.Client
	tokenEndpoint string
	clientID      string
	clientSecret  string
}

func defaultClientOptions() *clientOptions {
	return &clientOptions{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(o *clientOptions) {
		o.httpClient = client
	}
}

// WithStaticTokenEndpoint sets a static token endpoint URL.
func WithStaticTokenEndpoint(url string) ClientOption {
	return func(o *clientOptions) {
		o.tokenEndpoint = url
	}
}

// WithClientCredentials sets client credentials for authentication.
func WithClientCredentials(clientID, clientSecret string) ClientOption {
	return func(o *clientOptions) {
		o.clientID = clientID
		o.clientSecret = clientSecret
	}
}

// NewClient creates a new SharkAuth client.
func NewClient(baseURL string, opts ...ClientOption) (*Client, error) {
	options := defaultClientOptions()
	for _, opt := range opts {
		opt(options)
	}

	tokenURL := options.tokenEndpoint
	if tokenURL == "" {
		// Default to standard OAuth token endpoint
		tokenURL = strings.TrimSuffix(baseURL, "/") + "/oauth/token"
	}

	return &Client{
		baseURL:      baseURL,
		tokenURL:     tokenURL,
		httpClient:   options.httpClient,
		clientID:     options.clientID,
		clientSecret: options.clientSecret,
	}, nil
}

// BaseURL returns the SharkAuth base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// TokenURL returns the token endpoint URL.
func (c *Client) TokenURL() string {
	return c.tokenURL
}

// TokenResponse represents a token exchange response.
type TokenResponse struct {
	// AccessToken is the issued access token.
	AccessToken string `json:"access_token"`

	// IssuedTokenType identifies the type of token issued.
	IssuedTokenType string `json:"issued_token_type"`

	// TokenType is typically "Bearer" or "DPoP".
	TokenType string `json:"token_type"`

	// ExpiresIn is the lifetime in seconds of the access token.
	ExpiresIn int `json:"expires_in,omitempty"`

	// Scope is the scope of the access token.
	Scope string `json:"scope,omitempty"`

	// RefreshToken is an optional refresh token.
	RefreshToken string `json:"refresh_token,omitempty"`

	// GrantID is the SharkAuth grant identifier for audit trail.
	GrantID string `json:"grant_id,omitempty"`
}

// ExchangeOption configures a token exchange request.
type ExchangeOption func(*exchangeOptions)

type exchangeOptions struct {
	scope              string
	audience           string
	resource           string
	requestedTokenType string
	dpopProof          string
}

// WithScope sets the requested scope.
func WithScope(scope string) ExchangeOption {
	return func(o *exchangeOptions) {
		o.scope = scope
	}
}

// WithAudience sets the target audience.
func WithAudience(audience string) ExchangeOption {
	return func(o *exchangeOptions) {
		o.audience = audience
	}
}

// WithResource sets the target resource.
func WithResource(resource string) ExchangeOption {
	return func(o *exchangeOptions) {
		o.resource = resource
	}
}

// WithRequestedTokenType sets the requested token type.
func WithRequestedTokenType(tokenType string) ExchangeOption {
	return func(o *exchangeOptions) {
		o.requestedTokenType = tokenType
	}
}

// WithDPoP adds a DPoP proof to the exchange request.
func WithDPoP(proof string) ExchangeOption {
	return func(o *exchangeOptions) {
		o.dpopProof = proof
	}
}

// ExchangeAAuthToken exchanges an AAuth token for a SharkAuth access token.
func (c *Client) ExchangeAAuthToken(ctx context.Context, token string, opts ...ExchangeOption) (*TokenResponse, error) {
	return c.exchange(ctx, token, TokenTypeAAuthAgent, "", "", opts...)
}

// ExchangeWithActor exchanges a token with delegation.
func (c *Client) ExchangeWithActor(ctx context.Context, subjectToken, actorToken string, opts ...ExchangeOption) (*TokenResponse, error) {
	return c.exchange(ctx, subjectToken, TokenTypeJWT, actorToken, TokenTypeJWT, opts...)
}

// Exchange performs a generic token exchange.
func (c *Client) Exchange(ctx context.Context, subjectToken, subjectTokenType string, opts ...ExchangeOption) (*TokenResponse, error) {
	return c.exchange(ctx, subjectToken, subjectTokenType, "", "", opts...)
}

func (c *Client) exchange(ctx context.Context, subjectToken, subjectTokenType, actorToken, actorTokenType string, opts ...ExchangeOption) (*TokenResponse, error) {
	var options exchangeOptions
	for _, opt := range opts {
		opt(&options)
	}

	// Build form data
	data := url.Values{}
	data.Set("grant_type", GrantTypeTokenExchange)
	data.Set("subject_token", subjectToken)
	data.Set("subject_token_type", subjectTokenType)

	if actorToken != "" {
		data.Set("actor_token", actorToken)
		data.Set("actor_token_type", actorTokenType)
	}

	if options.requestedTokenType != "" {
		data.Set("requested_token_type", options.requestedTokenType)
	}
	if options.scope != "" {
		data.Set("scope", options.scope)
	}
	if options.resource != "" {
		data.Set("resource", options.resource)
	}
	if options.audience != "" {
		data.Set("audience", options.audience)
	}

	// Add client_id if set
	if c.clientID != "" && c.clientSecret == "" {
		data.Set("client_id", c.clientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add DPoP proof if provided
	if options.dpopProof != "" {
		req.Header.Set("DPoP", options.dpopProof)
	}

	// Add Basic auth if credentials are set
	if c.clientID != "" && c.clientSecret != "" {
		req.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrTokenExchangeFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%w: %s - %s", ErrTokenExchangeFailed, errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("%w: status %d", ErrTokenExchangeFailed, resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrTokenExchangeFailed, err)
	}

	return &tokenResp, nil
}

// TokenErrorResponse represents an OAuth 2.0 error response.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}
