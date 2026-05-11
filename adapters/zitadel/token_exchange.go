package zitadel

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

	// TokenTypeIDToken is the ID token type.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
)

// TokenExchanger wraps Zitadel's token exchange with ID-JAG support.
type TokenExchanger struct {
	issuer       string
	tokenURL     string
	httpClient   *http.Client
	clientID     string
	clientSecret string
}

// TokenExchangerOption configures a TokenExchanger.
type TokenExchangerOption func(*tokenExchangerOptions)

type tokenExchangerOptions struct {
	httpClient    *http.Client
	tokenEndpoint string
	clientID      string
	clientSecret  string
}

func defaultTokenExchangerOptions() *tokenExchangerOptions {
	return &tokenExchangerOptions{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// WithHTTPClient sets a custom HTTP client for the token exchanger.
func WithHTTPClient(client *http.Client) TokenExchangerOption {
	return func(o *tokenExchangerOptions) {
		o.httpClient = client
	}
}

// WithStaticTokenEndpoint sets a static token endpoint URL instead of using OIDC discovery.
func WithStaticTokenEndpoint(url string) TokenExchangerOption {
	return func(o *tokenExchangerOptions) {
		o.tokenEndpoint = url
	}
}

// WithClientCredentials sets client credentials for authentication.
func WithClientCredentials(clientID, clientSecret string) TokenExchangerOption {
	return func(o *tokenExchangerOptions) {
		o.clientID = clientID
		o.clientSecret = clientSecret
	}
}

// NewTokenExchanger creates a new token exchanger for the given Zitadel issuer.
// It uses OIDC discovery to find the token endpoint unless WithStaticTokenEndpoint is used.
func NewTokenExchanger(issuer string, opts ...TokenExchangerOption) (*TokenExchanger, error) {
	options := defaultTokenExchangerOptions()
	for _, opt := range opts {
		opt(options)
	}

	tokenURL := options.tokenEndpoint
	if tokenURL == "" {
		// Discover token endpoint
		discovered, err := discoverTokenEndpoint(issuer, options.httpClient)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
		}
		tokenURL = discovered
	}

	return &TokenExchanger{
		issuer:       issuer,
		tokenURL:     tokenURL,
		httpClient:   options.httpClient,
		clientID:     options.clientID,
		clientSecret: options.clientSecret,
	}, nil
}

// Issuer returns the Zitadel issuer URL.
func (e *TokenExchanger) Issuer() string {
	return e.issuer
}

// TokenURL returns the token endpoint URL.
func (e *TokenExchanger) TokenURL() string {
	return e.tokenURL
}

// TokenResponse represents a token exchange response.
type TokenResponse struct {
	// AccessToken is the issued access token.
	AccessToken string `json:"access_token"`

	// IssuedTokenType identifies the type of token issued.
	IssuedTokenType string `json:"issued_token_type"`

	// TokenType is typically "Bearer".
	TokenType string `json:"token_type"`

	// ExpiresIn is the lifetime in seconds of the access token.
	ExpiresIn int `json:"expires_in,omitempty"`

	// Scope is the scope of the access token.
	Scope string `json:"scope,omitempty"`

	// RefreshToken is an optional refresh token.
	RefreshToken string `json:"refresh_token,omitempty"`

	// IDToken is an optional ID token.
	IDToken string `json:"id_token,omitempty"`
}

// ExchangeOption configures a token exchange request.
type ExchangeOption func(*exchangeOptions)

type exchangeOptions struct {
	scope              string
	audience           string
	resource           string
	requestedTokenType string
}

// WithScope sets the requested scope for the token exchange.
func WithScope(scope string) ExchangeOption {
	return func(o *exchangeOptions) {
		o.scope = scope
	}
}

// WithAudience sets the target audience for the token exchange.
func WithAudience(audience string) ExchangeOption {
	return func(o *exchangeOptions) {
		o.audience = audience
	}
}

// WithResource sets the target resource for the token exchange.
func WithResource(resource string) ExchangeOption {
	return func(o *exchangeOptions) {
		o.resource = resource
	}
}

// WithRequestedTokenType sets the requested token type for the exchange.
func WithRequestedTokenType(tokenType string) ExchangeOption {
	return func(o *exchangeOptions) {
		o.requestedTokenType = tokenType
	}
}

// ExchangeAssertion exchanges an ID-JAG assertion for an access token.
// The assertion should be a signed JWT from an idjag.Assertion.
func (e *TokenExchanger) ExchangeAssertion(ctx context.Context, assertion string, opts ...ExchangeOption) (*TokenResponse, error) {
	return e.exchange(ctx, assertion, TokenTypeJWT, "", "", opts...)
}

// ExchangeWithActor exchanges an assertion with delegation (act claim support).
// The actorToken represents the identity of the acting party.
func (e *TokenExchanger) ExchangeWithActor(ctx context.Context, assertion, actorToken string, opts ...ExchangeOption) (*TokenResponse, error) {
	return e.exchange(ctx, assertion, TokenTypeJWT, actorToken, TokenTypeJWT, opts...)
}

// exchange performs the RFC 8693 token exchange request.
func (e *TokenExchanger) exchange(ctx context.Context, subjectToken, subjectTokenType, actorToken, actorTokenType string, opts ...ExchangeOption) (*TokenResponse, error) {
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

	// Add client_id if set and not using Basic auth
	if e.clientID != "" && e.clientSecret == "" {
		data.Set("client_id", e.clientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add Basic auth if credentials are set
	if e.clientID != "" && e.clientSecret != "" {
		req.SetBasicAuth(e.clientID, e.clientSecret)
	}

	resp, err := e.httpClient.Do(req)
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
