package idjag

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

// TokenExchangeClient handles OAuth 2.0 token exchange requests per RFC 8693.
type TokenExchangeClient struct {
	// TokenURL is the authorization server's token endpoint.
	TokenURL string

	// HTTPClient is the HTTP client to use for requests.
	// If nil, http.DefaultClient is used.
	HTTPClient *http.Client

	// ClientID is the OAuth client identifier.
	// If set, it will be included in the request.
	ClientID string

	// ClientSecret is the OAuth client secret.
	// If set, HTTP Basic authentication will be used.
	ClientSecret string
}

// NewTokenExchangeClient creates a new token exchange client.
func NewTokenExchangeClient(tokenURL string) *TokenExchangeClient {
	return &TokenExchangeClient{
		TokenURL:   tokenURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// WithCredentials sets client credentials for authentication.
func (c *TokenExchangeClient) WithCredentials(clientID, clientSecret string) *TokenExchangeClient {
	c.ClientID = clientID
	c.ClientSecret = clientSecret
	return c
}

// WithHTTPClient sets a custom HTTP client.
func (c *TokenExchangeClient) WithHTTPClient(client *http.Client) *TokenExchangeClient {
	c.HTTPClient = client
	return c
}

// TokenExchangeRequest represents an RFC 8693 token exchange request.
type TokenExchangeRequest struct {
	// SubjectToken is the security token being exchanged (required).
	// For ID-JAG, this is the signed assertion JWT.
	SubjectToken string

	// SubjectTokenType identifies the type of subject token (required).
	// For ID-JAG assertions, use TokenTypeJWT.
	SubjectTokenType string

	// ActorToken is an optional security token representing the actor.
	ActorToken string

	// ActorTokenType identifies the type of actor token (required if ActorToken is set).
	ActorTokenType string

	// RequestedTokenType identifies the type of token being requested.
	// Defaults to TokenTypeAccessToken if not specified.
	RequestedTokenType string

	// Scope is the requested scope for the issued token.
	Scope string

	// Resource is the target resource for the issued token.
	Resource string

	// Audience is the target audience for the issued token.
	Audience string
}

// TokenExchangeResponse represents an RFC 8693 token exchange response.
type TokenExchangeResponse struct {
	// AccessToken is the issued security token.
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
}

// Exchange performs a token exchange request.
func (c *TokenExchangeClient) Exchange(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if req.SubjectToken == "" {
		return nil, fmt.Errorf("%w: subject_token required", ErrTokenExchangeFailed)
	}
	if req.SubjectTokenType == "" {
		return nil, fmt.Errorf("%w: subject_token_type required", ErrTokenExchangeFailed)
	}

	// Build form data
	data := url.Values{}
	data.Set("grant_type", GrantTypeTokenExchange)
	data.Set("subject_token", req.SubjectToken)
	data.Set("subject_token_type", req.SubjectTokenType)

	if req.ActorToken != "" {
		data.Set("actor_token", req.ActorToken)
		if req.ActorTokenType == "" {
			return nil, fmt.Errorf("%w: actor_token_type required when actor_token is set", ErrTokenExchangeFailed)
		}
		data.Set("actor_token_type", req.ActorTokenType)
	}

	if req.RequestedTokenType != "" {
		data.Set("requested_token_type", req.RequestedTokenType)
	}
	if req.Scope != "" {
		data.Set("scope", req.Scope)
	}
	if req.Resource != "" {
		data.Set("resource", req.Resource)
	}
	if req.Audience != "" {
		data.Set("audience", req.Audience)
	}

	// Add client_id if set and not using Basic auth
	if c.ClientID != "" && c.ClientSecret == "" {
		data.Set("client_id", c.ClientID)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}

	httpReq.Header.Set(HeaderContentType, ContentTypeFormURLEncoded)

	// Add Basic auth if credentials are set
	if c.ClientID != "" && c.ClientSecret != "" {
		httpReq.SetBasicAuth(c.ClientID, c.ClientSecret)
	}

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
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

	var tokenResp TokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrTokenExchangeFailed, err)
	}

	return &tokenResp, nil
}

// ExchangeAssertion is a convenience method for exchanging an ID-JAG assertion.
// It sets the subject token type to JWT automatically.
func (c *TokenExchangeClient) ExchangeAssertion(ctx context.Context, assertion string, scope string) (*TokenExchangeResponse, error) {
	return c.Exchange(ctx, &TokenExchangeRequest{
		SubjectToken:     assertion,
		SubjectTokenType: TokenTypeJWT,
		Scope:            scope,
	})
}

// JWTBearerClient handles JWT bearer assertion grants per RFC 7523.
type JWTBearerClient struct {
	// TokenURL is the authorization server's token endpoint.
	TokenURL string

	// HTTPClient is the HTTP client to use for requests.
	HTTPClient *http.Client

	// ClientID is the OAuth client identifier.
	ClientID string
}

// NewJWTBearerClient creates a new JWT bearer client.
func NewJWTBearerClient(tokenURL string) *JWTBearerClient {
	return &JWTBearerClient{
		TokenURL:   tokenURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Exchange exchanges a JWT assertion for an access token using JWT bearer grant.
func (c *JWTBearerClient) Exchange(ctx context.Context, assertion, scope string) (*TokenExchangeResponse, error) {
	data := url.Values{}
	data.Set("grant_type", GrantTypeJWTBearer)
	data.Set("assertion", assertion)
	if scope != "" {
		data.Set("scope", scope)
	}
	if c.ClientID != "" {
		data.Set("client_id", c.ClientID)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}

	httpReq.Header.Set(HeaderContentType, ContentTypeFormURLEncoded)

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
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

	var tokenResp TokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrTokenExchangeFailed, err)
	}

	return &tokenResp, nil
}
