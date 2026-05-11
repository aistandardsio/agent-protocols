package zitadel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// GrantTypeJWTBearer is the grant type for RFC 7523 JWT bearer assertion.
//
//nolint:gosec // G101: OAuth URN per RFC 7523, not a credential
const GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// AssertionSigner can create signed ID-JAG assertions.
type AssertionSigner interface {
	// SignAssertion creates a signed JWT assertion for the given audience.
	SignAssertion(audience []string) (string, error)
}

// JWTProfileSource implements oauth2.TokenSource using ID-JAG assertions.
// It obtains access tokens from Zitadel using the JWT bearer grant (RFC 7523).
type JWTProfileSource struct {
	issuer     string
	tokenURL   string
	clientID   string
	signer     AssertionSigner
	scopes     []string
	httpClient *http.Client

	mu          sync.RWMutex
	cachedToken *oauth2.Token
}

// JWTProfileOption configures a JWTProfileSource.
type JWTProfileOption func(*jwtProfileOptions)

type jwtProfileOptions struct {
	httpClient    *http.Client
	tokenEndpoint string
	scopes        []string
}

func defaultJWTProfileOptions() *jwtProfileOptions {
	return &jwtProfileOptions{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// WithJWTProfileHTTPClient sets a custom HTTP client for the JWT profile source.
func WithJWTProfileHTTPClient(client *http.Client) JWTProfileOption {
	return func(o *jwtProfileOptions) {
		o.httpClient = client
	}
}

// WithJWTProfileTokenEndpoint sets a static token endpoint URL instead of using OIDC discovery.
func WithJWTProfileTokenEndpoint(url string) JWTProfileOption {
	return func(o *jwtProfileOptions) {
		o.tokenEndpoint = url
	}
}

// WithJWTProfileScopes sets the scopes to request.
func WithJWTProfileScopes(scopes ...string) JWTProfileOption {
	return func(o *jwtProfileOptions) {
		o.scopes = scopes
	}
}

// NewJWTProfileSource creates a token source for JWT profile grants.
// The signer is used to create signed ID-JAG assertions for authentication.
func NewJWTProfileSource(issuer, clientID string, signer AssertionSigner, opts ...JWTProfileOption) (*JWTProfileSource, error) {
	options := defaultJWTProfileOptions()
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

	return &JWTProfileSource{
		issuer:     issuer,
		tokenURL:   tokenURL,
		clientID:   clientID,
		signer:     signer,
		scopes:     options.scopes,
		httpClient: options.httpClient,
	}, nil
}

// Token returns an access token using JWT profile grant.
// Tokens are cached and reused until they expire.
func (s *JWTProfileSource) Token() (*oauth2.Token, error) {
	// Check for cached token
	s.mu.RLock()
	if s.cachedToken != nil && s.cachedToken.Valid() {
		token := s.cachedToken
		s.mu.RUnlock()
		return token, nil
	}
	s.mu.RUnlock()

	// Get new token
	token, err := s.fetchToken()
	if err != nil {
		return nil, err
	}

	// Cache the token
	s.mu.Lock()
	s.cachedToken = token
	s.mu.Unlock()

	return token, nil
}

// fetchToken obtains a new access token using the JWT bearer grant.
func (s *JWTProfileSource) fetchToken() (*oauth2.Token, error) {
	// Create assertion with token endpoint as audience
	assertion, err := s.signer.SignAssertion([]string{s.tokenURL})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to sign assertion: %v", ErrJWTProfileFailed, err)
	}

	// Build request
	data := url.Values{}
	data.Set("grant_type", GrantTypeJWTBearer)
	data.Set("assertion", assertion)
	if s.clientID != "" {
		data.Set("client_id", s.clientID)
	}
	if len(s.scopes) > 0 {
		data.Set("scope", strings.Join(s.scopes, " "))
	}

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWTProfileFailed, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWTProfileFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrJWTProfileFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%w: %s - %s", ErrJWTProfileFailed, errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("%w: status %d", ErrJWTProfileFailed, resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Scope        string `json:"scope,omitempty"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrJWTProfileFailed, err)
	}

	token := &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
	}

	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return token, nil
}

// Invalidate clears the cached token.
func (s *JWTProfileSource) Invalidate() {
	s.mu.Lock()
	s.cachedToken = nil
	s.mu.Unlock()
}

// IDJAGAssertionSigner adapts an idjag.Assertion to the AssertionSigner interface.
type IDJAGAssertionSigner struct {
	issuer        string
	subject       string
	signingMethod jwt.SigningMethod
	privateKey    interface{}
	keyID         string
	ttl           time.Duration
	actor         *idjag.Actor
}

// IDJAGSignerOption configures an IDJAGAssertionSigner.
type IDJAGSignerOption func(*IDJAGAssertionSigner)

// WithIDJAGSignerTTL sets the TTL for generated assertions.
func WithIDJAGSignerTTL(ttl time.Duration) IDJAGSignerOption {
	return func(s *IDJAGAssertionSigner) {
		s.ttl = ttl
	}
}

// WithIDJAGSignerActor sets the actor for delegation.
func WithIDJAGSignerActor(actor *idjag.Actor) IDJAGSignerOption {
	return func(s *IDJAGAssertionSigner) {
		s.actor = actor
	}
}

// NewIDJAGAssertionSigner creates a new assertion signer using idjag.Assertion.
func NewIDJAGAssertionSigner(issuer, subject string, method jwt.SigningMethod, privateKey interface{}, keyID string, opts ...IDJAGSignerOption) *IDJAGAssertionSigner {
	signer := &IDJAGAssertionSigner{
		issuer:        issuer,
		subject:       subject,
		signingMethod: method,
		privateKey:    privateKey,
		keyID:         keyID,
		ttl:           5 * time.Minute,
	}
	for _, opt := range opts {
		opt(signer)
	}
	return signer
}

// SignAssertion creates a signed JWT assertion for the given audience.
func (s *IDJAGAssertionSigner) SignAssertion(audience []string) (string, error) {
	assertion := idjag.NewAssertion(s.issuer, s.subject, audience, s.ttl)
	if s.actor != nil {
		assertion.WithActor(s.actor)
	}

	return assertion.Sign(s.signingMethod, s.privateKey, s.keyID)
}
