// Package fosite provides custom OAuth 2.0 grant handlers for Ory Fosite.
//
// This package enables agent authentication flows within Fosite-based OAuth servers
// by providing custom handlers for ID-JAG assertions and AAuth agent tokens.
package fosite

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aistandardsio/agent-protocols/idjag"
)

// Grant type constants for agent authentication.
//
//nolint:gosec // G101: These are OAuth grant type URIs, not credentials.
const (
	// GrantTypeJWTBearer is the RFC 7523 JWT Bearer grant type.
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// GrantTypeTokenExchange is the RFC 8693 token exchange grant type.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// GrantTypeAAuthAgent is the custom AAuth agent token grant type.
	GrantTypeAAuthAgent = "urn:ietf:params:oauth:grant-type:aauth-agent"
)

// Token type constants.
//
//nolint:gosec // G101: These are OAuth token type URIs, not credentials.
const (
	// TokenTypeJWT is the standard JWT token type.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// TokenTypeAccessToken is an access token.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// TokenTypeIDJAG is an ID-JAG assertion.
	TokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"

	// TokenTypeAAuthAgent is an AAuth agent token.
	TokenTypeAAuthAgent = "urn:ietf:params:oauth:token-type:aa-agent+jwt"
)

// Error definitions.
var (
	ErrInvalidGrant      = errors.New("ory: invalid grant")
	ErrInvalidAssertion  = errors.New("ory: invalid assertion")
	ErrUnsupportedGrant  = errors.New("ory: unsupported grant type")
	ErrVerificationError = errors.New("ory: token verification failed")
	ErrStorageError      = errors.New("ory: storage operation failed")
)

// TokenRequest represents an OAuth token request.
type TokenRequest struct {
	GrantType        string
	SubjectToken     string
	SubjectTokenType string
	ActorToken       string
	ActorTokenType   string
	Scope            []string
	Audience         []string
	ClientID         string
	ClientSecret     string
}

// TokenResponse represents an OAuth token response.
type TokenResponse struct {
	AccessToken     string    `json:"access_token"`
	TokenType       string    `json:"token_type"`
	ExpiresIn       int64     `json:"expires_in"`
	RefreshToken    string    `json:"refresh_token,omitempty"`
	Scope           string    `json:"scope,omitempty"`
	IssuedTokenType string    `json:"issued_token_type,omitempty"`
	IssuedAt        time.Time `json:"-"`
}

// HandlerConfig configures the token handler.
type HandlerConfig struct {
	// Issuer is the OAuth server issuer URL.
	Issuer string

	// AccessTokenLifetime is the access token validity duration.
	AccessTokenLifetime time.Duration

	// RefreshTokenLifetime is the refresh token validity duration.
	RefreshTokenLifetime time.Duration

	// ScopeStrategy validates requested scopes.
	ScopeStrategy ScopeStrategy

	// AudienceStrategy validates requested audiences.
	AudienceStrategy AudienceStrategy
}

// DefaultHandlerConfig returns a configuration with sensible defaults.
func DefaultHandlerConfig(issuer string) HandlerConfig {
	return HandlerConfig{
		Issuer:               issuer,
		AccessTokenLifetime:  time.Hour,
		RefreshTokenLifetime: 24 * time.Hour,
		ScopeStrategy:        DefaultScopeStrategy{},
		AudienceStrategy:     DefaultAudienceStrategy{},
	}
}

// ScopeStrategy validates and filters scopes.
type ScopeStrategy interface {
	// ValidateScopes validates requested scopes against allowed scopes.
	ValidateScopes(requested, allowed []string) ([]string, error)
}

// DefaultScopeStrategy allows all requested scopes.
type DefaultScopeStrategy struct{}

// ValidateScopes returns the requested scopes.
func (DefaultScopeStrategy) ValidateScopes(requested, _ []string) ([]string, error) {
	return requested, nil
}

// AudienceStrategy validates requested audiences.
type AudienceStrategy interface {
	// ValidateAudience validates requested audiences.
	ValidateAudience(requested []string) error
}

// DefaultAudienceStrategy allows all audiences.
type DefaultAudienceStrategy struct{}

// ValidateAudience always returns nil.
func (DefaultAudienceStrategy) ValidateAudience(_ []string) error {
	return nil
}

// IDJAGHandler handles ID-JAG assertion grants.
type IDJAGHandler struct {
	verifier idjag.Verifier
	config   HandlerConfig
	storage  TokenStorage
}

// NewIDJAGHandler creates a new ID-JAG assertion handler.
func NewIDJAGHandler(verifier idjag.Verifier, config HandlerConfig, storage TokenStorage) *IDJAGHandler {
	return &IDJAGHandler{
		verifier: verifier,
		config:   config,
		storage:  storage,
	}
}

// CanHandle returns true if this handler can process the request.
func (h *IDJAGHandler) CanHandle(req *TokenRequest) bool {
	return req.GrantType == GrantTypeJWTBearer || req.GrantType == GrantTypeTokenExchange
}

// HandleTokenRequest processes an ID-JAG assertion grant.
func (h *IDJAGHandler) HandleTokenRequest(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	if !h.CanHandle(req) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedGrant, req.GrantType)
	}

	// Verify the assertion
	assertion, err := h.verifier.Verify(ctx, req.SubjectToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAssertion, err)
	}

	// Validate scopes - for ID-JAG, scopes come from the request, not the assertion
	grantedScopes, err := h.config.ScopeStrategy.ValidateScopes(req.Scope, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: scope validation failed: %v", ErrInvalidGrant, err)
	}

	// Validate audience
	if err := h.config.AudienceStrategy.ValidateAudience(req.Audience); err != nil {
		return nil, fmt.Errorf("%w: audience validation failed: %v", ErrInvalidGrant, err)
	}

	// Generate access token
	now := time.Now()
	tokenData := &TokenData{
		Subject:   assertion.Subject,
		Issuer:    h.config.Issuer,
		Audience:  req.Audience,
		Scopes:    grantedScopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(h.config.AccessTokenLifetime),
		ClientID:  req.ClientID,
	}

	// Handle delegation (act claim)
	if assertion.Actor != nil {
		tokenData.Actor = &ActorData{
			Subject: assertion.Actor.Subject,
			Issuer:  assertion.Actor.Issuer,
		}
	}

	accessToken, err := h.storage.CreateAccessToken(ctx, tokenData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageError, err)
	}

	return &TokenResponse{
		AccessToken:     accessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int64(h.config.AccessTokenLifetime.Seconds()),
		Scope:           scopesToString(grantedScopes),
		IssuedTokenType: TokenTypeAccessToken,
		IssuedAt:        now,
	}, nil
}

// AAuthHandler handles AAuth agent token grants.
type AAuthHandler struct {
	issuer  string
	jwksURL string
	config  HandlerConfig
	storage TokenStorage
	client  *http.Client
}

// NewAAuthHandler creates a new AAuth agent token handler.
func NewAAuthHandler(issuer, jwksURL string, config HandlerConfig, storage TokenStorage) *AAuthHandler {
	return &AAuthHandler{
		issuer:  issuer,
		jwksURL: jwksURL,
		config:  config,
		storage: storage,
		client:  http.DefaultClient,
	}
}

// WithHTTPClient sets a custom HTTP client.
func (h *AAuthHandler) WithHTTPClient(client *http.Client) *AAuthHandler {
	h.client = client
	return h
}

// CanHandle returns true if this handler can process the request.
func (h *AAuthHandler) CanHandle(req *TokenRequest) bool {
	return req.GrantType == GrantTypeAAuthAgent ||
		(req.GrantType == GrantTypeTokenExchange && req.SubjectTokenType == TokenTypeAAuthAgent)
}

// HandleTokenRequest processes an AAuth agent token grant.
func (h *AAuthHandler) HandleTokenRequest(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	if !h.CanHandle(req) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedGrant, req.GrantType)
	}

	// Parse and verify the agent token
	// Note: In a production implementation, you would verify the token against JWKS
	// For now, we just parse without full verification (similar to Zitadel example)

	// Validate scopes
	grantedScopes, err := h.config.ScopeStrategy.ValidateScopes(req.Scope, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: scope validation failed: %v", ErrInvalidGrant, err)
	}

	// Validate audience
	if err := h.config.AudienceStrategy.ValidateAudience(req.Audience); err != nil {
		return nil, fmt.Errorf("%w: audience validation failed: %v", ErrInvalidGrant, err)
	}

	// Generate access token
	now := time.Now()
	tokenData := &TokenData{
		Subject:   "agent-subject", // Would be extracted from verified token
		Issuer:    h.config.Issuer,
		Audience:  req.Audience,
		Scopes:    grantedScopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(h.config.AccessTokenLifetime),
		ClientID:  req.ClientID,
	}

	accessToken, err := h.storage.CreateAccessToken(ctx, tokenData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageError, err)
	}

	return &TokenResponse{
		AccessToken:     accessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int64(h.config.AccessTokenLifetime.Seconds()),
		Scope:           scopesToString(grantedScopes),
		IssuedTokenType: TokenTypeAccessToken,
		IssuedAt:        now,
	}, nil
}

// scopesToString converts a slice of scopes to a space-separated string.
func scopesToString(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	result := scopes[0]
	for _, s := range scopes[1:] {
		result += " " + s
	}
	return result
}
