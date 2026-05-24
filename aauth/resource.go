package aauth

import (
	"context"
	"crypto"
	"fmt"
	"time"
)

// ResourceServer handles AAuth authentication on the resource side.
type ResourceServer struct {
	url       string
	keyPair   *KeyPair
	opts      *resourceOptions
	challenge *Challenge
}

// NewResourceServer creates a new resource server.
func NewResourceServer(url string, privateKey crypto.PrivateKey, keyID string, opts ...ResourceOption) (*ResourceServer, error) {
	if url == "" {
		return nil, fmt.Errorf("resource URL is required")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	// Create key pair
	kp, err := keyPairFromPrivateKey(privateKey, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	options := defaultResourceOptions()
	for _, opt := range opts {
		opt(options)
	}

	// Create default challenge
	challenge := NewChallenge(url)
	if options.personServerURL != "" {
		challenge.WithPersonServer(options.personServerURL)
	}
	if options.accessServerURL != "" {
		challenge.WithAccessServer(options.accessServerURL)
	}
	if options.requiredScope != "" {
		challenge.WithScope(options.requiredScope)
	}

	return &ResourceServer{
		url:       url,
		keyPair:   kp,
		opts:      options,
		challenge: challenge,
	}, nil
}

// URL returns the resource server URL.
func (rs *ResourceServer) URL() string {
	return rs.url
}

// Challenge returns the WWW-Authenticate challenge for this resource.
func (rs *ResourceServer) Challenge() *Challenge {
	return rs.challenge
}

// ChallengeHeader returns the WWW-Authenticate header value.
func (rs *ResourceServer) ChallengeHeader() string {
	return rs.challenge.String()
}

// IssueResourceToken creates a resource token for token exchange.
func (rs *ResourceServer) IssueResourceToken(agentID *AAuthID, agentJKT string, scope string) (*ResourceToken, error) {
	if agentID == nil {
		return nil, fmt.Errorf("agent ID is required")
	}
	if agentJKT == "" {
		return nil, fmt.Errorf("agent JKT is required")
	}

	// Determine audience (PS or AS)
	var audience []string
	if rs.opts.personServerURL != "" {
		audience = append(audience, rs.opts.personServerURL)
	}
	if rs.opts.accessServerURL != "" {
		audience = append(audience, rs.opts.accessServerURL)
	}
	if len(audience) == 0 {
		return nil, fmt.Errorf("no person server or access server configured")
	}

	token := NewResourceToken(
		rs.url,
		agentID.String(),
		audience,
		agentJKT,
		rs.opts.resourceTokenTTL,
	).
		WithAgent(agentID.String())

	if scope != "" {
		token.WithScope(scope)
	} else if rs.opts.requiredScope != "" {
		token.WithScope(rs.opts.requiredScope)
	}

	return token, nil
}

// SignResourceToken creates and signs a resource token.
func (rs *ResourceServer) SignResourceToken(agentID *AAuthID, agentJKT string, scope string) (string, error) {
	token, err := rs.IssueResourceToken(agentID, agentJKT, scope)
	if err != nil {
		return "", err
	}

	return token.Sign(rs.opts.signingMethod, rs.keyPair.PrivateKey, rs.keyPair.KeyID)
}

// KeyPair returns the resource server's key pair.
func (rs *ResourceServer) KeyPair() *KeyPair {
	return rs.keyPair
}

// Options returns the resource server options.
func (rs *ResourceServer) Options() *resourceOptions {
	return rs.opts
}

// VerifyAgentToken verifies an agent token.
func (rs *ResourceServer) VerifyAgentToken(ctx context.Context, tokenString string) (*AgentToken, error) {
	if rs.opts.agentTokenVerifier != nil {
		return rs.opts.agentTokenVerifier.VerifyAgentToken(ctx, tokenString)
	}

	// Parse without verification for now (in production, use JWKS verifier)
	token, err := ParseAgentToken(tokenString)
	if err != nil {
		return nil, err
	}

	if token.IsExpired() {
		return nil, ErrTokenExpired
	}

	return token, nil
}

// VerifyAuthToken verifies an auth token.
func (rs *ResourceServer) VerifyAuthToken(ctx context.Context, tokenString string) (*AuthToken, error) {
	if rs.opts.authTokenVerifier != nil {
		return rs.opts.authTokenVerifier.VerifyAuthToken(ctx, tokenString)
	}

	// Parse without verification for now (in production, use JWKS verifier)
	token, err := ParseAuthToken(tokenString)
	if err != nil {
		return nil, err
	}

	if token.IsExpired() {
		return nil, ErrTokenExpired
	}

	// Check audience
	if !token.HasAudience(rs.url) {
		return nil, ErrAudienceMismatch
	}

	return token, nil
}

// PublicJWKS returns the public keys as a JWKS for discovery.
func (rs *ResourceServer) PublicJWKS() (*JWKS, error) {
	jwk, err := rs.keyPair.ToJWK()
	if err != nil {
		return nil, err
	}

	return &JWKS{
		Keys: []JWK{*jwk},
	}, nil
}

// ResourceMetadata represents the .well-known/aauth-resource.json metadata.
type ResourceMetadata struct {
	// Resource is the resource URL.
	Resource string `json:"resource"`

	// JWKSURI is the URL to the resource's JWKS.
	JWKSURI string `json:"jwks_uri,omitempty"`

	// PersonServerURI is the person server URL.
	PersonServerURI string `json:"person_server_uri,omitempty"`

	// AccessServerURI is the access server URL.
	AccessServerURI string `json:"access_server_uri,omitempty"`

	// ScopesSupported lists supported scopes.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// SigningAlgorithmsSupported lists supported signing algorithms.
	SigningAlgorithmsSupported []string `json:"signing_algs_supported,omitempty"`
}

// Metadata returns the resource metadata for discovery.
func (rs *ResourceServer) Metadata() *ResourceMetadata {
	return &ResourceMetadata{
		Resource:                   rs.url,
		JWKSURI:                    rs.url + "/.well-known/jwks.json",
		PersonServerURI:            rs.opts.personServerURL,
		AccessServerURI:            rs.opts.accessServerURL,
		ScopesSupported:            []string{rs.opts.requiredScope},
		SigningAlgorithmsSupported: []string{rs.opts.signingMethod.Alg()},
	}
}

// ResourceTokenExchangeRequest represents a request to exchange tokens.
type ResourceTokenExchangeRequest struct {
	// AgentToken is the agent's identity token.
	AgentToken *AgentToken

	// AgentJKT is the agent's JWK thumbprint.
	AgentJKT string

	// Scope is the requested scope.
	Scope string
}

// CreateTokenExchangeResponse creates a resource token for exchange.
func (rs *ResourceServer) CreateTokenExchangeResponse(req *ResourceTokenExchangeRequest) (string, error) {
	agentID, err := ParseAAuthID(req.AgentToken.Subject)
	if err != nil {
		return "", fmt.Errorf("invalid agent subject: %w", err)
	}

	return rs.SignResourceToken(agentID, req.AgentJKT, req.Scope)
}

// TokenResponse represents a token exchange response.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// CreateTokenResponse creates a token response with the given token.
func CreateTokenResponse(token string, expiresIn time.Duration, scope string) *TokenResponse {
	return &TokenResponse{
		AccessToken:     token,
		TokenType:       "Bearer",
		ExpiresIn:       int(expiresIn.Seconds()),
		Scope:           scope,
		IssuedTokenType: TokenTypeURIResourceJWT,
	}
}
