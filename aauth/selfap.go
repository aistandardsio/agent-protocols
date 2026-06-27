package aauth

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SelfAPClient enables an agent to act as its own Authorization Provider.
// This is used when an agent can self-issue tokens without requiring
// an external authorization server.
type SelfAPClient struct {
	// Agent identity
	agentID *AAuthID
	keyPair *KeyPair

	// Token configuration
	issuer        string
	tokenTTL      time.Duration
	signingMethod jwt.SigningMethod

	// Metadata for well-known endpoint
	metadata *SelfAPMetadata
}

// SelfAPMetadata describes the capabilities of a self-AP.
type SelfAPMetadata struct {
	// Issuer is the issuer identifier (usually the agent's domain).
	Issuer string `json:"issuer"`

	// JWKSURI is the URL for the agent's public keys.
	JWKSURI string `json:"jwks_uri,omitempty"`

	// TokenEndpoint is where token requests should be sent (usually self).
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// SupportedGrantTypes lists supported grant types.
	SupportedGrantTypes []string `json:"grant_types_supported"`

	// SupportedScopes lists available scopes.
	SupportedScopes []string `json:"scopes_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported lists supported auth methods.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// ResponseTypesSupported lists supported response types.
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`

	// SelfIssued indicates this is a self-issued AP.
	SelfIssued bool `json:"self_issued"`
}

// SelfAPOption configures a SelfAPClient.
type SelfAPOption func(*SelfAPClient)

// WithSelfAPIssuer sets the issuer for self-issued tokens.
func WithSelfAPIssuer(issuer string) SelfAPOption {
	return func(c *SelfAPClient) {
		c.issuer = issuer
	}
}

// WithSelfAPTokenTTL sets the TTL for self-issued tokens.
func WithSelfAPTokenTTL(ttl time.Duration) SelfAPOption {
	return func(c *SelfAPClient) {
		c.tokenTTL = ttl
	}
}

// WithSelfAPSigningMethod sets the JWT signing method.
func WithSelfAPSigningMethod(method jwt.SigningMethod) SelfAPOption {
	return func(c *SelfAPClient) {
		c.signingMethod = method
	}
}

// WithSelfAPMetadata sets the AP metadata.
func WithSelfAPMetadata(metadata *SelfAPMetadata) SelfAPOption {
	return func(c *SelfAPClient) {
		c.metadata = metadata
	}
}

// NewSelfAPClient creates a new self-AP client.
func NewSelfAPClient(agentID *AAuthID, privateKey crypto.PrivateKey, opts ...SelfAPOption) (*SelfAPClient, error) {
	if agentID == nil {
		return nil, fmt.Errorf("agent ID is required")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	kp, err := keyPairFromPrivateKey(privateKey, agentID.Local)
	if err != nil {
		return nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	c := &SelfAPClient{
		agentID:       agentID,
		keyPair:       kp,
		issuer:        fmt.Sprintf("https://%s", agentID.Domain),
		tokenTTL:      1 * time.Hour,
		signingMethod: jwt.SigningMethodES256,
	}

	for _, opt := range opts {
		opt(c)
	}

	// Set default metadata if not provided
	if c.metadata == nil {
		c.metadata = &SelfAPMetadata{
			Issuer:              c.issuer,
			SupportedGrantTypes: []string{GrantTypeTokenExchange},
			SelfIssued:          true,
		}
	}

	return c, nil
}

// IssueAgentToken creates a self-issued agent token.
func (c *SelfAPClient) IssueAgentToken(ctx context.Context, audience ...string) (string, error) {
	cnf, err := c.keyPair.ToCNF()
	if err != nil {
		return "", fmt.Errorf("failed to create CNF: %w", err)
	}

	token := NewAgentToken(c.issuer, c.agentID.String(), cnf, c.tokenTTL)

	if len(audience) > 0 {
		token.WithAudience(audience...)
	}

	return token.Sign(c.signingMethod, c.keyPair.PrivateKey, c.keyPair.KeyID)
}

// IssueAuthToken creates a self-issued authorization token.
// This is used when the agent can authorize itself for certain operations.
func (c *SelfAPClient) IssueAuthToken(ctx context.Context, scope string, audience ...string) (string, error) {
	cnf, err := c.keyPair.ToCNF()
	if err != nil {
		return "", fmt.Errorf("failed to create CNF: %w", err)
	}

	token := NewAuthToken(c.issuer, c.agentID.String(), audience, cnf, c.tokenTTL)
	token.WithScope(scope)

	return token.Sign(c.signingMethod, c.keyPair.PrivateKey, c.keyPair.KeyID)
}

// IssueMissionToken creates a token with mission claims.
func (c *SelfAPClient) IssueMissionToken(ctx context.Context, mission *MissionClaims, audience ...string) (string, error) {
	cnf, err := c.keyPair.ToCNF()
	if err != nil {
		return "", fmt.Errorf("failed to create CNF: %w", err)
	}

	// Build scopes from permissions
	var scopes []string
	for _, p := range mission.Permissions {
		if p.Scope != "" {
			scopes = append(scopes, p.Scope)
		}
	}

	token := NewAuthToken(c.issuer, c.agentID.String(), audience, cnf, c.tokenTTL)
	token.WithScope(joinScopes(scopes))

	// Add mission claims
	token.Mission = mission
	token.InteractionType = mission.InteractionType

	return token.Sign(c.signingMethod, c.keyPair.PrivateKey, c.keyPair.KeyID)
}

// IssueDelegatedToken creates a token for delegation to another agent.
func (c *SelfAPClient) IssueDelegatedToken(ctx context.Context, delegateTo string, scope string, audience ...string) (string, error) {
	cnf, err := c.keyPair.ToCNF()
	if err != nil {
		return "", fmt.Errorf("failed to create CNF: %w", err)
	}

	token := NewAuthToken(c.issuer, c.agentID.String(), audience, cnf, c.tokenTTL)
	token.WithScope(scope)

	// Add may_act claim for delegation
	token.MayAct = &Actor{
		Subject: delegateTo,
	}

	return token.Sign(c.signingMethod, c.keyPair.PrivateKey, c.keyPair.KeyID)
}

// Metadata returns the self-AP metadata for well-known endpoint.
func (c *SelfAPClient) Metadata() *SelfAPMetadata {
	return c.metadata
}

// JWKS returns the JWK Set containing the agent's public key.
func (c *SelfAPClient) JWKS() (*JWKSet, error) {
	jwk, err := c.keyPair.ToJWK()
	if err != nil {
		return nil, err
	}
	return &JWKSet{Keys: []JWK{*jwk}}, nil
}

// SelfAPHandler provides HTTP handlers for self-AP endpoints.
type SelfAPHandler struct {
	client *SelfAPClient
}

// NewSelfAPHandler creates handlers for self-AP endpoints.
func NewSelfAPHandler(client *SelfAPClient) *SelfAPHandler {
	return &SelfAPHandler{client: client}
}

// joinScopes joins scopes with space separator.
func joinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	result := scopes[0]
	for i := 1; i < len(scopes); i++ {
		result += " " + scopes[i]
	}
	return result
}
