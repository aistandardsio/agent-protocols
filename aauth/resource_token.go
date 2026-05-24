package aauth

import (
	"crypto"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ResourceToken represents an aa-resource+jwt token.
// This token is issued by a resource to be exchanged at an authorization server.
type ResourceToken struct {
	// Issuer is the resource URL.
	Issuer string `json:"iss"`

	// Subject is the AAuth ID of the agent.
	Subject string `json:"sub"`

	// Audience is the Person Server or Access Server URL.
	Audience []string `json:"aud"`

	// IssuedAt is when the token was issued.
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is when the token expires (typically short, < 5 minutes).
	ExpiresAt time.Time `json:"exp"`

	// JWTID is a unique identifier for the token.
	JWTID string `json:"jti,omitempty"`

	// AgentJKT is the JWK thumbprint of the agent's key.
	AgentJKT string `json:"agent_jkt"`

	// Agent is the agent identifier (AAuth ID).
	Agent string `json:"agent,omitempty"`

	// Scope is the requested scope.
	Scope string `json:"scope,omitempty"`

	// DWK is the delegate well-known URL.
	DWK string `json:"dwk,omitempty"`

	// Mission contains mission-specific claims (optional).
	Mission map[string]any `json:"mission,omitempty"`

	// Claims contains any additional custom claims.
	Claims map[string]any `json:"-"`
}

// NewResourceToken creates a new resource token with the required fields.
// Default TTL is 5 minutes per the AAuth spec recommendation.
func NewResourceToken(issuer, subject string, audience []string, agentJKT string, ttl time.Duration) *ResourceToken {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()
	return &ResourceToken{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		AgentJKT:  agentJKT,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
}

// WithScope sets the scope for the token.
func (t *ResourceToken) WithScope(scope string) *ResourceToken {
	t.Scope = scope
	return t
}

// WithJWTID sets the JWT ID for the token.
func (t *ResourceToken) WithJWTID(jti string) *ResourceToken {
	t.JWTID = jti
	return t
}

// WithAgent sets the agent identifier.
func (t *ResourceToken) WithAgent(agent string) *ResourceToken {
	t.Agent = agent
	return t
}

// WithDWK sets the delegate well-known URL.
func (t *ResourceToken) WithDWK(dwk string) *ResourceToken {
	t.DWK = dwk
	return t
}

// WithMission sets mission-specific claims.
func (t *ResourceToken) WithMission(mission map[string]any) *ResourceToken {
	t.Mission = mission
	return t
}

// WithClaim adds a custom claim to the token.
func (t *ResourceToken) WithClaim(name string, value any) *ResourceToken {
	if t.Claims == nil {
		t.Claims = make(map[string]any)
	}
	t.Claims[name] = value
	return t
}

// IsExpired returns true if the token has expired.
func (t *ResourceToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// HasAudience checks if the token has a specific audience.
func (t *ResourceToken) HasAudience(aud string) bool {
	for _, a := range t.Audience {
		if a == aud {
			return true
		}
	}
	return false
}

// TimeToExpiry returns the time until the token expires.
func (t *ResourceToken) TimeToExpiry() time.Duration {
	ttl := time.Until(t.ExpiresAt)
	if ttl < 0 {
		return 0
	}
	return ttl
}

// Validate checks that the token has all required fields.
func (t *ResourceToken) Validate() error {
	if t.Issuer == "" {
		return fmt.Errorf("%w: missing issuer", ErrInvalidToken)
	}
	if t.Subject == "" {
		return fmt.Errorf("%w: missing subject", ErrInvalidToken)
	}
	if len(t.Audience) == 0 {
		return fmt.Errorf("%w: missing audience", ErrMissingAudience)
	}
	if t.AgentJKT == "" {
		return fmt.Errorf("%w: missing agent_jkt", ErrInvalidToken)
	}
	if t.IsExpired() {
		return ErrTokenExpired
	}
	return nil
}

// Sign creates a signed JWT string from the token.
func (t *ResourceToken) Sign(method jwt.SigningMethod, key crypto.PrivateKey, keyID string) (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}

	claims := t.toJWTClaims()
	token := jwt.NewWithClaims(method, claims)

	// Set header fields
	token.Header["typ"] = TokenTypeResourceJWT
	if keyID != "" {
		token.Header["kid"] = keyID
	}

	return token.SignedString(key)
}

// toJWTClaims converts the ResourceToken to JWT claims.
func (t *ResourceToken) toJWTClaims() jwt.MapClaims {
	claims := jwt.MapClaims{
		ClaimIssuer:         t.Issuer,
		ClaimSubject:        t.Subject,
		ClaimIssuedAt:       jwt.NewNumericDate(t.IssuedAt),
		ClaimExpirationTime: jwt.NewNumericDate(t.ExpiresAt),
		ClaimAgentJKT:       t.AgentJKT,
	}

	// Handle audience (single string or array)
	if len(t.Audience) == 1 {
		claims[ClaimAudience] = t.Audience[0]
	} else if len(t.Audience) > 1 {
		claims[ClaimAudience] = t.Audience
	}

	if t.JWTID != "" {
		claims[ClaimJWTID] = t.JWTID
	}

	if t.Agent != "" {
		claims[ClaimAgent] = t.Agent
	}

	if t.Scope != "" {
		claims[ClaimScope] = t.Scope
	}

	if t.DWK != "" {
		claims[ClaimDWK] = t.DWK
	}

	if t.Mission != nil {
		claims[ClaimMission] = t.Mission
	}

	// Add custom claims
	for name, value := range t.Claims {
		claims[name] = value
	}

	return claims
}

// ParseResourceToken parses a JWT string into a ResourceToken without verification.
// Use this for inspection only; always verify tokens in production.
func ParseResourceToken(tokenString string) (*ResourceToken, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Validate typ header matches expected token type
	if err := validateTokenType(token, TokenTypeResourceJWT); err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", ErrInvalidToken)
	}

	return resourceTokenFromClaims(claims)
}

// resourceTokenFromClaims extracts a ResourceToken from JWT claims.
func resourceTokenFromClaims(claims jwt.MapClaims) (*ResourceToken, error) {
	t := &ResourceToken{
		Claims: make(map[string]any),
	}

	// Extract standard claims
	if iss, ok := claims[ClaimIssuer].(string); ok {
		t.Issuer = iss
	}
	if sub, ok := claims[ClaimSubject].(string); ok {
		t.Subject = sub
	}
	if jti, ok := claims[ClaimJWTID].(string); ok {
		t.JWTID = jti
	}
	if agentJKT, ok := claims[ClaimAgentJKT].(string); ok {
		t.AgentJKT = agentJKT
	}
	if agent, ok := claims[ClaimAgent].(string); ok {
		t.Agent = agent
	}
	if scope, ok := claims[ClaimScope].(string); ok {
		t.Scope = scope
	}
	if dwk, ok := claims[ClaimDWK].(string); ok {
		t.DWK = dwk
	}

	// Extract audience
	t.Audience = extractAudience(claims)

	// Extract timestamps
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		t.IssuedAt = iat.Time
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		t.ExpiresAt = exp.Time
	}

	// Extract mission
	if mission, ok := claims[ClaimMission].(map[string]interface{}); ok {
		t.Mission = mission
	}

	// Store remaining claims as custom claims
	standardClaims := map[string]bool{
		ClaimIssuer: true, ClaimSubject: true, ClaimAudience: true,
		ClaimIssuedAt: true, ClaimExpirationTime: true, ClaimJWTID: true,
		ClaimAgentJKT: true, ClaimAgent: true, ClaimScope: true,
		ClaimDWK: true, ClaimMission: true,
	}
	for name, value := range claims {
		if !standardClaims[name] {
			t.Claims[name] = value
		}
	}

	return t, nil
}
