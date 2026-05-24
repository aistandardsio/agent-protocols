package aauth

import (
	"crypto"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AgentToken represents an aa-agent+jwt token.
// This token proves the identity of an agent and binds it to a cryptographic key.
type AgentToken struct {
	// Issuer is the agent provider URL.
	Issuer string `json:"iss"`

	// Subject is the AAuth ID of the agent (e.g., "aauth:calendar-bot@example.com").
	Subject string `json:"sub"`

	// Audience is the intended audience (typically the resource URL).
	Audience []string `json:"aud,omitempty"`

	// IssuedAt is when the token was issued.
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time `json:"exp"`

	// JWTID is a unique identifier for the token.
	JWTID string `json:"jti,omitempty"`

	// CNF is the confirmation claim binding the token to a key (required).
	CNF *CNF `json:"cnf"`

	// DWK is the delegate well-known URL for the agent provider.
	DWK string `json:"dwk,omitempty"`

	// PS is the person server URL (optional).
	PS string `json:"ps,omitempty"`

	// Actor represents a delegation chain (optional).
	Actor *Actor `json:"act,omitempty"`

	// Claims contains any additional custom claims.
	Claims map[string]any `json:"-"`
}

// Actor represents an actor in a delegation chain (RFC 8693).
type Actor struct {
	// Subject is the subject of the actor.
	Subject string `json:"sub"`

	// Issuer is the issuer of the actor's identity.
	Issuer string `json:"iss,omitempty"`

	// Actor is a nested actor for multi-level delegation.
	Actor *Actor `json:"act,omitempty"`
}

// NewAgentToken creates a new agent token with the required fields.
func NewAgentToken(issuer, subject string, cnf *CNF, ttl time.Duration) *AgentToken {
	now := time.Now()
	return &AgentToken{
		Issuer:    issuer,
		Subject:   subject,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		CNF:       cnf,
	}
}

// WithAudience sets the audience for the token.
func (t *AgentToken) WithAudience(audience ...string) *AgentToken {
	t.Audience = audience
	return t
}

// WithJWTID sets the JWT ID for the token.
func (t *AgentToken) WithJWTID(jti string) *AgentToken {
	t.JWTID = jti
	return t
}

// WithDWK sets the delegate well-known URL.
func (t *AgentToken) WithDWK(dwk string) *AgentToken {
	t.DWK = dwk
	return t
}

// WithPS sets the person server URL.
func (t *AgentToken) WithPS(ps string) *AgentToken {
	t.PS = ps
	return t
}

// WithActor sets the actor for delegation.
func (t *AgentToken) WithActor(actor *Actor) *AgentToken {
	t.Actor = actor
	return t
}

// WithClaim adds a custom claim to the token.
func (t *AgentToken) WithClaim(name string, value any) *AgentToken {
	if t.Claims == nil {
		t.Claims = make(map[string]any)
	}
	t.Claims[name] = value
	return t
}

// IsExpired returns true if the token has expired.
func (t *AgentToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// TimeToExpiry returns the time until the token expires.
func (t *AgentToken) TimeToExpiry() time.Duration {
	ttl := time.Until(t.ExpiresAt)
	if ttl < 0 {
		return 0
	}
	return ttl
}

// Validate checks that the token has all required fields.
func (t *AgentToken) Validate() error {
	if t.Issuer == "" {
		return fmt.Errorf("%w: missing issuer", ErrInvalidToken)
	}
	if t.Subject == "" {
		return fmt.Errorf("%w: missing subject", ErrInvalidToken)
	}
	if t.CNF == nil {
		return fmt.Errorf("%w: missing cnf claim", ErrMissingCNF)
	}
	if t.IsExpired() {
		return ErrTokenExpired
	}
	return nil
}

// Sign creates a signed JWT string from the token.
func (t *AgentToken) Sign(method jwt.SigningMethod, key crypto.PrivateKey, keyID string) (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}

	claims := t.toJWTClaims()
	token := jwt.NewWithClaims(method, claims)

	// Set header fields
	token.Header["typ"] = TokenTypeAgentJWT
	if keyID != "" {
		token.Header["kid"] = keyID
	}

	return token.SignedString(key)
}

// toJWTClaims converts the AgentToken to JWT claims.
func (t *AgentToken) toJWTClaims() jwt.MapClaims {
	claims := jwt.MapClaims{
		ClaimIssuer:         t.Issuer,
		ClaimSubject:        t.Subject,
		ClaimIssuedAt:       jwt.NewNumericDate(t.IssuedAt),
		ClaimExpirationTime: jwt.NewNumericDate(t.ExpiresAt),
		ClaimCNF:            t.CNF,
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

	if t.DWK != "" {
		claims[ClaimDWK] = t.DWK
	}

	if t.PS != "" {
		claims[ClaimPS] = t.PS
	}

	if t.Actor != nil {
		claims[ClaimActor] = t.Actor
	}

	// Add custom claims
	for name, value := range t.Claims {
		claims[name] = value
	}

	return claims
}

// ParseAgentToken parses a JWT string into an AgentToken without verification.
// Use this for inspection only; always verify tokens in production.
func ParseAgentToken(tokenString string) (*AgentToken, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Validate typ header matches expected token type
	if err := validateTokenType(token, TokenTypeAgentJWT); err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", ErrInvalidToken)
	}

	return agentTokenFromClaims(claims)
}

// validateTokenType checks that the JWT typ header matches the expected type.
// Returns nil if the typ header is missing, "JWT" (default), or matches the expected type.
// The "JWT" default is accepted for backward compatibility with legacy tokens.
func validateTokenType(token *jwt.Token, expectedType string) error {
	typ, ok := token.Header["typ"].(string)
	if !ok || typ == "" {
		// typ header is optional per JWT spec; skip validation if missing
		return nil
	}
	// Accept "JWT" as a valid value for backward compatibility
	// (golang-jwt sets this as default when typ is not specified)
	if typ == "JWT" {
		return nil
	}
	if typ != expectedType {
		return fmt.Errorf("%w: expected typ %s, got %s", ErrInvalidToken, expectedType, typ)
	}
	return nil
}

// agentTokenFromClaims extracts an AgentToken from JWT claims.
func agentTokenFromClaims(claims jwt.MapClaims) (*AgentToken, error) {
	t := &AgentToken{
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
	if dwk, ok := claims[ClaimDWK].(string); ok {
		t.DWK = dwk
	}
	if ps, ok := claims[ClaimPS].(string); ok {
		t.PS = ps
	}

	// Extract audience (can be string or []interface{})
	t.Audience = extractAudience(claims)

	// Extract timestamps
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		t.IssuedAt = iat.Time
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		t.ExpiresAt = exp.Time
	}

	// Extract CNF claim
	if cnfMap, ok := claims[ClaimCNF].(map[string]interface{}); ok {
		t.CNF = cnfFromMap(cnfMap)
	}

	// Extract actor claim
	if actMap, ok := claims[ClaimActor].(map[string]interface{}); ok {
		t.Actor = actorFromMap(actMap)
	}

	// Store remaining claims as custom claims
	standardClaims := map[string]bool{
		ClaimIssuer: true, ClaimSubject: true, ClaimAudience: true,
		ClaimIssuedAt: true, ClaimExpirationTime: true, ClaimJWTID: true,
		ClaimCNF: true, ClaimActor: true, ClaimDWK: true, ClaimPS: true,
	}
	for name, value := range claims {
		if !standardClaims[name] {
			t.Claims[name] = value
		}
	}

	return t, nil
}

// extractAudience extracts audience from claims (handles string or array).
func extractAudience(claims jwt.MapClaims) []string {
	switch aud := claims[ClaimAudience].(type) {
	case string:
		return []string{aud}
	case []interface{}:
		result := make([]string, 0, len(aud))
		for _, a := range aud {
			if s, ok := a.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return aud
	default:
		return nil
	}
}

// cnfFromMap extracts a CNF from a map.
func cnfFromMap(m map[string]interface{}) *CNF {
	cnf := &CNF{}

	if jwk, ok := m[CNFClaimJWK].(map[string]interface{}); ok {
		// Re-marshal the JWK to JSON
		if jwkBytes, err := jsonMarshal(jwk); err == nil {
			cnf.JWK = jwkBytes
		}
	}
	if jku, ok := m[CNFClaimJKU].(string); ok {
		cnf.JKU = jku
	}
	if kid, ok := m[CNFClaimKID].(string); ok {
		cnf.Kid = kid
	}

	return cnf
}

// actorFromMap extracts an Actor from a map.
func actorFromMap(m map[string]interface{}) *Actor {
	actor := &Actor{}

	if sub, ok := m["sub"].(string); ok {
		actor.Subject = sub
	}
	if iss, ok := m["iss"].(string); ok {
		actor.Issuer = iss
	}
	if actMap, ok := m["act"].(map[string]interface{}); ok {
		actor.Actor = actorFromMap(actMap)
	}

	return actor
}

// jsonMarshal is a helper for JSON marshaling within this package.
func jsonMarshal(v interface{}) ([]byte, error) {
	// Use encoding/json directly
	return encodeJSON(v)
}
