package aauth

import (
	"crypto"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthToken represents an aa-auth+jwt token.
// This token grants an agent authorization to access a resource.
type AuthToken struct {
	// Issuer is the authorization server (Person Server or Access Server) URL.
	Issuer string `json:"iss"`

	// Subject is the AAuth ID of the authorized agent.
	Subject string `json:"sub"`

	// Audience is the resource(s) the token authorizes access to.
	Audience []string `json:"aud"`

	// IssuedAt is when the token was issued.
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time `json:"exp"`

	// JWTID is a unique identifier for the token.
	JWTID string `json:"jti,omitempty"`

	// CNF is the confirmation claim binding the token to a key (required).
	CNF *CNF `json:"cnf"`

	// Scope is the authorized scope(s).
	Scope string `json:"scope,omitempty"`

	// Actor represents the delegation chain (optional).
	Actor *Actor `json:"act,omitempty"`

	// MayAct indicates the entity may act on behalf of another.
	MayAct *Actor `json:"may_act,omitempty"`

	// Claims contains any additional custom claims.
	Claims map[string]any `json:"-"`
}

// NewAuthToken creates a new auth token with the required fields.
func NewAuthToken(issuer, subject string, audience []string, cnf *CNF, ttl time.Duration) *AuthToken {
	now := time.Now()
	return &AuthToken{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		CNF:       cnf,
	}
}

// WithScope sets the scope for the token.
func (t *AuthToken) WithScope(scope string) *AuthToken {
	t.Scope = scope
	return t
}

// WithJWTID sets the JWT ID for the token.
func (t *AuthToken) WithJWTID(jti string) *AuthToken {
	t.JWTID = jti
	return t
}

// WithActor sets the actor for delegation.
func (t *AuthToken) WithActor(actor *Actor) *AuthToken {
	t.Actor = actor
	return t
}

// WithMayAct sets the may_act claim.
func (t *AuthToken) WithMayAct(mayAct *Actor) *AuthToken {
	t.MayAct = mayAct
	return t
}

// WithClaim adds a custom claim to the token.
func (t *AuthToken) WithClaim(name string, value any) *AuthToken {
	if t.Claims == nil {
		t.Claims = make(map[string]any)
	}
	t.Claims[name] = value
	return t
}

// IsExpired returns true if the token has expired.
func (t *AuthToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// TimeToExpiry returns the time until the token expires.
func (t *AuthToken) TimeToExpiry() time.Duration {
	ttl := time.Until(t.ExpiresAt)
	if ttl < 0 {
		return 0
	}
	return ttl
}

// Validate checks that the token has all required fields.
func (t *AuthToken) Validate() error {
	if t.Issuer == "" {
		return fmt.Errorf("%w: missing issuer", ErrInvalidToken)
	}
	if t.Subject == "" {
		return fmt.Errorf("%w: missing subject", ErrInvalidToken)
	}
	if len(t.Audience) == 0 {
		return fmt.Errorf("%w: missing audience", ErrMissingAudience)
	}
	if t.CNF == nil {
		return fmt.Errorf("%w: missing cnf claim", ErrMissingCNF)
	}
	if t.IsExpired() {
		return ErrTokenExpired
	}
	return nil
}

// HasAudience checks if the token includes the specified audience.
func (t *AuthToken) HasAudience(audience string) bool {
	for _, aud := range t.Audience {
		if aud == audience {
			return true
		}
	}
	return false
}

// Sign creates a signed JWT string from the token.
func (t *AuthToken) Sign(method jwt.SigningMethod, key crypto.PrivateKey, keyID string) (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}

	claims := t.toJWTClaims()
	token := jwt.NewWithClaims(method, claims)

	// Set header fields
	token.Header["typ"] = TokenTypeAuthJWT
	if keyID != "" {
		token.Header["kid"] = keyID
	}

	return token.SignedString(key)
}

// toJWTClaims converts the AuthToken to JWT claims.
func (t *AuthToken) toJWTClaims() jwt.MapClaims {
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

	if t.Scope != "" {
		claims[ClaimScope] = t.Scope
	}

	if t.Actor != nil {
		claims[ClaimActor] = t.Actor
	}

	if t.MayAct != nil {
		claims[ClaimMayAct] = t.MayAct
	}

	// Add custom claims
	for name, value := range t.Claims {
		claims[name] = value
	}

	return claims
}

// ParseAuthToken parses a JWT string into an AuthToken without verification.
// Use this for inspection only; always verify tokens in production.
func ParseAuthToken(tokenString string) (*AuthToken, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Validate typ header matches expected token type
	if err := validateTokenType(token, TokenTypeAuthJWT); err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", ErrInvalidToken)
	}

	return authTokenFromClaims(claims)
}

// authTokenFromClaims extracts an AuthToken from JWT claims.
func authTokenFromClaims(claims jwt.MapClaims) (*AuthToken, error) {
	t := &AuthToken{
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
	if scope, ok := claims[ClaimScope].(string); ok {
		t.Scope = scope
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

	// Extract CNF claim
	if cnfMap, ok := claims[ClaimCNF].(map[string]interface{}); ok {
		t.CNF = cnfFromMap(cnfMap)
	}

	// Extract actor claim
	if actMap, ok := claims[ClaimActor].(map[string]interface{}); ok {
		t.Actor = actorFromMap(actMap)
	}

	// Extract may_act claim
	if mayActMap, ok := claims[ClaimMayAct].(map[string]interface{}); ok {
		t.MayAct = actorFromMap(mayActMap)
	}

	// Store remaining claims as custom claims
	standardClaims := map[string]bool{
		ClaimIssuer: true, ClaimSubject: true, ClaimAudience: true,
		ClaimIssuedAt: true, ClaimExpirationTime: true, ClaimJWTID: true,
		ClaimCNF: true, ClaimActor: true, ClaimScope: true, ClaimMayAct: true,
	}
	for name, value := range claims {
		if !standardClaims[name] {
			t.Claims[name] = value
		}
	}

	return t, nil
}
