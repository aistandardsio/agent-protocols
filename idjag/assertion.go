package idjag

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Assertion represents an ID-JAG identity assertion.
// It contains the standard JWT claims plus the optional "act" claim for delegation.
type Assertion struct {
	// Issuer identifies the principal that issued the assertion (iss claim).
	Issuer string `json:"iss"`

	// Subject identifies the principal that is the subject of the assertion (sub claim).
	// For direct agent authentication, this is the agent's identity.
	// For delegation, this is the human/principal identity being delegated.
	Subject string `json:"sub"`

	// Audience identifies the recipients that the assertion is intended for (aud claim).
	// Typically includes the authorization server's token endpoint.
	Audience []string `json:"aud"`

	// IssuedAt is the time at which the assertion was issued (iat claim).
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is the expiration time of the assertion (exp claim).
	ExpiresAt time.Time `json:"exp"`

	// NotBefore is the time before which the assertion is not valid (nbf claim).
	NotBefore time.Time `json:"nbf,omitempty"`

	// JWTID is a unique identifier for the assertion (jti claim).
	JWTID string `json:"jti,omitempty"`

	// Actor identifies the acting party in delegation scenarios (act claim).
	// When present, Subject identifies the delegating principal and Actor
	// identifies the party acting on their behalf.
	Actor *Actor `json:"act,omitempty"`

	// Claims contains additional custom claims not covered by the standard fields.
	Claims map[string]any `json:"-"`
}

// Actor represents the acting party in a delegation chain.
// Per RFC 8693, this appears in the "act" claim.
type Actor struct {
	// Subject identifies the actor (sub claim within act).
	Subject string `json:"sub"`

	// Issuer optionally identifies who asserted this actor's identity.
	Issuer string `json:"iss,omitempty"`

	// Actor allows for nested delegation chains.
	// For example, User -> Agent1 -> Agent2.
	Actor *Actor `json:"act,omitempty"`
}

// NewAssertion creates a new Assertion with common fields populated.
func NewAssertion(issuer, subject string, audience []string, ttl time.Duration) *Assertion {
	now := time.Now()
	return &Assertion{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
}

// NewDelegatedAssertion creates an assertion representing delegation.
// The subject is the delegating principal (e.g., human user), and the
// actorSubject is the acting party (e.g., agent).
func NewDelegatedAssertion(issuer, subject, actorSubject string, audience []string, ttl time.Duration) *Assertion {
	a := NewAssertion(issuer, subject, audience, ttl)
	a.Actor = &Actor{Subject: actorSubject}
	return a
}

// WithActor adds an actor to the assertion for delegation.
func (a *Assertion) WithActor(actor *Actor) *Assertion {
	a.Actor = actor
	return a
}

// WithClaim adds a custom claim to the assertion.
func (a *Assertion) WithClaim(name string, value any) *Assertion {
	if a.Claims == nil {
		a.Claims = make(map[string]any)
	}
	a.Claims[name] = value
	return a
}

// IsExpired returns true if the assertion has expired.
func (a *Assertion) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// IsDelegated returns true if the assertion represents delegation (has an actor).
func (a *Assertion) IsDelegated() bool {
	return a.Actor != nil
}

// DelegationChain returns the full chain of actors from outermost to innermost.
// For non-delegated assertions, returns nil.
func (a *Assertion) DelegationChain() []*Actor {
	if a.Actor == nil {
		return nil
	}
	var chain []*Actor
	current := a.Actor
	for current != nil {
		chain = append(chain, current)
		current = current.Actor
	}
	return chain
}

// Sign creates a signed JWT string from the assertion.
func (a *Assertion) Sign(method jwt.SigningMethod, key crypto.PrivateKey, keyID string) (string, error) {
	claims := a.toJWTClaims()

	token := jwt.NewWithClaims(method, claims)
	if keyID != "" {
		token.Header["kid"] = keyID
	}

	return token.SignedString(key)
}

// toJWTClaims converts the assertion to jwt.MapClaims.
func (a *Assertion) toJWTClaims() jwt.MapClaims {
	claims := jwt.MapClaims{
		ClaimIssuer:         a.Issuer,
		ClaimSubject:        a.Subject,
		ClaimIssuedAt:       jwt.NewNumericDate(a.IssuedAt),
		ClaimExpirationTime: jwt.NewNumericDate(a.ExpiresAt),
	}

	// Handle audience (can be string or array)
	if len(a.Audience) == 1 {
		claims[ClaimAudience] = a.Audience[0]
	} else if len(a.Audience) > 1 {
		claims[ClaimAudience] = a.Audience
	}

	if !a.NotBefore.IsZero() {
		claims[ClaimNotBefore] = jwt.NewNumericDate(a.NotBefore)
	}

	if a.JWTID != "" {
		claims[ClaimJWTID] = a.JWTID
	}

	if a.Actor != nil {
		claims[ClaimActor] = a.Actor.toMap()
	}

	// Add custom claims
	for k, v := range a.Claims {
		claims[k] = v
	}

	return claims
}

// toMap converts Actor to a map for JWT encoding.
func (actor *Actor) toMap() map[string]any {
	m := map[string]any{
		ClaimSubject: actor.Subject,
	}
	if actor.Issuer != "" {
		m[ClaimIssuer] = actor.Issuer
	}
	if actor.Actor != nil {
		m[ClaimActor] = actor.Actor.toMap()
	}
	return m
}

// ParseAssertion parses a JWT string into an Assertion without verification.
// Use Verifier.Verify for validated parsing.
func ParseAssertion(tokenString string) (*Assertion, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAssertion, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidAssertion
	}

	return assertionFromClaims(claims)
}

// assertionFromClaims constructs an Assertion from JWT claims.
func assertionFromClaims(claims jwt.MapClaims) (*Assertion, error) {
	a := &Assertion{
		Claims: make(map[string]any),
	}

	// Parse issuer
	if iss, ok := claims[ClaimIssuer].(string); ok {
		a.Issuer = iss
	}

	// Parse subject
	if sub, ok := claims[ClaimSubject].(string); ok {
		a.Subject = sub
	}

	// Parse audience (can be string or []interface{})
	switch aud := claims[ClaimAudience].(type) {
	case string:
		a.Audience = []string{aud}
	case []any:
		for _, v := range aud {
			if s, ok := v.(string); ok {
				a.Audience = append(a.Audience, s)
			}
		}
	}

	// Parse timestamps
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		a.IssuedAt = iat.Time
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		a.ExpiresAt = exp.Time
	}
	if nbf, err := claims.GetNotBefore(); err == nil && nbf != nil {
		a.NotBefore = nbf.Time
	}

	// Parse JWT ID
	if jti, ok := claims[ClaimJWTID].(string); ok {
		a.JWTID = jti
	}

	// Parse actor claim
	if act, ok := claims[ClaimActor].(map[string]any); ok {
		a.Actor = actorFromMap(act)
	}

	// Collect remaining claims
	standardClaims := map[string]bool{
		ClaimIssuer: true, ClaimSubject: true, ClaimAudience: true,
		ClaimIssuedAt: true, ClaimExpirationTime: true, ClaimNotBefore: true,
		ClaimJWTID: true, ClaimActor: true,
	}
	for k, v := range claims {
		if !standardClaims[k] {
			a.Claims[k] = v
		}
	}

	return a, nil
}

// actorFromMap constructs an Actor from a map.
func actorFromMap(m map[string]any) *Actor {
	actor := &Actor{}
	if sub, ok := m[ClaimSubject].(string); ok {
		actor.Subject = sub
	}
	if iss, ok := m[ClaimIssuer].(string); ok {
		actor.Issuer = iss
	}
	if nestedAct, ok := m[ClaimActor].(map[string]any); ok {
		actor.Actor = actorFromMap(nestedAct)
	}
	return actor
}

// MarshalJSON implements custom JSON marshaling for Assertion.
func (a *Assertion) MarshalJSON() ([]byte, error) {
	type alias Assertion
	data := struct {
		*alias
		IssuedAt  int64 `json:"iat"`
		ExpiresAt int64 `json:"exp"`
		NotBefore int64 `json:"nbf,omitempty"`
	}{
		alias:     (*alias)(a),
		IssuedAt:  a.IssuedAt.Unix(),
		ExpiresAt: a.ExpiresAt.Unix(),
	}
	if !a.NotBefore.IsZero() {
		data.NotBefore = a.NotBefore.Unix()
	}
	return json.Marshal(data)
}
