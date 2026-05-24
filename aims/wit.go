package aims

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// WIT (Workload Identity Token) errors.
var (
	ErrWITMissingSubject  = errors.New("WIT must have a subject (SPIFFE ID)")
	ErrWITMissingIssuer   = errors.New("WIT must have an issuer")
	ErrWITMissingAudience = errors.New("WIT must have at least one audience")
	ErrWITExpired         = errors.New("WIT has expired")
	ErrWITNotYetValid     = errors.New("WIT is not yet valid")
	ErrWITInvalidType     = errors.New("WIT has invalid typ header")
)

// TokenTypeWIT is the JWT typ header value for Workload Identity Tokens.
const TokenTypeWIT = "wimse-id+jwt" //nolint:gosec // G101: This is a token type identifier, not a credential

// WorkloadIdentityToken (WIT) is a JWT representing workload identity.
// Per draft-ietf-wimse-s2s-protocol, a WIT is bound to a specific key
// and can be used to authenticate workload-to-workload communication.
type WorkloadIdentityToken struct {
	// Issuer identifies the SPIFFE trust domain that issued this token.
	Issuer string `json:"iss"`

	// Subject is the SPIFFE ID of the workload.
	Subject string `json:"sub"`

	// Audience contains the intended recipients of this token.
	Audience []string `json:"aud"`

	// Expiry is when this token expires.
	Expiry time.Time `json:"exp"`

	// IssuedAt is when this token was issued.
	IssuedAt time.Time `json:"iat"`

	// NotBefore is the earliest time the token is valid (optional).
	NotBefore time.Time `json:"nbf,omitempty"`

	// JWTID is a unique identifier for this token.
	JWTID string `json:"jti,omitempty"`

	// CNF contains the confirmation key binding (key proof).
	CNF *CNF `json:"cnf,omitempty"`
}

// CNF contains the confirmation key binding for a WIT.
// This proves possession of the key material.
type CNF struct {
	// JWK is an embedded JSON Web Key.
	JWK json.RawMessage `json:"jwk,omitempty"`

	// Kid is a key ID reference (when key is retrieved separately).
	Kid string `json:"kid,omitempty"`

	// X5T is the X.509 certificate SHA-256 thumbprint.
	X5T string `json:"x5t#S256,omitempty"`
}

// WITOption configures a WorkloadIdentityToken.
type WITOption func(*WorkloadIdentityToken)

// WithWITJTI sets a custom JWT ID.
func WithWITJTI(jti string) WITOption {
	return func(w *WorkloadIdentityToken) {
		w.JWTID = jti
	}
}

// WithWITNotBefore sets the not-before time.
func WithWITNotBefore(nbf time.Time) WITOption {
	return func(w *WorkloadIdentityToken) {
		w.NotBefore = nbf
	}
}

// WithWITCNF sets the confirmation key.
func WithWITCNF(cnf *CNF) WITOption {
	return func(w *WorkloadIdentityToken) {
		w.CNF = cnf
	}
}

// NewWIT creates a new Workload Identity Token.
// The SPIFFE ID's trust domain is used as the issuer.
func NewWIT(spiffeID *SPIFFEID, audience []string, ttl time.Duration, opts ...WITOption) *WorkloadIdentityToken {
	now := time.Now()
	w := &WorkloadIdentityToken{
		Issuer:   fmt.Sprintf("https://%s", spiffeID.TrustDomain),
		Subject:  spiffeID.String(),
		Audience: audience,
		IssuedAt: now,
		Expiry:   now.Add(ttl),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Validate checks if the WIT has all required fields and is temporally valid.
func (w *WorkloadIdentityToken) Validate() error {
	if w.Subject == "" {
		return ErrWITMissingSubject
	}
	if w.Issuer == "" {
		return ErrWITMissingIssuer
	}
	if len(w.Audience) == 0 {
		return ErrWITMissingAudience
	}

	now := time.Now()
	if !w.Expiry.IsZero() && now.After(w.Expiry) {
		return ErrWITExpired
	}
	if !w.NotBefore.IsZero() && now.Before(w.NotBefore) {
		return ErrWITNotYetValid
	}

	return nil
}

// Sign creates a signed JWT string from this WIT.
func (w *WorkloadIdentityToken) Sign(signer crypto.Signer, keyID string) (string, error) {
	// Determine signing method based on key type
	method := signingMethodForKey(signer)

	// Build claims
	claims := jwt.MapClaims{
		"iss": w.Issuer,
		"sub": w.Subject,
		"aud": w.Audience,
		"iat": w.IssuedAt.Unix(),
		"exp": w.Expiry.Unix(),
	}

	if w.JWTID != "" {
		claims["jti"] = w.JWTID
	}
	if !w.NotBefore.IsZero() {
		claims["nbf"] = w.NotBefore.Unix()
	}
	if w.CNF != nil {
		cnfMap := make(map[string]any)
		if len(w.CNF.JWK) > 0 {
			var jwkData any
			if err := json.Unmarshal(w.CNF.JWK, &jwkData); err == nil {
				cnfMap["jwk"] = jwkData
			}
		}
		if w.CNF.Kid != "" {
			cnfMap["kid"] = w.CNF.Kid
		}
		if w.CNF.X5T != "" {
			cnfMap["x5t#S256"] = w.CNF.X5T
		}
		if len(cnfMap) > 0 {
			claims["cnf"] = cnfMap
		}
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["typ"] = TokenTypeWIT
	token.Header["kid"] = keyID

	return token.SignedString(signer)
}

// SPIFFEID returns the SPIFFE ID from the subject claim.
func (w *WorkloadIdentityToken) SPIFFEID() (*SPIFFEID, error) {
	return ParseSPIFFEID(w.Subject)
}

// IsExpired returns true if the token has expired.
func (w *WorkloadIdentityToken) IsExpired() bool {
	return time.Now().After(w.Expiry)
}

// TimeToExpiry returns the duration until this token expires.
func (w *WorkloadIdentityToken) TimeToExpiry() time.Duration {
	ttl := w.Expiry.Sub(time.Now())
	if ttl < 0 {
		return 0
	}
	return ttl
}

// Type returns CredentialWIT.
func (w *WorkloadIdentityToken) Type() CredentialType {
	return CredentialWIT
}

// ExpiresAt returns the token's expiration time.
func (w *WorkloadIdentityToken) ExpiresAt() time.Time {
	return w.Expiry
}

// signingMethodForKey determines the appropriate JWT signing method for a key.
func signingMethodForKey(signer crypto.Signer) jwt.SigningMethod {
	pub := signer.Public()
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return jwt.SigningMethodRS256
	case *ecdsa.PublicKey:
		// Choose algorithm based on curve size
		switch k.Curve.Params().BitSize {
		case 256:
			return jwt.SigningMethodES256
		case 384:
			return jwt.SigningMethodES384
		case 521:
			return jwt.SigningMethodES512
		default:
			return jwt.SigningMethodES256
		}
	case ed25519.PublicKey:
		return jwt.SigningMethodEdDSA
	default:
		// Fallback to ES256 for unknown key types
		return jwt.SigningMethodES256
	}
}

// GenerateJTI generates a random JWT ID.
func GenerateJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

// ParseWIT parses a JWT string into a WorkloadIdentityToken without verification.
// Use this for inspection only; always verify tokens in production.
func ParseWIT(tokenString string) (*WorkloadIdentityToken, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse WIT: %w", err)
	}

	// Validate typ header if present
	if typ, ok := token.Header["typ"].(string); ok && typ != "" {
		if typ != TokenTypeWIT {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrWITInvalidType, TokenTypeWIT, typ)
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return witFromClaims(claims)
}

// witFromClaims extracts a WorkloadIdentityToken from JWT claims.
func witFromClaims(claims jwt.MapClaims) (*WorkloadIdentityToken, error) {
	w := &WorkloadIdentityToken{}

	// Extract standard claims
	if iss, ok := claims["iss"].(string); ok {
		w.Issuer = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		w.Subject = sub
	}
	if jti, ok := claims["jti"].(string); ok {
		w.JWTID = jti
	}

	// Extract audience (can be string or []interface{})
	w.Audience = extractAudience(claims)

	// Extract timestamps
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		w.IssuedAt = iat.Time
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		w.Expiry = exp.Time
	}
	if nbf, err := claims.GetNotBefore(); err == nil && nbf != nil {
		w.NotBefore = nbf.Time
	}

	// Extract CNF claim
	if cnfMap, ok := claims["cnf"].(map[string]interface{}); ok {
		w.CNF = cnfFromMap(cnfMap)
	}

	return w, nil
}

// extractAudience extracts audience from claims (handles string or array).
func extractAudience(claims jwt.MapClaims) []string {
	switch aud := claims["aud"].(type) {
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

	if jwk, ok := m["jwk"].(map[string]interface{}); ok {
		if jwkBytes, err := json.Marshal(jwk); err == nil {
			cnf.JWK = jwkBytes
		}
	}
	if kid, ok := m["kid"].(string); ok {
		cnf.Kid = kid
	}
	if x5t, ok := m["x5t#S256"].(string); ok {
		cnf.X5T = x5t
	}

	return cnf
}

// WITVerifier verifies Workload Identity Tokens.
type WITVerifier struct {
	// PublicKey is the public key used to verify signatures.
	PublicKey crypto.PublicKey

	// ExpectedIssuer is the required issuer claim value (optional).
	ExpectedIssuer string

	// ExpectedAudience is the required audience claim value (optional).
	ExpectedAudience string

	// ClockSkew allows for clock differences between systems.
	ClockSkew time.Duration
}

// NewWITVerifier creates a new WIT verifier with a public key.
func NewWITVerifier(publicKey crypto.PublicKey) *WITVerifier {
	return &WITVerifier{
		PublicKey: publicKey,
	}
}

// WithExpectedIssuer sets the expected issuer for verification.
func (v *WITVerifier) WithExpectedIssuer(issuer string) *WITVerifier {
	v.ExpectedIssuer = issuer
	return v
}

// WithExpectedAudience sets the expected audience for verification.
func (v *WITVerifier) WithExpectedAudience(audience string) *WITVerifier {
	v.ExpectedAudience = audience
	return v
}

// WithClockSkew sets the allowed clock skew for time validation.
func (v *WITVerifier) WithClockSkew(skew time.Duration) *WITVerifier {
	v.ClockSkew = skew
	return v
}

// Verify verifies a WIT JWT string and returns the parsed token.
//
//nolint:dupl // WIT and WPT verifiers have similar structure but different token types and errors
func (v *WITVerifier) Verify(tokenString string) (*WorkloadIdentityToken, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Validate typ header if present
		if typ, ok := token.Header["typ"].(string); ok && typ != "" {
			if typ != TokenTypeWIT {
				return nil, fmt.Errorf("%w: expected %s, got %s", ErrWITInvalidType, TokenTypeWIT, typ)
			}
		}
		return v.PublicKey, nil
	}

	var parserOpts []jwt.ParserOption
	if v.ClockSkew > 0 {
		parserOpts = append(parserOpts, jwt.WithLeeway(v.ClockSkew))
	}
	if v.ExpectedIssuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.ExpectedIssuer))
	}
	if v.ExpectedAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(v.ExpectedAudience))
	}

	parser := jwt.NewParser(parserOpts...)
	token, err := parser.Parse(tokenString, keyFunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrWITExpired
		}
		return nil, fmt.Errorf("WIT verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid WIT claims")
	}

	return witFromClaims(claims)
}
