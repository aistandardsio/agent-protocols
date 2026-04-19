package aims

import (
	"crypto"
	"crypto/rand"
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
)

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
	switch pub.(type) {
	case interface{ Size() int }:
		// RSA key - use RS256 by default
		return jwt.SigningMethodRS256
	default:
		// For other key types, try ES256 (common for EC keys)
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
