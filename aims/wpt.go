package aims

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// WPT (WIMSE Proof Token) errors.
var (
	ErrWPTMissingIssuer   = errors.New("WPT must have an issuer (must match WIT subject)")
	ErrWPTMissingAudience = errors.New("WPT must have an audience")
	ErrWPTMissingHTM      = errors.New("WPT must have HTTP method (htm)")
	ErrWPTMissingHTU      = errors.New("WPT must have HTTP URI (htu)")
	ErrWPTExpired         = errors.New("WPT has expired")
	ErrWPTInvalidType     = errors.New("WPT has invalid typ header")
)

// TokenTypeWPT is the JWT typ header value for WIMSE Proof Tokens.
const TokenTypeWPT = "wimse-proof+jwt" //nolint:gosec // G101: This is a token type identifier, not a credential

// WPT header name per draft-ietf-wimse-s2s-protocol.
const (
	// HeaderWPT is the HTTP header for the WIMSE Proof Token.
	HeaderWPT = "Workload-Identity-Token"

	// HeaderDPoP is an alternative header used in some DPoP-style deployments.
	HeaderDPoP = "DPoP"
)

// WIMSEProofToken (WPT) binds authentication to a specific HTTP request.
// Per draft-ietf-wimse-s2s-protocol, a WPT proves possession of the key
// that was bound to the WIT, and binds that proof to a specific request.
type WIMSEProofToken struct {
	// Issuer must match the WIT's subject (the calling workload's SPIFFE ID).
	Issuer string `json:"iss"`

	// Audience is the target service (the recipient of the request).
	Audience string `json:"aud"`

	// IssuedAt is when this proof was created.
	IssuedAt time.Time `json:"iat"`

	// Expiry is when this proof expires (typically very short-lived).
	Expiry time.Time `json:"exp,omitempty"`

	// JWTID is a unique identifier for replay prevention.
	JWTID string `json:"jti,omitempty"`

	// Nonce for additional replay protection (if provided by server).
	Nonce string `json:"nonce,omitempty"`

	// HTM is the HTTP method (GET, POST, etc.).
	HTM string `json:"htm"`

	// HTU is the HTTP URI (typically the path and query).
	HTU string `json:"htu"`

	// ATH is the access token hash (if binding to an access token).
	ATH string `json:"ath,omitempty"`
}

// WPTOption configures a WIMSEProofToken.
type WPTOption func(*WIMSEProofToken)

// WithWPTNonce sets the nonce for replay protection.
func WithWPTNonce(nonce string) WPTOption {
	return func(p *WIMSEProofToken) {
		p.Nonce = nonce
	}
}

// WithWPTJTI sets the JWT ID for replay prevention.
func WithWPTJTI(jti string) WPTOption {
	return func(p *WIMSEProofToken) {
		p.JWTID = jti
	}
}

// WithWPTExpiry sets a custom expiry time.
func WithWPTExpiry(exp time.Time) WPTOption {
	return func(p *WIMSEProofToken) {
		p.Expiry = exp
	}
}

// WithWPTAccessToken binds the WPT to an access token via ATH claim.
func WithWPTAccessToken(accessToken string) WPTOption {
	return func(p *WIMSEProofToken) {
		p.ATH = hashAccessToken(accessToken)
	}
}

// NewWPT creates a new WIMSE Proof Token for an HTTP request.
// The issuer should be the SPIFFE ID of the calling workload (matching the WIT subject).
func NewWPT(issuer, audience, method, uri string, opts ...WPTOption) *WIMSEProofToken {
	now := time.Now()
	p := &WIMSEProofToken{
		Issuer:   issuer,
		Audience: audience,
		IssuedAt: now,
		Expiry:   now.Add(5 * time.Minute), // Default 5 minute expiry
		HTM:      strings.ToUpper(method),
		HTU:      uri,
		JWTID:    GenerateJTI(),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// NewWPTFromWIT creates a WPT bound to a WIT for an HTTP request.
func NewWPTFromWIT(wit *WorkloadIdentityToken, audience, method, uri string, opts ...WPTOption) *WIMSEProofToken {
	return NewWPT(wit.Subject, audience, method, uri, opts...)
}

// NewWPTForRequest creates a WPT bound to an http.Request.
func NewWPTForRequest(issuer, audience string, r *http.Request, opts ...WPTOption) *WIMSEProofToken {
	uri := r.URL.Path
	if r.URL.RawQuery != "" {
		uri += "?" + r.URL.RawQuery
	}
	return NewWPT(issuer, audience, r.Method, uri, opts...)
}

// Validate checks if the WPT has all required fields.
func (p *WIMSEProofToken) Validate() error {
	if p.Issuer == "" {
		return ErrWPTMissingIssuer
	}
	if p.Audience == "" {
		return ErrWPTMissingAudience
	}
	if p.HTM == "" {
		return ErrWPTMissingHTM
	}
	if p.HTU == "" {
		return ErrWPTMissingHTU
	}
	if !p.Expiry.IsZero() && time.Now().After(p.Expiry) {
		return ErrWPTExpired
	}
	return nil
}

// Sign creates a signed JWT string from this WPT.
func (p *WIMSEProofToken) Sign(signer crypto.Signer, keyID string) (string, error) {
	method := signingMethodForKey(signer)

	claims := jwt.MapClaims{
		"iss": p.Issuer,
		"aud": p.Audience,
		"iat": p.IssuedAt.Unix(),
		"htm": p.HTM,
		"htu": p.HTU,
	}

	if !p.Expiry.IsZero() {
		claims["exp"] = p.Expiry.Unix()
	}
	if p.JWTID != "" {
		claims["jti"] = p.JWTID
	}
	if p.Nonce != "" {
		claims["nonce"] = p.Nonce
	}
	if p.ATH != "" {
		claims["ath"] = p.ATH
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["typ"] = TokenTypeWPT
	token.Header["kid"] = keyID

	return token.SignedString(signer)
}

// BindToRequest adds the WPT to an HTTP request.
// The WPT is added as a signed JWT in the Workload-Identity-Token header.
func (p *WIMSEProofToken) BindToRequest(r *http.Request, signer crypto.Signer, keyID string) error {
	signed, err := p.Sign(signer, keyID)
	if err != nil {
		return err
	}
	r.Header.Set(HeaderWPT, signed)
	return nil
}

// IsExpired returns true if the proof token has expired.
func (p *WIMSEProofToken) IsExpired() bool {
	if p.Expiry.IsZero() {
		return false
	}
	return time.Now().After(p.Expiry)
}

// MatchesRequest checks if this WPT matches the given HTTP request.
func (p *WIMSEProofToken) MatchesRequest(r *http.Request) bool {
	if strings.ToUpper(r.Method) != p.HTM {
		return false
	}

	uri := r.URL.Path
	if r.URL.RawQuery != "" {
		uri += "?" + r.URL.RawQuery
	}
	return uri == p.HTU
}

// hashAccessToken computes the ATH (access token hash) for binding.
// Uses SHA-256 and base64url encoding per the spec.
func hashAccessToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// WPTFromHeader extracts a WPT JWT from an HTTP header.
func WPTFromHeader(r *http.Request) string {
	return r.Header.Get(HeaderWPT)
}

// ParseWPT parses a JWT string into a WIMSEProofToken without verification.
// Use this for inspection only; always verify tokens in production.
func ParseWPT(tokenString string) (*WIMSEProofToken, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse WPT: %w", err)
	}

	// Validate typ header if present
	if typ, ok := token.Header["typ"].(string); ok && typ != "" {
		if typ != TokenTypeWPT {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrWPTInvalidType, TokenTypeWPT, typ)
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return wptFromClaims(claims)
}

// wptFromClaims extracts a WIMSEProofToken from JWT claims.
func wptFromClaims(claims jwt.MapClaims) (*WIMSEProofToken, error) {
	p := &WIMSEProofToken{}

	// Extract standard claims
	if iss, ok := claims["iss"].(string); ok {
		p.Issuer = iss
	}
	if aud, ok := claims["aud"].(string); ok {
		p.Audience = aud
	}
	if jti, ok := claims["jti"].(string); ok {
		p.JWTID = jti
	}
	if nonce, ok := claims["nonce"].(string); ok {
		p.Nonce = nonce
	}

	// Extract HTTP binding claims
	if htm, ok := claims["htm"].(string); ok {
		p.HTM = htm
	}
	if htu, ok := claims["htu"].(string); ok {
		p.HTU = htu
	}
	if ath, ok := claims["ath"].(string); ok {
		p.ATH = ath
	}

	// Extract timestamps
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		p.IssuedAt = iat.Time
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		p.Expiry = exp.Time
	}

	return p, nil
}

// WPTVerifier verifies WIMSE Proof Tokens.
type WPTVerifier struct {
	// PublicKey is the public key used to verify signatures.
	PublicKey crypto.PublicKey

	// ExpectedIssuer is the required issuer claim value (optional).
	// Should match the WIT's subject (SPIFFE ID of the caller).
	ExpectedIssuer string

	// ExpectedAudience is the required audience claim value (optional).
	ExpectedAudience string

	// ClockSkew allows for clock differences between systems.
	ClockSkew time.Duration
}

// NewWPTVerifier creates a new WPT verifier with a public key.
func NewWPTVerifier(publicKey crypto.PublicKey) *WPTVerifier {
	return &WPTVerifier{
		PublicKey: publicKey,
	}
}

// WithExpectedIssuer sets the expected issuer for verification.
func (v *WPTVerifier) WithExpectedIssuer(issuer string) *WPTVerifier {
	v.ExpectedIssuer = issuer
	return v
}

// WithExpectedAudience sets the expected audience for verification.
func (v *WPTVerifier) WithExpectedAudience(audience string) *WPTVerifier {
	v.ExpectedAudience = audience
	return v
}

// WithClockSkew sets the allowed clock skew for time validation.
func (v *WPTVerifier) WithClockSkew(skew time.Duration) *WPTVerifier {
	v.ClockSkew = skew
	return v
}

// Verify verifies a WPT JWT string and returns the parsed token.
//
//nolint:dupl // WIT and WPT verifiers have similar structure but different token types and errors
func (v *WPTVerifier) Verify(tokenString string) (*WIMSEProofToken, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Validate typ header if present
		if typ, ok := token.Header["typ"].(string); ok && typ != "" {
			if typ != TokenTypeWPT {
				return nil, fmt.Errorf("%w: expected %s, got %s", ErrWPTInvalidType, TokenTypeWPT, typ)
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
			return nil, ErrWPTExpired
		}
		return nil, fmt.Errorf("WPT verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid WPT claims")
	}

	return wptFromClaims(claims)
}

// VerifyRequest verifies a WPT and checks it matches the given HTTP request.
func (v *WPTVerifier) VerifyRequest(tokenString string, r *http.Request) (*WIMSEProofToken, error) {
	wpt, err := v.Verify(tokenString)
	if err != nil {
		return nil, err
	}

	if !wpt.MatchesRequest(r) {
		return nil, fmt.Errorf("WPT does not match request: method=%s uri=%s", r.Method, r.URL.Path)
	}

	return wpt, nil
}
