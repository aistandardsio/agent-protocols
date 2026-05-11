package zitadel

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/aims"
	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

// DefaultAllowedAlgorithms is the default set of allowed signing algorithms.
var DefaultAllowedAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"ES256", "ES384", "ES512",
	"PS256", "PS384", "PS512",
}

// Verifier validates tokens against Zitadel's JWKS.
type Verifier struct {
	issuer            string
	jwksURL           string
	httpClient        *http.Client
	allowedAlgorithms []string
	clockSkew         time.Duration
	cacheTTL          time.Duration

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	lastFetch time.Time
}

// VerifierOption configures a Verifier.
type VerifierOption func(*verifierOptions)

type verifierOptions struct {
	httpClient        *http.Client
	jwksURL           string
	allowedAlgorithms []string
	clockSkew         time.Duration
	cacheTTL          time.Duration
}

func defaultVerifierOptions() *verifierOptions {
	return &verifierOptions{
		httpClient:        &http.Client{Timeout: 30 * time.Second},
		allowedAlgorithms: DefaultAllowedAlgorithms,
		clockSkew:         time.Minute,
		cacheTTL:          15 * time.Minute,
	}
}

// WithVerifierHTTPClient sets a custom HTTP client for the verifier.
func WithVerifierHTTPClient(client *http.Client) VerifierOption {
	return func(o *verifierOptions) {
		o.httpClient = client
	}
}

// WithStaticJWKSURL sets a static JWKS URL instead of using OIDC discovery.
func WithStaticJWKSURL(url string) VerifierOption {
	return func(o *verifierOptions) {
		o.jwksURL = url
	}
}

// WithAllowedAlgorithms sets the allowed signing algorithms.
func WithAllowedAlgorithms(algs ...string) VerifierOption {
	return func(o *verifierOptions) {
		o.allowedAlgorithms = algs
	}
}

// WithClockSkew sets the allowed clock skew for token validation.
func WithClockSkew(d time.Duration) VerifierOption {
	return func(o *verifierOptions) {
		o.clockSkew = d
	}
}

// WithCacheTTL sets the JWKS cache duration.
func WithCacheTTL(d time.Duration) VerifierOption {
	return func(o *verifierOptions) {
		o.cacheTTL = d
	}
}

// NewVerifier creates a Zitadel-backed token verifier.
// It uses OIDC discovery to find the JWKS endpoint unless WithStaticJWKSURL is used.
func NewVerifier(issuer string, opts ...VerifierOption) (*Verifier, error) {
	options := defaultVerifierOptions()
	for _, opt := range opts {
		opt(options)
	}

	jwksURL := options.jwksURL
	if jwksURL == "" {
		// Discover JWKS URL
		discovered, err := discoverJWKSURL(issuer, options.httpClient)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
		}
		jwksURL = discovered
	}

	return &Verifier{
		issuer:            issuer,
		jwksURL:           jwksURL,
		httpClient:        options.httpClient,
		allowedAlgorithms: options.allowedAlgorithms,
		clockSkew:         options.clockSkew,
		cacheTTL:          options.cacheTTL,
		keys:              make(map[string]crypto.PublicKey),
	}, nil
}

// Issuer returns the Zitadel issuer URL.
func (v *Verifier) Issuer() string {
	return v.issuer
}

// JWKSURL returns the JWKS endpoint URL.
func (v *Verifier) JWKSURL() string {
	return v.jwksURL
}

// VerifyIDJAGAssertion verifies an ID-JAG assertion token.
func (v *Verifier) VerifyIDJAGAssertion(ctx context.Context, tokenString string) (*idjag.Assertion, error) {
	claims, err := v.verifyToken(ctx, tokenString, "")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	return assertionFromClaims(claims)
}

// VerifyAIMSWIT verifies an AIMS Workload Identity Token.
func (v *Verifier) VerifyAIMSWIT(ctx context.Context, tokenString string) (*aims.WorkloadIdentityToken, error) {
	claims, err := v.verifyToken(ctx, tokenString, "")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	return witFromClaims(claims)
}

// VerifyAAuthAgentToken verifies an AAuth agent token.
func (v *Verifier) VerifyAAuthAgentToken(ctx context.Context, tokenString string) (*aauth.AgentToken, error) {
	claims, err := v.verifyToken(ctx, tokenString, aauth.TokenTypeAgentJWT)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	return agentTokenFromClaims(claims)
}

// verifyToken performs JWT verification and returns the claims.
func (v *Verifier) verifyToken(ctx context.Context, tokenString string, expectedType string) (jwt.MapClaims, error) {
	parserOpts := []jwt.ParserOption{
		jwt.WithLeeway(v.clockSkew),
		jwt.WithIssuer(v.issuer),
	}

	parser := jwt.NewParser(parserOpts...)

	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check token type if expected
		if expectedType != "" {
			if typ, ok := token.Header["typ"].(string); ok && typ != expectedType {
				return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidTokenType, expectedType, typ)
			}
		}

		// Validate algorithm
		if !v.isAllowedAlgorithm(token.Method.Alg()) {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, token.Method.Alg())
		}

		// Get key ID from header
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("%w: missing kid in token header", ErrKeyNotFound)
		}

		// Get the key
		key, err := v.getKey(ctx, kid)
		if err != nil {
			return nil, err
		}

		return key, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, ErrVerificationFailed
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", ErrVerificationFailed)
	}

	return claims, nil
}

// isAllowedAlgorithm checks if an algorithm is in the allowed list.
func (v *Verifier) isAllowedAlgorithm(alg string) bool {
	for _, a := range v.allowedAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

// getKey retrieves a key from cache or JWKS.
func (v *Verifier) getKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	// Check cache first
	v.mu.RLock()
	key, found := v.keys[kid]
	needsRefresh := time.Since(v.lastFetch) > v.cacheTTL
	v.mu.RUnlock()

	if found && !needsRefresh {
		return key, nil
	}

	// Refresh JWKS
	if err := v.refreshKeys(ctx); err != nil {
		// If we have a cached key, use it even if refresh failed
		if found {
			return key, nil
		}
		return nil, err
	}

	// Check cache again after refresh
	v.mu.RLock()
	key, found = v.keys[kid]
	v.mu.RUnlock()

	if !found {
		return nil, fmt.Errorf("%w: key %s not found in JWKS", ErrKeyNotFound, kid)
	}

	return key, nil
}

// refreshKeys fetches the JWKS and updates the cache.
func (v *Verifier) refreshKeys(ctx context.Context) error {
	//nolint:gosec // G107: jwksURL is from trusted discovery
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch failed: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return err
	}

	keys := make(map[string]crypto.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == "" {
			continue
		}
		pubKey, err := jwk.ToPublicKey()
		if err != nil {
			continue // Skip invalid keys
		}
		keys[jwk.KeyID] = pubKey
	}

	v.mu.Lock()
	v.keys = keys
	v.lastFetch = time.Now()
	v.mu.Unlock()

	return nil
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg,omitempty"`
	Use       string `json:"use,omitempty"`

	// RSA parameters
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent

	// EC parameters
	Curve string `json:"crv,omitempty"` // Curve name
	X     string `json:"x,omitempty"`   // X coordinate
	Y     string `json:"y,omitempty"`   // Y coordinate
}

// ToPublicKey converts a JWK to a crypto.PublicKey.
func (k *JWK) ToPublicKey() (crypto.PublicKey, error) {
	switch k.KeyType {
	case "RSA":
		return k.toRSAPublicKey()
	case "EC":
		return k.toECPublicKey()
	default:
		return nil, fmt.Errorf("%w: key type %s", ErrUnsupportedAlgorithm, k.KeyType)
	}
}

func (k *JWK) toRSAPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	return &rsa.PublicKey{N: n, E: e}, nil
}

func (k *JWK) toECPublicKey() (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}

	curve, err := curveFromName(k.Curve)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func curveFromName(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: curve %s", ErrUnsupportedAlgorithm, name)
	}
}

// Helper functions to convert JWT claims to protocol-specific types

// assertionFromClaims converts JWT claims to an idjag.Assertion.
func assertionFromClaims(claims jwt.MapClaims) (*idjag.Assertion, error) {
	a := &idjag.Assertion{
		Claims: make(map[string]any),
	}

	// Parse standard claims
	if iss, ok := claims["iss"].(string); ok {
		a.Issuer = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		a.Subject = sub
	}

	// Parse audience
	switch aud := claims["aud"].(type) {
	case string:
		a.Audience = []string{aud}
	case []interface{}:
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
	if jti, ok := claims["jti"].(string); ok {
		a.JWTID = jti
	}

	// Parse actor claim
	if act, ok := claims["act"].(map[string]interface{}); ok {
		a.Actor = actorFromMap(act)
	}

	// Collect remaining claims
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true,
		"iat": true, "exp": true, "nbf": true,
		"jti": true, "act": true,
	}
	for k, v := range claims {
		if !standardClaims[k] {
			a.Claims[k] = v
		}
	}

	return a, nil
}

// actorFromMap converts a map to an idjag.Actor.
func actorFromMap(m map[string]interface{}) *idjag.Actor {
	actor := &idjag.Actor{}
	if sub, ok := m["sub"].(string); ok {
		actor.Subject = sub
	}
	if iss, ok := m["iss"].(string); ok {
		actor.Issuer = iss
	}
	if nestedAct, ok := m["act"].(map[string]interface{}); ok {
		actor.Actor = actorFromMap(nestedAct)
	}
	return actor
}

// witFromClaims converts JWT claims to an aims.WorkloadIdentityToken.
func witFromClaims(claims jwt.MapClaims) (*aims.WorkloadIdentityToken, error) {
	wit := &aims.WorkloadIdentityToken{}

	// Parse standard claims
	if iss, ok := claims["iss"].(string); ok {
		wit.Issuer = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		wit.Subject = sub
	}

	// Parse audience
	switch aud := claims["aud"].(type) {
	case string:
		wit.Audience = []string{aud}
	case []interface{}:
		for _, v := range aud {
			if s, ok := v.(string); ok {
				wit.Audience = append(wit.Audience, s)
			}
		}
	}

	// Parse timestamps
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		wit.IssuedAt = iat.Time
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		wit.Expiry = exp.Time
	}
	if nbf, err := claims.GetNotBefore(); err == nil && nbf != nil {
		wit.NotBefore = nbf.Time
	}

	// Parse JWT ID
	if jti, ok := claims["jti"].(string); ok {
		wit.JWTID = jti
	}

	// Parse CNF claim
	if cnfMap, ok := claims["cnf"].(map[string]interface{}); ok {
		wit.CNF = aimsCnfFromMap(cnfMap)
	}

	return wit, nil
}

// aimsCnfFromMap converts a map to an aims.CNF.
func aimsCnfFromMap(m map[string]interface{}) *aims.CNF {
	cnf := &aims.CNF{}
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

// agentTokenFromClaims converts JWT claims to an aauth.AgentToken.
func agentTokenFromClaims(claims jwt.MapClaims) (*aauth.AgentToken, error) {
	t := &aauth.AgentToken{
		Claims: make(map[string]any),
	}

	// Parse standard claims
	if iss, ok := claims["iss"].(string); ok {
		t.Issuer = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		t.Subject = sub
	}
	if jti, ok := claims["jti"].(string); ok {
		t.JWTID = jti
	}

	// Parse audience
	switch aud := claims["aud"].(type) {
	case string:
		t.Audience = []string{aud}
	case []interface{}:
		for _, v := range aud {
			if s, ok := v.(string); ok {
				t.Audience = append(t.Audience, s)
			}
		}
	}

	// Parse timestamps
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		t.IssuedAt = iat.Time
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		t.ExpiresAt = exp.Time
	}

	// Parse AAuth-specific claims
	if dwk, ok := claims["dwk"].(string); ok {
		t.DWK = dwk
	}
	if ps, ok := claims["ps"].(string); ok {
		t.PS = ps
	}

	// Parse CNF claim
	if cnfMap, ok := claims["cnf"].(map[string]interface{}); ok {
		t.CNF = aAuthCnfFromMap(cnfMap)
	}

	// Parse actor claim
	if actMap, ok := claims["act"].(map[string]interface{}); ok {
		t.Actor = aAuthActorFromMap(actMap)
	}

	// Collect remaining claims
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true,
		"iat": true, "exp": true, "jti": true,
		"cnf": true, "act": true, "dwk": true, "ps": true,
	}
	for k, v := range claims {
		if !standardClaims[k] {
			t.Claims[k] = v
		}
	}

	return t, nil
}

// aAuthCnfFromMap converts a map to an aauth.CNF.
func aAuthCnfFromMap(m map[string]interface{}) *aauth.CNF {
	cnf := &aauth.CNF{}
	if jwk, ok := m["jwk"].(map[string]interface{}); ok {
		if jwkBytes, err := json.Marshal(jwk); err == nil {
			cnf.JWK = jwkBytes
		}
	}
	if jku, ok := m["jku"].(string); ok {
		cnf.JKU = jku
	}
	if kid, ok := m["kid"].(string); ok {
		cnf.Kid = kid
	}
	return cnf
}

// aAuthActorFromMap converts a map to an aauth.Actor.
func aAuthActorFromMap(m map[string]interface{}) *aauth.Actor {
	actor := &aauth.Actor{}
	if sub, ok := m["sub"].(string); ok {
		actor.Subject = sub
	}
	if iss, ok := m["iss"].(string); ok {
		actor.Issuer = iss
	}
	if nestedAct, ok := m["act"].(map[string]interface{}); ok {
		actor.Actor = aAuthActorFromMap(nestedAct)
	}
	return actor
}
