package idjag

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Verifier validates ID-JAG assertions.
type Verifier interface {
	// Verify validates the JWT and returns the parsed Assertion.
	Verify(ctx context.Context, tokenString string) (*Assertion, error)
}

// VerifierOptions configures assertion verification.
type VerifierOptions struct {
	// ExpectedIssuer is the required issuer claim value.
	// If empty, issuer is not validated.
	ExpectedIssuer string

	// ExpectedAudience is the required audience claim value.
	// If empty, audience is not validated.
	ExpectedAudience string

	// AllowedAlgorithms restricts which signing algorithms are accepted.
	// If empty, defaults to RS256, RS384, RS512, ES256, ES384, ES512.
	AllowedAlgorithms []string

	// ClockSkew allows for clock differences between systems.
	// Default is 0 (strict timing).
	ClockSkew time.Duration

	// RequireActor requires the assertion to have an actor claim.
	RequireActor bool
}

// StaticKeyVerifier verifies JWTs using a pre-configured public key.
type StaticKeyVerifier struct {
	publicKey crypto.PublicKey
	keyID     string
	opts      VerifierOptions
}

// NewStaticKeyVerifier creates a verifier with a single public key.
func NewStaticKeyVerifier(publicKey crypto.PublicKey, keyID string, opts VerifierOptions) *StaticKeyVerifier {
	return &StaticKeyVerifier{
		publicKey: publicKey,
		keyID:     keyID,
		opts:      opts,
	}
}

// Verify validates the JWT signature and claims.
func (v *StaticKeyVerifier) Verify(ctx context.Context, tokenString string) (*Assertion, error) {
	keyFunc := func(token *jwt.Token) (any, error) {
		// Validate algorithm
		if !v.isAllowedAlgorithm(token.Method.Alg()) {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, token.Method.Alg())
		}

		// Validate key ID if specified
		if v.keyID != "" {
			if kid, ok := token.Header["kid"].(string); ok && kid != v.keyID {
				return nil, ErrKeyNotFound
			}
		}

		return v.publicKey, nil
	}

	return v.parseAndValidate(tokenString, keyFunc)
}

func (v *StaticKeyVerifier) isAllowedAlgorithm(alg string) bool {
	allowed := v.opts.AllowedAlgorithms
	if len(allowed) == 0 {
		allowed = []string{AlgorithmRS256, AlgorithmRS384, AlgorithmRS512,
			AlgorithmES256, AlgorithmES384, AlgorithmES512}
	}
	for _, a := range allowed {
		if a == alg {
			return true
		}
	}
	return false
}

func (v *StaticKeyVerifier) parseAndValidate(tokenString string, keyFunc jwt.Keyfunc) (*Assertion, error) {
	var parserOpts []jwt.ParserOption
	if v.opts.ClockSkew > 0 {
		parserOpts = append(parserOpts, jwt.WithLeeway(v.opts.ClockSkew))
	}
	if v.opts.ExpectedIssuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.opts.ExpectedIssuer))
	}
	if v.opts.ExpectedAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(v.opts.ExpectedAudience))
	}

	parser := jwt.NewParser(parserOpts...)
	token, err := parser.Parse(tokenString, keyFunc)
	if err != nil {
		if err == jwt.ErrTokenExpired {
			return nil, ErrExpiredAssertion
		}
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidAssertion
	}

	assertion, err := assertionFromClaims(claims)
	if err != nil {
		return nil, err
	}

	// Additional validation
	if v.opts.RequireActor && assertion.Actor == nil {
		return nil, fmt.Errorf("%w: act claim required", ErrMissingRequiredClaim)
	}

	return assertion, nil
}

// JWKSVerifier verifies JWTs using keys fetched from a JWKS endpoint.
type JWKSVerifier struct {
	jwksURL    string
	httpClient *http.Client
	opts       VerifierOptions

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	lastFetch time.Time
	cacheTTL  time.Duration
}

// NewJWKSVerifier creates a verifier that fetches keys from a JWKS endpoint.
func NewJWKSVerifier(jwksURL string, opts VerifierOptions) *JWKSVerifier {
	return &JWKSVerifier{
		jwksURL:    jwksURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		opts:       opts,
		keys:       make(map[string]crypto.PublicKey),
		cacheTTL:   5 * time.Minute,
	}
}

// WithHTTPClient sets a custom HTTP client for JWKS fetching.
func (v *JWKSVerifier) WithHTTPClient(client *http.Client) *JWKSVerifier {
	v.httpClient = client
	return v
}

// WithCacheTTL sets the cache duration for JWKS keys.
func (v *JWKSVerifier) WithCacheTTL(ttl time.Duration) *JWKSVerifier {
	v.cacheTTL = ttl
	return v
}

// Verify validates the JWT signature and claims using JWKS.
func (v *JWKSVerifier) Verify(ctx context.Context, tokenString string) (*Assertion, error) {
	keyFunc := func(token *jwt.Token) (any, error) {
		// Get key ID from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("%w: missing kid header", ErrKeyNotFound)
		}

		// Try to get key from cache
		key, err := v.getKey(ctx, kid)
		if err != nil {
			return nil, err
		}

		return key, nil
	}

	sv := &StaticKeyVerifier{opts: v.opts}
	return sv.parseAndValidate(tokenString, keyFunc)
}

func (v *JWKSVerifier) getKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.RLock()
	key, found := v.keys[kid]
	needsRefresh := time.Since(v.lastFetch) > v.cacheTTL
	v.mu.RUnlock()

	if found && !needsRefresh {
		return key, nil
	}

	// Refresh JWKS
	if err := v.refresh(ctx); err != nil {
		// If we have a cached key, use it even if refresh failed
		if found {
			return key, nil
		}
		return nil, err
	}

	v.mu.RLock()
	key, found = v.keys[kid]
	v.mu.RUnlock()

	if !found {
		return nil, ErrKeyNotFound
	}

	return key, nil
}

func (v *JWKSVerifier) refresh(ctx context.Context) error {
	//nolint:gosec // G704: JWKS URL is configured by application, not user input
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}

	//nolint:gosec // G704: JWKS URL is configured by application, not user input
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch failed: status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	keys := make(map[string]crypto.PublicKey)
	for _, key := range jwks.Keys {
		pubKey, err := key.ToPublicKey()
		if err != nil {
			continue // Skip invalid keys
		}
		keys[key.KeyID] = pubKey
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

// NewJWKFromRSAPublicKey creates a JWK from an RSA public key.
func NewJWKFromRSAPublicKey(pubKey *rsa.PublicKey, keyID, algorithm string) JWK {
	return JWK{
		KeyType:   "RSA",
		KeyID:     keyID,
		Algorithm: algorithm,
		Use:       "sig",
		N:         base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}
}

// NewJWKFromECPublicKey creates a JWK from an EC public key.
func NewJWKFromECPublicKey(pubKey *ecdsa.PublicKey, keyID, algorithm string) JWK {
	var curveName string
	switch pubKey.Curve.Params().BitSize {
	case 256:
		curveName = "P-256"
	case 384:
		curveName = "P-384"
	case 521:
		curveName = "P-521"
	}

	return JWK{
		KeyType:   "EC",
		KeyID:     keyID,
		Algorithm: algorithm,
		Use:       "sig",
		Curve:     curveName,
		X:         base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
		Y:         base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
	}
}
