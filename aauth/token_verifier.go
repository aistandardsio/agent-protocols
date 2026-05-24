package aauth

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenVerifier verifies AAuth tokens.
type TokenVerifier interface {
	// VerifyAgentToken verifies an agent token and returns the parsed token.
	VerifyAgentToken(ctx context.Context, tokenString string) (*AgentToken, error)

	// VerifyAuthToken verifies an auth token and returns the parsed token.
	VerifyAuthToken(ctx context.Context, tokenString string) (*AuthToken, error)

	// VerifyResourceToken verifies a resource token and returns the parsed token.
	VerifyResourceToken(ctx context.Context, tokenString string) (*ResourceToken, error)
}

// TokenVerifierOptions configures a TokenVerifier.
type TokenVerifierOptions struct {
	// PublicKey is the key used for verification.
	PublicKey crypto.PublicKey

	// KeyID is the expected key ID (optional).
	KeyID string

	// Issuer is the expected issuer (optional).
	Issuer string

	// Audience is the expected audience (optional).
	Audience string

	// AllowedAlgorithms restricts which algorithms are accepted.
	AllowedAlgorithms []string

	// ClockSkew is the allowed clock skew for expiration checking.
	ClockSkew time.Duration
}

// StaticKeyVerifier verifies tokens using a static public key.
type StaticKeyVerifier struct {
	opts TokenVerifierOptions
}

// NewStaticKeyVerifier creates a new verifier with a static public key.
func NewStaticKeyVerifier(publicKey crypto.PublicKey, opts ...TokenVerifierOption) (*StaticKeyVerifier, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is required")
	}

	v := &StaticKeyVerifier{
		opts: TokenVerifierOptions{
			PublicKey: publicKey,
		},
	}

	for _, opt := range opts {
		opt(&v.opts)
	}

	return v, nil
}

// TokenVerifierOption configures a TokenVerifier.
type TokenVerifierOption func(*TokenVerifierOptions)

// WithVerifierKeyID sets the expected key ID.
func WithVerifierKeyID(keyID string) TokenVerifierOption {
	return func(opts *TokenVerifierOptions) {
		opts.KeyID = keyID
	}
}

// WithVerifierIssuer sets the expected issuer.
func WithVerifierIssuer(issuer string) TokenVerifierOption {
	return func(opts *TokenVerifierOptions) {
		opts.Issuer = issuer
	}
}

// WithVerifierAudience sets the expected audience.
func WithVerifierAudience(audience string) TokenVerifierOption {
	return func(opts *TokenVerifierOptions) {
		opts.Audience = audience
	}
}

// WithVerifierAllowedAlgorithms sets the allowed algorithms.
func WithVerifierAllowedAlgorithms(algorithms []string) TokenVerifierOption {
	return func(opts *TokenVerifierOptions) {
		opts.AllowedAlgorithms = algorithms
	}
}

// WithVerifierClockSkew sets the allowed clock skew.
func WithVerifierClockSkew(skew time.Duration) TokenVerifierOption {
	return func(opts *TokenVerifierOptions) {
		opts.ClockSkew = skew
	}
}

// VerifyAgentToken verifies an agent token.
func (v *StaticKeyVerifier) VerifyAgentToken(ctx context.Context, tokenString string) (*AgentToken, error) {
	claims, err := v.verifyToken(tokenString, TokenTypeAgentJWT)
	if err != nil {
		return nil, err
	}

	token, err := agentTokenFromClaims(claims)
	if err != nil {
		return nil, err
	}

	// Validate required fields
	if token.CNF == nil {
		return nil, ErrMissingCNF
	}

	return token, nil
}

// VerifyAuthToken verifies an auth token.
func (v *StaticKeyVerifier) VerifyAuthToken(ctx context.Context, tokenString string) (*AuthToken, error) {
	claims, err := v.verifyToken(tokenString, TokenTypeAuthJWT)
	if err != nil {
		return nil, err
	}

	token, err := authTokenFromClaims(claims)
	if err != nil {
		return nil, err
	}

	// Validate required fields
	if token.CNF == nil {
		return nil, ErrMissingCNF
	}
	if len(token.Audience) == 0 {
		return nil, ErrMissingAudience
	}

	// Check audience if specified
	if v.opts.Audience != "" && !token.HasAudience(v.opts.Audience) {
		return nil, ErrAudienceMismatch
	}

	return token, nil
}

// VerifyResourceToken verifies a resource token.
func (v *StaticKeyVerifier) VerifyResourceToken(ctx context.Context, tokenString string) (*ResourceToken, error) {
	claims, err := v.verifyToken(tokenString, TokenTypeResourceJWT)
	if err != nil {
		return nil, err
	}

	token, err := resourceTokenFromClaims(claims)
	if err != nil {
		return nil, err
	}

	// Validate required fields
	if token.AgentJKT == "" {
		return nil, fmt.Errorf("%w: missing agent_jkt", ErrInvalidToken)
	}

	// Check audience if specified
	if v.opts.Audience != "" {
		found := false
		for _, aud := range token.Audience {
			if aud == v.opts.Audience {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrAudienceMismatch
		}
	}

	return token, nil
}

// verifyToken performs JWT verification and returns the claims.
func (v *StaticKeyVerifier) verifyToken(tokenString string, expectedType string) (jwt.MapClaims, error) {
	// Parse and verify the token
	parserOpts := []jwt.ParserOption{
		jwt.WithLeeway(v.opts.ClockSkew),
	}

	if v.opts.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.opts.Issuer))
	}

	if v.opts.Audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(v.opts.Audience))
	}

	parser := jwt.NewParser(parserOpts...)

	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check token type if present in header
		if typ, ok := token.Header["typ"].(string); ok && expectedType != "" {
			if typ != expectedType {
				return nil, fmt.Errorf("%w: expected type %s, got %s", ErrInvalidToken, expectedType, typ)
			}
		}

		// Check key ID if specified
		if v.opts.KeyID != "" {
			if kid, ok := token.Header["kid"].(string); ok && kid != v.opts.KeyID {
				return nil, fmt.Errorf("%w: key ID mismatch", ErrKeyNotFound)
			}
		}

		// Check algorithm if restricted
		if len(v.opts.AllowedAlgorithms) > 0 {
			allowed := false
			for _, alg := range v.opts.AllowedAlgorithms {
				if token.Method.Alg() == alg {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, fmt.Errorf("%w: algorithm %s not allowed", ErrUnsupportedAlgorithm, token.Method.Alg())
			}
		}

		return v.opts.PublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	if !token.Valid {
		return nil, ErrSignatureInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", ErrInvalidToken)
	}

	return claims, nil
}

// HTTPClient is an interface for making HTTP requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// JWKSVerifier verifies tokens using a JWKS endpoint.
type JWKSVerifier struct {
	jwksURL    string
	httpClient HTTPClient
	opts       TokenVerifierOptions

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	lastFetch time.Time
	cacheTTL  time.Duration
}

// NewJWKSVerifier creates a new verifier that fetches keys from a JWKS endpoint.
func NewJWKSVerifier(jwksURL string, opts ...TokenVerifierOption) *JWKSVerifier {
	v := &JWKSVerifier{
		jwksURL:    jwksURL,
		httpClient: http.DefaultClient,
		keys:       make(map[string]crypto.PublicKey),
		cacheTTL:   15 * time.Minute,
	}

	for _, opt := range opts {
		opt(&v.opts)
	}

	return v
}

// WithHTTPClient sets a custom HTTP client.
func (v *JWKSVerifier) WithHTTPClient(client HTTPClient) *JWKSVerifier {
	v.httpClient = client
	return v
}

// WithCacheTTL sets the cache TTL for JWKS keys.
func (v *JWKSVerifier) WithCacheTTL(ttl time.Duration) *JWKSVerifier {
	v.cacheTTL = ttl
	return v
}

// VerifyAgentToken verifies an agent token using JWKS.
func (v *JWKSVerifier) VerifyAgentToken(ctx context.Context, tokenString string) (*AgentToken, error) {
	claims, err := v.verifyToken(ctx, tokenString, TokenTypeAgentJWT)
	if err != nil {
		return nil, err
	}

	token, err := agentTokenFromClaims(claims)
	if err != nil {
		return nil, err
	}

	if token.CNF == nil {
		return nil, ErrMissingCNF
	}

	return token, nil
}

// VerifyAuthToken verifies an auth token using JWKS.
func (v *JWKSVerifier) VerifyAuthToken(ctx context.Context, tokenString string) (*AuthToken, error) {
	claims, err := v.verifyToken(ctx, tokenString, TokenTypeAuthJWT)
	if err != nil {
		return nil, err
	}

	token, err := authTokenFromClaims(claims)
	if err != nil {
		return nil, err
	}

	if token.CNF == nil {
		return nil, ErrMissingCNF
	}

	return token, nil
}

// VerifyResourceToken verifies a resource token using JWKS.
func (v *JWKSVerifier) VerifyResourceToken(ctx context.Context, tokenString string) (*ResourceToken, error) {
	claims, err := v.verifyToken(ctx, tokenString, TokenTypeResourceJWT)
	if err != nil {
		return nil, err
	}

	token, err := resourceTokenFromClaims(claims)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// verifyToken verifies a token using JWKS-fetched keys.
func (v *JWKSVerifier) verifyToken(ctx context.Context, tokenString string, expectedType string) (jwt.MapClaims, error) {
	parserOpts := []jwt.ParserOption{
		jwt.WithLeeway(v.opts.ClockSkew),
	}

	if v.opts.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.opts.Issuer))
	}

	if v.opts.Audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(v.opts.Audience))
	}

	parser := jwt.NewParser(parserOpts...)

	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check token type if present in header
		if typ, ok := token.Header["typ"].(string); ok && expectedType != "" {
			if typ != expectedType {
				return nil, fmt.Errorf("%w: expected type %s, got %s", ErrInvalidToken, expectedType, typ)
			}
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
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	if !token.Valid {
		return nil, ErrSignatureInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", ErrInvalidToken)
	}

	return claims, nil
}

// getKey retrieves a key from the cache or fetches from JWKS.
func (v *JWKSVerifier) getKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	// Check cache first
	v.mu.RLock()
	key, ok := v.keys[kid]
	needRefresh := time.Since(v.lastFetch) > v.cacheTTL
	v.mu.RUnlock()

	if ok && !needRefresh {
		return key, nil
	}

	// Fetch JWKS
	if err := v.refreshKeys(ctx); err != nil {
		// If we have a cached key, use it even if refresh failed
		if ok {
			return key, nil
		}
		return nil, err
	}

	// Check cache again after refresh
	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: key %s not found in JWKS", ErrKeyNotFound, kid)
	}

	return key, nil
}

// refreshKeys fetches the JWKS and updates the cache.
func (v *JWKSVerifier) refreshKeys(ctx context.Context) error {
	//nolint:gosec // G704: jwksURL is set by the application developer via NewJWKSVerifier, not user input
	req, err := http.NewRequestWithContext(ctx, "GET", v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("%w: failed to create request: %v", ErrDiscoveryFailed, err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: failed to fetch JWKS: %v", ErrDiscoveryFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: JWKS returned status %d", ErrDiscoveryFailed, resp.StatusCode)
	}

	// Read and parse JWKS
	var jwks JWKS
	if err := decodeJSONFromReader(resp.Body, &jwks); err != nil {
		return fmt.Errorf("%w: failed to parse JWKS: %v", ErrDiscoveryFailed, err)
	}

	// Convert JWKs to public keys
	keys := make(map[string]crypto.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kid == "" {
			continue
		}
		pubKey, err := JWKToPublicKey(&jwk)
		if err != nil {
			continue // Skip invalid keys
		}
		keys[jwk.Kid] = pubKey
	}

	// Update cache
	v.mu.Lock()
	v.keys = keys
	v.lastFetch = time.Now()
	v.mu.Unlock()

	return nil
}

// decodeJSONFromReader decodes JSON from an io.Reader.
func decodeJSONFromReader(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}
