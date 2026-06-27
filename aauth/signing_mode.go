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
)

// SigningMode identifies the method used to provide and verify signing keys.
type SigningMode string

// Supported signing modes per AAuth specification.
const (
	// SigningModeJWT embeds the public key as a JWK in the agent token CNF claim.
	// This is the default mode for agents with self-contained identity.
	SigningModeJWT SigningMode = "jwt"

	// SigningModeJWKSURI references a remote JWKS URL for key resolution.
	// The CNF claim contains jku (URL) and kid (key ID).
	SigningModeJWKSURI SigningMode = "jwks_uri"

	// SigningModeJKTJWT uses a JWT thumbprint for key confirmation.
	// The CNF claim contains only the jkt (JWK thumbprint).
	SigningModeJKTJWT SigningMode = "jkt-jwt"

	// SigningModeHWK indicates hardware key-backed signatures.
	// Used with TPM, HSM, or secure enclave-backed keys.
	SigningModeHWK SigningMode = "hwk"
)

// SignatureKeyProvider resolves signing keys for different signing modes.
// Implementations handle key storage, retrieval, and cryptographic operations.
type SignatureKeyProvider interface {
	// Mode returns the signing mode this provider supports.
	Mode() SigningMode

	// Sign signs the given data using the provider's private key.
	Sign(ctx context.Context, data []byte) ([]byte, error)

	// PublicKey returns the public key for signature verification.
	PublicKey(ctx context.Context) (crypto.PublicKey, error)

	// CNF returns the confirmation claim for this key provider.
	// The format depends on the signing mode (embedded JWK, JKU reference, etc.).
	CNF(ctx context.Context) (*CNF, error)

	// KeyID returns the key identifier.
	KeyID() string

	// Algorithm returns the signing algorithm (e.g., "ES256", "RS256").
	Algorithm() string
}

// JWTKeyProvider provides keys using embedded JWK in the JWT (default mode).
type JWTKeyProvider struct {
	keyPair *KeyPair
}

// NewJWTKeyProvider creates a key provider with an embedded JWK.
func NewJWTKeyProvider(keyPair *KeyPair) *JWTKeyProvider {
	return &JWTKeyProvider{keyPair: keyPair}
}

// Mode returns SigningModeJWT.
func (p *JWTKeyProvider) Mode() SigningMode {
	return SigningModeJWT
}

// Sign signs the data using the private key.
func (p *JWTKeyProvider) Sign(ctx context.Context, data []byte) ([]byte, error) {
	signer, ok := p.keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	hash, err := hashForAlgorithm(p.keyPair.Algorithm)
	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	return signer.Sign(nil, digest, hash)
}

// PublicKey returns the public key.
func (p *JWTKeyProvider) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return p.keyPair.PublicKey, nil
}

// CNF returns a CNF with an embedded JWK.
func (p *JWTKeyProvider) CNF(ctx context.Context) (*CNF, error) {
	return p.keyPair.ToCNF()
}

// KeyID returns the key identifier.
func (p *JWTKeyProvider) KeyID() string {
	return p.keyPair.KeyID
}

// Algorithm returns the signing algorithm.
func (p *JWTKeyProvider) Algorithm() string {
	return p.keyPair.Algorithm
}

// JWKSURIKeyProvider resolves keys from a remote JWKS endpoint.
type JWKSURIKeyProvider struct {
	keyPair    *KeyPair
	jwksURI    string
	httpClient *http.Client

	// Cache for resolved JWKS
	mu           sync.RWMutex
	cachedJWKS   *JWKSet
	cacheExpires time.Time
	cacheTTL     time.Duration
}

// JWKSet represents a JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKSURIKeyProviderOption configures a JWKSURIKeyProvider.
type JWKSURIKeyProviderOption func(*JWKSURIKeyProvider)

// WithJWKSHTTPClient sets a custom HTTP client for JWKS fetching.
func WithJWKSHTTPClient(client *http.Client) JWKSURIKeyProviderOption {
	return func(p *JWKSURIKeyProvider) {
		p.httpClient = client
	}
}

// WithJWKSCacheTTL sets the cache TTL for fetched JWKS.
func WithJWKSCacheTTL(ttl time.Duration) JWKSURIKeyProviderOption {
	return func(p *JWKSURIKeyProvider) {
		p.cacheTTL = ttl
	}
}

// NewJWKSURIKeyProvider creates a key provider that references a remote JWKS.
func NewJWKSURIKeyProvider(keyPair *KeyPair, jwksURI string, opts ...JWKSURIKeyProviderOption) *JWKSURIKeyProvider {
	p := &JWKSURIKeyProvider{
		keyPair:    keyPair,
		jwksURI:    jwksURI,
		httpClient: http.DefaultClient,
		cacheTTL:   5 * time.Minute,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Mode returns SigningModeJWKSURI.
func (p *JWKSURIKeyProvider) Mode() SigningMode {
	return SigningModeJWKSURI
}

// Sign signs the data using the private key.
func (p *JWKSURIKeyProvider) Sign(ctx context.Context, data []byte) ([]byte, error) {
	signer, ok := p.keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	hash, err := hashForAlgorithm(p.keyPair.Algorithm)
	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	return signer.Sign(nil, digest, hash)
}

// PublicKey returns the public key (local or fetched from JWKS).
func (p *JWKSURIKeyProvider) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return p.keyPair.PublicKey, nil
}

// CNF returns a CNF with a JKU reference.
func (p *JWKSURIKeyProvider) CNF(ctx context.Context) (*CNF, error) {
	return NewCNFWithJKU(p.jwksURI, p.keyPair.KeyID), nil
}

// KeyID returns the key identifier.
func (p *JWKSURIKeyProvider) KeyID() string {
	return p.keyPair.KeyID
}

// Algorithm returns the signing algorithm.
func (p *JWKSURIKeyProvider) Algorithm() string {
	return p.keyPair.Algorithm
}

// JWKSURI returns the JWKS URI.
func (p *JWKSURIKeyProvider) JWKSURI() string {
	return p.jwksURI
}

// FetchJWKS fetches the JWKS from the remote URI.
func (p *JWKSURIKeyProvider) FetchJWKS(ctx context.Context) (*JWKSet, error) {
	// Check cache first
	p.mu.RLock()
	if p.cachedJWKS != nil && time.Now().Before(p.cacheExpires) {
		jwks := p.cachedJWKS
		p.mu.RUnlock()
		return jwks, nil
	}
	p.mu.RUnlock()

	// Fetch from remote
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKSet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Cache the result
	p.mu.Lock()
	p.cachedJWKS = &jwks
	p.cacheExpires = time.Now().Add(p.cacheTTL)
	p.mu.Unlock()

	return &jwks, nil
}

// FindKey finds a key by ID in the cached or fetched JWKS.
func (p *JWKSURIKeyProvider) FindKey(ctx context.Context, kid string) (*JWK, error) {
	jwks, err := p.FetchJWKS(ctx)
	if err != nil {
		return nil, err
	}

	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == kid {
			return &jwks.Keys[i], nil
		}
	}

	return nil, fmt.Errorf("%w: key %s not found in JWKS", ErrInvalidKey, kid)
}

// JKTJWTKeyProvider uses JWT thumbprint for key confirmation.
type JKTJWTKeyProvider struct {
	keyPair    *KeyPair
	thumbprint string
}

// NewJKTJWTKeyProvider creates a key provider using JWK thumbprint confirmation.
func NewJKTJWTKeyProvider(keyPair *KeyPair) (*JKTJWTKeyProvider, error) {
	thumbprint, err := keyPair.Thumbprint()
	if err != nil {
		return nil, fmt.Errorf("failed to compute thumbprint: %w", err)
	}
	return &JKTJWTKeyProvider{
		keyPair:    keyPair,
		thumbprint: thumbprint,
	}, nil
}

// Mode returns SigningModeJKTJWT.
func (p *JKTJWTKeyProvider) Mode() SigningMode {
	return SigningModeJKTJWT
}

// Sign signs the data using the private key.
func (p *JKTJWTKeyProvider) Sign(ctx context.Context, data []byte) ([]byte, error) {
	signer, ok := p.keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	hash, err := hashForAlgorithm(p.keyPair.Algorithm)
	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	return signer.Sign(nil, digest, hash)
}

// PublicKey returns the public key.
func (p *JKTJWTKeyProvider) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return p.keyPair.PublicKey, nil
}

// CNF returns a CNF with only the JKT (thumbprint).
func (p *JKTJWTKeyProvider) CNF(ctx context.Context) (*CNF, error) {
	// JKT-JWT mode uses a different CNF structure with just the thumbprint
	// For compatibility, we embed a minimal JWK reference
	return &CNF{
		Kid: p.thumbprint,
	}, nil
}

// KeyID returns the key identifier (thumbprint).
func (p *JKTJWTKeyProvider) KeyID() string {
	return p.thumbprint
}

// Algorithm returns the signing algorithm.
func (p *JKTJWTKeyProvider) Algorithm() string {
	return p.keyPair.Algorithm
}

// Thumbprint returns the JWK thumbprint.
func (p *JKTJWTKeyProvider) Thumbprint() string {
	return p.thumbprint
}

// HWKKeyProvider provides hardware key-backed signatures.
// This is an interface for TPM, HSM, or secure enclave integration.
type HWKKeyProvider struct {
	keyID     string
	algorithm string
	signer    crypto.Signer
	publicKey crypto.PublicKey

	// Attestation data for hardware key verification
	attestation []byte
}

// HWKKeyProviderOption configures an HWKKeyProvider.
type HWKKeyProviderOption func(*HWKKeyProvider)

// WithHWKAttestation sets attestation data for the hardware key.
func WithHWKAttestation(attestation []byte) HWKKeyProviderOption {
	return func(p *HWKKeyProvider) {
		p.attestation = attestation
	}
}

// NewHWKKeyProvider creates a hardware key provider.
// The signer must be backed by secure hardware (TPM, HSM, etc.).
func NewHWKKeyProvider(keyID, algorithm string, signer crypto.Signer, opts ...HWKKeyProviderOption) (*HWKKeyProvider, error) {
	pub := signer.Public()
	if pub == nil {
		return nil, fmt.Errorf("signer has no public key")
	}

	p := &HWKKeyProvider{
		keyID:     keyID,
		algorithm: algorithm,
		signer:    signer,
		publicKey: pub,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Mode returns SigningModeHWK.
func (p *HWKKeyProvider) Mode() SigningMode {
	return SigningModeHWK
}

// Sign signs the data using the hardware-backed key.
func (p *HWKKeyProvider) Sign(ctx context.Context, data []byte) ([]byte, error) {
	hash, err := hashForAlgorithm(p.algorithm)
	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	return p.signer.Sign(nil, digest, hash)
}

// PublicKey returns the public key.
func (p *HWKKeyProvider) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return p.publicKey, nil
}

// CNF returns a CNF with the public key JWK.
func (p *HWKKeyProvider) CNF(ctx context.Context) (*CNF, error) {
	return NewCNFWithJWK(p.publicKey, p.keyID)
}

// KeyID returns the key identifier.
func (p *HWKKeyProvider) KeyID() string {
	return p.keyID
}

// Algorithm returns the signing algorithm.
func (p *HWKKeyProvider) Algorithm() string {
	return p.algorithm
}

// Attestation returns the hardware attestation data, if available.
func (p *HWKKeyProvider) Attestation() []byte {
	return p.attestation
}

// hashForAlgorithm returns the hash function for the given algorithm.
func hashForAlgorithm(alg string) (crypto.Hash, error) {
	switch alg {
	case AlgorithmES256, AlgorithmRS256, AlgorithmPS256:
		return crypto.SHA256, nil
	case AlgorithmES384, AlgorithmRS384, AlgorithmPS384:
		return crypto.SHA384, nil
	case AlgorithmES512, AlgorithmRS512, AlgorithmPS512:
		return crypto.SHA512, nil
	case AlgorithmEdDSA:
		return 0, nil // Ed25519 doesn't use pre-hashing
	default:
		return 0, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}
}

// KeyProviderFromKeyPair creates the appropriate key provider based on options.
func KeyProviderFromKeyPair(keyPair *KeyPair, mode SigningMode, opts ...any) (SignatureKeyProvider, error) {
	switch mode {
	case SigningModeJWT, "":
		return NewJWTKeyProvider(keyPair), nil
	case SigningModeJKTJWT:
		return NewJKTJWTKeyProvider(keyPair)
	case SigningModeJWKSURI:
		// Extract JWKS URI from options
		for _, opt := range opts {
			if uri, ok := opt.(string); ok {
				return NewJWKSURIKeyProvider(keyPair, uri), nil
			}
		}
		return nil, fmt.Errorf("JWKS URI required for jwks_uri signing mode")
	default:
		return nil, fmt.Errorf("%w: unsupported signing mode %s", ErrUnsupportedAlgorithm, mode)
	}
}
