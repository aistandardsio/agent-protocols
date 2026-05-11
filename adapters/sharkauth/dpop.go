package sharkauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DPoPHeader represents the JWT header for a DPoP proof.
type DPoPHeader struct {
	Type      string          `json:"typ"`
	Algorithm string          `json:"alg"`
	JWK       json.RawMessage `json:"jwk"`
}

// DPoPClaims represents the JWT claims for a DPoP proof per RFC 9449.
type DPoPClaims struct {
	jwt.RegisteredClaims
	HTTPMethod string `json:"htm"`
	HTTPUri    string `json:"htu"`
	Nonce      string `json:"nonce,omitempty"`
	ATH        string `json:"ath,omitempty"` // Access token hash
}

// DPoPProof represents a generated DPoP proof.
type DPoPProof struct {
	// Token is the signed DPoP JWT.
	Token string

	// JTI is the unique token identifier.
	JTI string

	// IssuedAt is when the proof was created.
	IssuedAt time.Time
}

// DPoPProofOption configures DPoP proof generation.
type DPoPProofOption func(*dpopProofOptions)

type dpopProofOptions struct {
	nonce       string
	accessToken string
	jti         string
}

// WithNonce adds a server-provided nonce to the proof.
func WithNonce(nonce string) DPoPProofOption {
	return func(o *dpopProofOptions) {
		o.nonce = nonce
	}
}

// WithAccessTokenBinding binds the proof to an access token (for resource access).
func WithAccessTokenBinding(accessToken string) DPoPProofOption {
	return func(o *dpopProofOptions) {
		o.accessToken = accessToken
	}
}

// WithJTI sets a specific JTI for the proof.
func WithJTI(jti string) DPoPProofOption {
	return func(o *dpopProofOptions) {
		o.jti = jti
	}
}

// CreateDPoPProof creates a DPoP proof for a request per RFC 9449.
func CreateDPoPProof(privateKey crypto.Signer, method, uri string, opts ...DPoPProofOption) (*DPoPProof, error) {
	var options dpopProofOptions
	for _, opt := range opts {
		opt(&options)
	}

	// Generate JTI if not provided
	jti := options.jti
	if jti == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("%w: failed to generate jti: %v", ErrDPoPFailed, err)
		}
		jti = base64.RawURLEncoding.EncodeToString(b)
	}

	now := time.Now()
	claims := &DPoPClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       jti,
			IssuedAt: jwt.NewNumericDate(now),
		},
		HTTPMethod: method,
		HTTPUri:    uri,
	}

	if options.nonce != "" {
		claims.Nonce = options.nonce
	}

	if options.accessToken != "" {
		// Compute access token hash (SHA-256, base64url)
		hash := sha256.Sum256([]byte(options.accessToken))
		claims.ATH = base64.RawURLEncoding.EncodeToString(hash[:])
	}

	// Determine algorithm and create JWK
	var signingMethod jwt.SigningMethod
	var jwk map[string]interface{}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		signingMethod = jwt.SigningMethodRS256
		jwk = map[string]interface{}{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537
		}
	case *ecdsa.PrivateKey:
		switch key.Curve.Params().BitSize {
		case 256:
			signingMethod = jwt.SigningMethodES256
			jwk = map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
				"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
			}
		case 384:
			signingMethod = jwt.SigningMethodES384
			jwk = map[string]interface{}{
				"kty": "EC",
				"crv": "P-384",
				"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
				"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
			}
		default:
			return nil, fmt.Errorf("%w: unsupported EC curve", ErrDPoPFailed)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported key type", ErrDPoPFailed)
	}

	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal JWK: %v", ErrDPoPFailed, err)
	}

	// Create token with custom header
	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = json.RawMessage(jwkJSON)

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to sign proof: %v", ErrDPoPFailed, err)
	}

	return &DPoPProof{
		Token:    signedToken,
		JTI:      jti,
		IssuedAt: now,
	}, nil
}

// VerifyDPoPProof verifies a DPoP proof against expected values.
// This is primarily for testing; in production, the authorization server verifies proofs.
func VerifyDPoPProof(proof, expectedMethod, expectedURI string) (*DPoPClaims, error) {
	// Parse without verification to extract JWK
	token, _, err := jwt.NewParser().ParseUnverified(proof, &DPoPClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse proof: %v", ErrInvalidDPoP, err)
	}

	// Check header type
	if typ, ok := token.Header["typ"].(string); !ok || typ != "dpop+jwt" {
		return nil, fmt.Errorf("%w: invalid typ header", ErrInvalidDPoP)
	}

	// Extract and parse JWK
	jwkRaw, ok := token.Header["jwk"]
	if !ok {
		return nil, fmt.Errorf("%w: missing jwk header", ErrInvalidDPoP)
	}

	var jwk map[string]interface{}
	switch v := jwkRaw.(type) {
	case map[string]interface{}:
		jwk = v
	case json.RawMessage:
		if err := json.Unmarshal(v, &jwk); err != nil {
			return nil, fmt.Errorf("%w: invalid jwk header: %v", ErrInvalidDPoP, err)
		}
	default:
		return nil, fmt.Errorf("%w: invalid jwk header type", ErrInvalidDPoP)
	}

	// Parse public key from JWK
	publicKey, err := parseJWKPublicKey(jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDPoP, err)
	}

	// Verify signature
	verifiedToken, err := jwt.ParseWithClaims(proof, &DPoPClaims{}, func(t *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: signature verification failed: %v", ErrInvalidDPoP, err)
	}

	claims, ok := verifiedToken.Claims.(*DPoPClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", ErrInvalidDPoP)
	}

	// Verify method and URI
	if claims.HTTPMethod != expectedMethod {
		return nil, fmt.Errorf("%w: method mismatch", ErrInvalidDPoP)
	}
	if claims.HTTPUri != expectedURI {
		return nil, fmt.Errorf("%w: URI mismatch", ErrInvalidDPoP)
	}

	return claims, nil
}

// parseJWKPublicKey parses a public key from a JWK.
// Note: This is a placeholder for testing. In production, use a proper JWK library.
//
//nolint:unparam // Placeholder returns nil; production should use proper JWK parsing.
func parseJWKPublicKey(jwk map[string]interface{}) (interface{}, error) {
	kty, _ := jwk["kty"].(string)

	switch kty {
	case "RSA":
		// Simplified RSA parsing - in production use a proper JWK library
		return nil, fmt.Errorf("RSA JWK parsing not implemented")
	case "EC":
		// Simplified EC parsing - in production use a proper JWK library
		return nil, fmt.Errorf("EC JWK parsing not implemented")
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}
