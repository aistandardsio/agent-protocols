package authzserver

import (
	"context"
	"fmt"
	"sync"

	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

// MultiIssuerVerifier verifies ID-JAG assertions from multiple trusted issuers.
// Each issuer is mapped to its JWKS URL for key retrieval.
type MultiIssuerVerifier struct {
	// issuerToJWKS maps issuer URLs to their JWKS endpoints
	issuerToJWKS map[string]string
	opts         idjag.VerifierOptions

	mu        sync.RWMutex
	verifiers map[string]*idjag.JWKSVerifier
}

// NewMultiIssuerVerifier creates a verifier that accepts tokens from multiple issuers.
// The issuers map keys are issuer URLs (the "iss" claim value) and values are JWKS URLs.
//
// Example:
//
//	issuers := map[string]string{
//	    "https://idp1.example.com": "https://idp1.example.com/.well-known/jwks.json",
//	    "https://idp2.example.com": "https://idp2.example.com/oauth2/jwks",
//	}
//	verifier := NewMultiIssuerVerifier(issuers, opts)
func NewMultiIssuerVerifier(issuers map[string]string, opts idjag.VerifierOptions) *MultiIssuerVerifier {
	return &MultiIssuerVerifier{
		issuerToJWKS: issuers,
		opts:         opts,
		verifiers:    make(map[string]*idjag.JWKSVerifier),
	}
}

// AddIssuer adds a new trusted issuer at runtime.
func (v *MultiIssuerVerifier) AddIssuer(issuer, jwksURL string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.issuerToJWKS[issuer] = jwksURL
	// Remove cached verifier so it will be recreated with potentially new URL
	delete(v.verifiers, issuer)
}

// RemoveIssuer removes a trusted issuer.
func (v *MultiIssuerVerifier) RemoveIssuer(issuer string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.issuerToJWKS, issuer)
	delete(v.verifiers, issuer)
}

// Issuers returns the list of trusted issuer URLs.
func (v *MultiIssuerVerifier) Issuers() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	issuers := make([]string, 0, len(v.issuerToJWKS))
	for iss := range v.issuerToJWKS {
		issuers = append(issuers, iss)
	}
	return issuers
}

// Verify validates the JWT signature and claims.
// It first extracts the issuer from the token, then uses the appropriate
// JWKS verifier for that issuer.
func (v *MultiIssuerVerifier) Verify(ctx context.Context, tokenString string) (*idjag.Assertion, error) {
	// Parse token without verification to extract issuer
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", idjag.ErrInvalidAssertion, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, idjag.ErrInvalidAssertion
	}

	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return nil, fmt.Errorf("%w: iss", idjag.ErrMissingRequiredClaim)
	}

	// Get or create verifier for this issuer
	verifier, err := v.getVerifier(issuer)
	if err != nil {
		return nil, err
	}

	// Verify with issuer-specific verifier
	return verifier.Verify(ctx, tokenString)
}

func (v *MultiIssuerVerifier) getVerifier(issuer string) (*idjag.JWKSVerifier, error) {
	v.mu.RLock()
	verifier, found := v.verifiers[issuer]
	jwksURL, trusted := v.issuerToJWKS[issuer]
	v.mu.RUnlock()

	if found {
		return verifier, nil
	}

	if !trusted {
		return nil, fmt.Errorf("%w: issuer %s not trusted", idjag.ErrInvalidAssertion, issuer)
	}

	// Create verifier with issuer-specific options
	opts := v.opts
	opts.ExpectedIssuer = issuer
	verifier = idjag.NewJWKSVerifier(jwksURL, opts)

	v.mu.Lock()
	v.verifiers[issuer] = verifier
	v.mu.Unlock()

	return verifier, nil
}

// VerifierChain chains multiple verifiers together, trying each in order
// until one succeeds or all fail.
type VerifierChain struct {
	verifiers []idjag.Verifier
}

// NewVerifierChain creates a verifier that tries multiple verifiers in order.
// This is useful when you need different verification strategies for different tokens.
func NewVerifierChain(verifiers ...idjag.Verifier) *VerifierChain {
	return &VerifierChain{verifiers: verifiers}
}

// Verify tries each verifier in order until one succeeds.
func (c *VerifierChain) Verify(ctx context.Context, tokenString string) (*idjag.Assertion, error) {
	var lastErr error
	for _, v := range c.verifiers {
		assertion, err := v.Verify(ctx, tokenString)
		if err == nil {
			return assertion, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, idjag.ErrInvalidAssertion
}

// Add appends a verifier to the chain.
func (c *VerifierChain) Add(v idjag.Verifier) {
	c.verifiers = append(c.verifiers, v)
}
