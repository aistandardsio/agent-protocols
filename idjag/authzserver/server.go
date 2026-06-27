package authzserver

import (
	"crypto"
	"log/slog"
	"net/http"
	"time"

	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

// Server is the Authorization Server that handles ID-JAG token exchange
// and policy-based authorization routing.
type Server struct {
	store      Store
	issuer     string
	privateKey crypto.PrivateKey
	keyID      string
	publicKey  crypto.PublicKey
	logger     *slog.Logger

	// Token settings
	tokenTTL      time.Duration
	signingMethod jwt.SigningMethod

	// ID-JAG verifier for validating incoming assertions
	verifier idjag.Verifier

	// Policy evaluation
	policyEvaluator PolicyEvaluator

	// AAuth Person Server URL for consent redirects (optional)
	personServerURL string
}

// Option configures the Server.
type Option func(*Server)

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

// WithTokenTTL sets the token TTL.
func WithTokenTTL(ttl time.Duration) Option {
	return func(s *Server) {
		s.tokenTTL = ttl
	}
}

// WithSigningMethod sets the JWT signing method.
func WithSigningMethod(method jwt.SigningMethod) Option {
	return func(s *Server) {
		s.signingMethod = method
	}
}

// WithVerifier sets the ID-JAG verifier.
func WithVerifier(v idjag.Verifier) Option {
	return func(s *Server) {
		s.verifier = v
	}
}

// WithJWKSVerifier creates and sets a JWKS-based verifier for ID-JAG assertions.
// The verifier will fetch public keys from the provided JWKS URL.
func WithJWKSVerifier(jwksURL string, opts idjag.VerifierOptions) Option {
	return func(s *Server) {
		s.verifier = idjag.NewJWKSVerifier(jwksURL, opts)
	}
}

// WithStaticKeyVerifier creates and sets a static key verifier for ID-JAG assertions.
// Use this when you have a pre-configured public key for a single issuer.
func WithStaticKeyVerifier(publicKey crypto.PublicKey, keyID string, opts idjag.VerifierOptions) Option {
	return func(s *Server) {
		s.verifier = idjag.NewStaticKeyVerifier(publicKey, keyID, opts)
	}
}

// WithMultiIssuerVerifier creates a verifier that accepts tokens from multiple issuers.
// Each issuer is identified by its issuer URL and verified using its JWKS endpoint.
func WithMultiIssuerVerifier(issuers map[string]string, opts idjag.VerifierOptions) Option {
	return func(s *Server) {
		s.verifier = NewMultiIssuerVerifier(issuers, opts)
	}
}

// WithVerifierChain creates a verifier that tries multiple verifiers in order.
// This is useful when you need to support multiple verification strategies.
func WithVerifierChain(verifiers ...idjag.Verifier) Option {
	return func(s *Server) {
		s.verifier = NewVerifierChain(verifiers...)
	}
}

// WithPolicyEvaluator sets the policy evaluator.
func WithPolicyEvaluator(pe PolicyEvaluator) Option {
	return func(s *Server) {
		s.policyEvaluator = pe
	}
}

// WithPersonServerURL sets the AAuth Person Server URL for consent redirects.
func WithPersonServerURL(url string) Option {
	return func(s *Server) {
		s.personServerURL = url
	}
}

// New creates a new Authorization Server.
func New(store Store, issuer string, privateKey crypto.PrivateKey, keyID string, opts ...Option) (*Server, error) {
	// Extract public key
	var publicKey crypto.PublicKey
	if signer, ok := privateKey.(crypto.Signer); ok {
		publicKey = signer.Public()
	} else {
		return nil, ErrInvalidPrivateKey
	}

	s := &Server{
		store:         store,
		issuer:        issuer,
		privateKey:    privateKey,
		keyID:         keyID,
		publicKey:     publicKey,
		logger:        slog.Default(),
		tokenTTL:      time.Hour,
		signingMethod: jwt.SigningMethodES256,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Use default policy evaluator if none set
	if s.policyEvaluator == nil {
		s.policyEvaluator = NewDefaultPolicyEvaluator(store)
	}

	return s, nil
}

// Store returns the underlying store.
func (s *Server) Store() Store {
	return s.store
}

// Issuer returns the token issuer URL.
func (s *Server) Issuer() string {
	return s.issuer
}

// PublicKey returns the server's public key.
func (s *Server) PublicKey() crypto.PublicKey {
	return s.publicKey
}

// KeyID returns the key identifier.
func (s *Server) KeyID() string {
	return s.keyID
}

// RegisterHandlers registers all Authorization Server handlers on the given mux.
// This is a convenience method for registering all handlers at once.
func (s *Server) RegisterHandlers(mux *http.ServeMux) {
	// Discovery
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.HandleMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", s.HandleJWKS)

	// Token exchange (RFC 8693)
	mux.HandleFunc("POST /token", s.HandleToken)

	// Token introspection (RFC 7662)
	mux.HandleFunc("POST /introspect", s.HandleIntrospect)

	// Token revocation (RFC 7009)
	mux.HandleFunc("POST /revoke", s.HandleRevoke)

	// Policy endpoint (custom - for policy queries)
	mux.HandleFunc("POST /policy/evaluate", s.HandlePolicyEvaluate)

	// Admin endpoints
	mux.HandleFunc("GET /admin/policies", s.HandleListPolicies)
	mux.HandleFunc("POST /admin/policies", s.HandleCreatePolicy)
	mux.HandleFunc("DELETE /admin/policies/{id}", s.HandleDeletePolicy)
	mux.HandleFunc("GET /admin/tokens", s.HandleListTokens)
}

// Handler returns an http.Handler that serves all Authorization Server endpoints.
// Use this when you want the Authorization Server to handle all routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.RegisterHandlers(mux)
	return mux
}
