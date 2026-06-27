package personserver

import (
	"crypto"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Server is the Person Server that handles human consent for agent authorization.
type Server struct {
	store      Store
	issuer     string
	privateKey crypto.PrivateKey
	keyID      string
	publicKey  crypto.PublicKey
	logger     *slog.Logger

	// Token settings
	tokenTTL       time.Duration
	missionTimeout time.Duration
	pollInterval   int
	signingMethod  jwt.SigningMethod

	// Templates
	templates *template.Template
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

// WithMissionTimeout sets the mission pending timeout.
func WithMissionTimeout(timeout time.Duration) Option {
	return func(s *Server) {
		s.missionTimeout = timeout
	}
}

// WithSigningMethod sets the JWT signing method.
func WithSigningMethod(method jwt.SigningMethod) Option {
	return func(s *Server) {
		s.signingMethod = method
	}
}

// New creates a new Person Server.
func New(store Store, issuer string, privateKey crypto.PrivateKey, keyID string, opts ...Option) (*Server, error) {
	// Extract public key
	var publicKey crypto.PublicKey
	if signer, ok := privateKey.(crypto.Signer); ok {
		publicKey = signer.Public()
	} else {
		return nil, ErrInvalidPrivateKey
	}

	s := &Server{
		store:          store,
		issuer:         issuer,
		privateKey:     privateKey,
		keyID:          keyID,
		publicKey:      publicKey,
		logger:         slog.Default(),
		tokenTTL:       time.Hour,
		missionTimeout: 10 * time.Minute,
		pollInterval:   5,
		signingMethod:  jwt.SigningMethodES256,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Parse templates
	s.templates = template.Must(template.New("consent").Parse(consentTemplate))

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

// RegisterHandlers registers all Person Server handlers on the given mux.
// This is a convenience method for registering all handlers at once.
func (s *Server) RegisterHandlers(mux *http.ServeMux) {
	// Discovery
	mux.HandleFunc("GET /.well-known/aauth-configuration", s.HandleMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", s.HandleJWKS)

	// Authorization
	mux.HandleFunc("POST /authorize", s.HandleAuthorize)

	// Consent
	mux.HandleFunc("GET /consent/{id}", s.HandleConsentPage)
	mux.HandleFunc("POST /consent/{id}", s.HandleConsentSubmit)
	mux.HandleFunc("GET /consent/status/{id}", s.HandleConsentStatus)

	// Token
	mux.HandleFunc("POST /token", s.HandleToken)
	mux.HandleFunc("POST /revoke", s.HandleRevoke)

	// Admin (for demo purposes)
	mux.HandleFunc("GET /admin/users", s.HandleListUsers)
	mux.HandleFunc("POST /admin/users", s.HandleCreateUser)
	mux.HandleFunc("GET /admin/agents", s.HandleListAgents)
	mux.HandleFunc("POST /admin/agents", s.HandleCreateAgent)
	mux.HandleFunc("GET /admin/missions", s.HandleListMissions)
}

// Handler returns an http.Handler that serves all Person Server endpoints.
// Use this when you want the Person Server to handle all routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.RegisterHandlers(mux)
	return mux
}
