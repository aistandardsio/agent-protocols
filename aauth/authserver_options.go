package aauth

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthServerOption configures an AuthServer.
type AuthServerOption func(*authServerOptions)

type authServerOptions struct {
	// HTTP client for outbound requests
	httpClient *http.Client

	// Signing method for auth tokens
	signingMethod jwt.SigningMethod

	// Default auth token TTL
	authTokenTTL time.Duration

	// Agent token verifier
	agentTokenVerifier TokenVerifier

	// Resource token verifier
	resourceTokenVerifier TokenVerifier

	// JWKS URL for agent token verification
	agentJWKSURL string

	// JWKS URL for resource token verification
	resourceJWKSURL string

	// Allowed algorithms for token verification
	allowedAlgorithms []string

	// Clock skew tolerance
	clockSkew time.Duration

	// Scope handler for authorization decisions
	scopeHandler ScopeHandler

	// Token endpoint path (default: /token)
	tokenEndpointPath string

	// Supported grant types
	supportedGrantTypes []string
}

// ScopeHandler is called to validate and potentially modify requested scopes.
type ScopeHandler func(agentID *AAuthID, requestedScope string) (grantedScope string, err error)

func defaultAuthServerOptions() *authServerOptions {
	return &authServerOptions{
		httpClient:    http.DefaultClient,
		signingMethod: jwt.SigningMethodES256,
		authTokenTTL:  time.Hour,
		clockSkew:     time.Minute,
		supportedGrantTypes: []string{
			GrantTypeTokenExchange,
		},
		tokenEndpointPath: "/token",
	}
}

// WithAuthServerHTTPClient sets a custom HTTP client.
func WithAuthServerHTTPClient(client *http.Client) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.httpClient = client
	}
}

// WithAuthServerSigningMethod sets the signing method for auth tokens.
func WithAuthServerSigningMethod(method jwt.SigningMethod) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.signingMethod = method
	}
}

// WithAuthTokenTTL sets the default TTL for auth tokens.
func WithAuthTokenTTL(ttl time.Duration) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.authTokenTTL = ttl
	}
}

// WithAuthServerAgentTokenVerifier sets a custom agent token verifier.
func WithAuthServerAgentTokenVerifier(verifier TokenVerifier) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.agentTokenVerifier = verifier
	}
}

// WithAuthServerResourceTokenVerifier sets a custom resource token verifier.
func WithAuthServerResourceTokenVerifier(verifier TokenVerifier) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.resourceTokenVerifier = verifier
	}
}

// WithAuthServerAgentJWKSURL sets the JWKS URL for agent token verification.
func WithAuthServerAgentJWKSURL(url string) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.agentJWKSURL = url
	}
}

// WithAuthServerResourceJWKSURL sets the JWKS URL for resource token verification.
func WithAuthServerResourceJWKSURL(url string) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.resourceJWKSURL = url
	}
}

// WithAuthServerAllowedAlgorithms sets the allowed verification algorithms.
func WithAuthServerAllowedAlgorithms(algorithms []string) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.allowedAlgorithms = algorithms
	}
}

// WithAuthServerClockSkew sets the clock skew tolerance.
func WithAuthServerClockSkew(skew time.Duration) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.clockSkew = skew
	}
}

// WithScopeHandler sets the scope handler for authorization decisions.
func WithScopeHandler(handler ScopeHandler) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.scopeHandler = handler
	}
}

// WithTokenEndpointPath sets the token endpoint path.
func WithTokenEndpointPath(path string) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.tokenEndpointPath = path
	}
}

// WithSupportedGrantTypes sets the supported grant types.
func WithSupportedGrantTypes(grantTypes []string) AuthServerOption {
	return func(opts *authServerOptions) {
		opts.supportedGrantTypes = grantTypes
	}
}
