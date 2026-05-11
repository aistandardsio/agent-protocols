package zitadel

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/aims"
	"github.com/aistandardsio/agent-protocols/idjag"
)

// TokenType identifies the type of token being validated.
type TokenType string

const (
	// TokenTypeIDJAG indicates an ID-JAG assertion.
	TokenTypeIDJAG TokenType = "idjag"

	// TokenTypeAIMS indicates an AIMS Workload Identity Token.
	TokenTypeAIMS TokenType = "aims"

	// TokenTypeAAuth indicates an AAuth agent token.
	TokenTypeAAuth TokenType = "aauth"
)

// Context keys for storing verified token information.
type contextKey string

//nolint:gosec // G101: These are context keys, not credentials
const (
	contextKeyIDJAGAssertion contextKey = "zitadel_idjag_assertion"
	contextKeyAIMSWIT        contextKey = "zitadel_aims_wit"
	contextKeyAAuthToken     contextKey = "zitadel_aauth_token"
	contextKeyTokenType      contextKey = "zitadel_token_type"
)

// MiddlewareOptions configures the middleware behavior.
type MiddlewareOptions struct {
	// RequiredScopes specifies scopes that must be present in the token.
	RequiredScopes []string

	// RequiredAudience specifies the audience that must be present in the token.
	RequiredAudience string

	// AllowAnonymous allows requests without a token to proceed.
	// The token context values will be nil for anonymous requests.
	AllowAnonymous bool

	// ErrorHandler is called when authentication fails.
	// If nil, a default JSON error response is sent.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

	// TokenType specifies which token type to expect.
	// If empty, the middleware will attempt to detect the type.
	TokenType TokenType
}

// Middleware validates bearer tokens against Zitadel.
type Middleware struct {
	verifier *Verifier
	opts     MiddlewareOptions
}

// NewMiddleware creates authentication middleware.
func NewMiddleware(verifier *Verifier, opts MiddlewareOptions) *Middleware {
	return &Middleware{
		verifier: verifier,
		opts:     opts,
	}
}

// Handler wraps an http.Handler with token validation.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token
		token := extractBearerToken(r)
		if token == "" {
			if m.opts.AllowAnonymous {
				next.ServeHTTP(w, r)
				return
			}
			m.handleError(w, r, ErrMissingToken)
			return
		}

		// Verify token and get claims
		ctx, err := m.verifyAndSetContext(r.Context(), token)
		if err != nil {
			m.handleError(w, r, err)
			return
		}

		// Validate audience if required
		if m.opts.RequiredAudience != "" {
			if !m.hasAudience(ctx, m.opts.RequiredAudience) {
				m.handleError(w, r, ErrInvalidAudience)
				return
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// HandlerFunc wraps an http.HandlerFunc with token validation.
func (m *Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return m.Handler(next).ServeHTTP
}

// verifyAndSetContext verifies the token and returns a context with the verified claims.
func (m *Middleware) verifyAndSetContext(ctx context.Context, token string) (context.Context, error) {
	switch m.opts.TokenType {
	case TokenTypeIDJAG:
		assertion, err := m.verifier.VerifyIDJAGAssertion(ctx, token)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, contextKeyIDJAGAssertion, assertion)
		ctx = context.WithValue(ctx, contextKeyTokenType, TokenTypeIDJAG)
		return ctx, nil

	case TokenTypeAIMS:
		wit, err := m.verifier.VerifyAIMSWIT(ctx, token)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, contextKeyAIMSWIT, wit)
		ctx = context.WithValue(ctx, contextKeyTokenType, TokenTypeAIMS)
		return ctx, nil

	case TokenTypeAAuth:
		agentToken, err := m.verifier.VerifyAAuthAgentToken(ctx, token)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, contextKeyAAuthToken, agentToken)
		ctx = context.WithValue(ctx, contextKeyTokenType, TokenTypeAAuth)
		return ctx, nil

	default:
		// Auto-detect token type
		return m.autoDetectAndVerify(ctx, token)
	}
}

// autoDetectAndVerify attempts to detect the token type and verify it.
func (m *Middleware) autoDetectAndVerify(ctx context.Context, token string) (context.Context, error) {
	// Try AAuth first (has specific typ header)
	agentToken, err := m.verifier.VerifyAAuthAgentToken(ctx, token)
	if err == nil {
		ctx = context.WithValue(ctx, contextKeyAAuthToken, agentToken)
		ctx = context.WithValue(ctx, contextKeyTokenType, TokenTypeAAuth)
		return ctx, nil
	}

	// Try ID-JAG (generic JWT assertion)
	assertion, err := m.verifier.VerifyIDJAGAssertion(ctx, token)
	if err == nil {
		ctx = context.WithValue(ctx, contextKeyIDJAGAssertion, assertion)
		ctx = context.WithValue(ctx, contextKeyTokenType, TokenTypeIDJAG)
		return ctx, nil
	}

	// Try AIMS WIT
	wit, witErr := m.verifier.VerifyAIMSWIT(ctx, token)
	if witErr == nil {
		ctx = context.WithValue(ctx, contextKeyAIMSWIT, wit)
		ctx = context.WithValue(ctx, contextKeyTokenType, TokenTypeAIMS)
		return ctx, nil
	}

	// Return the last error
	return nil, err
}

// hasAudience checks if the verified token contains the required audience.
func (m *Middleware) hasAudience(ctx context.Context, audience string) bool {
	tokenType, _ := ctx.Value(contextKeyTokenType).(TokenType)

	switch tokenType {
	case TokenTypeIDJAG:
		if assertion, ok := ctx.Value(contextKeyIDJAGAssertion).(*idjag.Assertion); ok {
			for _, aud := range assertion.Audience {
				if aud == audience {
					return true
				}
			}
		}
	case TokenTypeAIMS:
		if wit, ok := ctx.Value(contextKeyAIMSWIT).(*aims.WorkloadIdentityToken); ok {
			for _, aud := range wit.Audience {
				if aud == audience {
					return true
				}
			}
		}
	case TokenTypeAAuth:
		if token, ok := ctx.Value(contextKeyAAuthToken).(*aauth.AgentToken); ok {
			for _, aud := range token.Audience {
				if aud == audience {
					return true
				}
			}
		}
	}
	return false
}

// handleError sends an error response.
func (m *Middleware) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if m.opts.ErrorHandler != nil {
		m.opts.ErrorHandler(w, r, err)
		return
	}

	w.Header().Set("WWW-Authenticate", `Bearer realm="zitadel"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	resp := TokenErrorResponse{
		Error:            ErrorAccessDenied,
		ErrorDescription: err.Error(),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// extractBearerToken extracts the bearer token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}

	return strings.TrimPrefix(auth, prefix)
}

// Context accessors

// IDJAGAssertionFromContext returns the verified ID-JAG assertion from the context.
func IDJAGAssertionFromContext(ctx context.Context) (*idjag.Assertion, bool) {
	assertion, ok := ctx.Value(contextKeyIDJAGAssertion).(*idjag.Assertion)
	return assertion, ok
}

// AIMSWITFromContext returns the verified AIMS WIT from the context.
func AIMSWITFromContext(ctx context.Context) (*aims.WorkloadIdentityToken, bool) {
	wit, ok := ctx.Value(contextKeyAIMSWIT).(*aims.WorkloadIdentityToken)
	return wit, ok
}

// AAuthTokenFromContext returns the verified AAuth agent token from the context.
func AAuthTokenFromContext(ctx context.Context) (*aauth.AgentToken, bool) {
	token, ok := ctx.Value(contextKeyAAuthToken).(*aauth.AgentToken)
	return token, ok
}

// TokenTypeFromContext returns the type of verified token in the context.
func TokenTypeFromContext(ctx context.Context) (TokenType, bool) {
	tokenType, ok := ctx.Value(contextKeyTokenType).(TokenType)
	return tokenType, ok
}

// RequireIDJAG returns middleware that requires an ID-JAG assertion.
func RequireIDJAG(verifier *Verifier, opts MiddlewareOptions) *Middleware {
	opts.TokenType = TokenTypeIDJAG
	return NewMiddleware(verifier, opts)
}

// RequireAIMS returns middleware that requires an AIMS WIT.
func RequireAIMS(verifier *Verifier, opts MiddlewareOptions) *Middleware {
	opts.TokenType = TokenTypeAIMS
	return NewMiddleware(verifier, opts)
}

// RequireAAuth returns middleware that requires an AAuth agent token.
func RequireAAuth(verifier *Verifier, opts MiddlewareOptions) *Middleware {
	opts.TokenType = TokenTypeAAuth
	return NewMiddleware(verifier, opts)
}
