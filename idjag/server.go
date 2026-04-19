package idjag

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthorizationServer handles token exchange requests for ID-JAG assertions.
type AuthorizationServer struct {
	// Verifier validates incoming assertions.
	Verifier Verifier

	// SigningMethod is the JWT signing method for access tokens.
	SigningMethod jwt.SigningMethod

	// SigningKey is the private key for signing access tokens.
	SigningKey crypto.PrivateKey

	// KeyID is the key identifier to include in token headers.
	KeyID string

	// Issuer is the issuer claim for access tokens.
	Issuer string

	// TokenTTL is the lifetime for issued access tokens.
	TokenTTL time.Duration

	// AllowedScopes restricts which scopes can be requested.
	// If empty, all scopes are allowed.
	AllowedScopes []string

	// ScopeValidator is an optional function to validate scope requests.
	// If set, it is called to validate the requested scope against the assertion.
	ScopeValidator func(assertion *Assertion, requestedScope string) error
}

// NewAuthorizationServer creates a new authorization server.
func NewAuthorizationServer(verifier Verifier, signingMethod jwt.SigningMethod, signingKey crypto.PrivateKey, keyID, issuer string) *AuthorizationServer {
	return &AuthorizationServer{
		Verifier:      verifier,
		SigningMethod: signingMethod,
		SigningKey:    signingKey,
		KeyID:         keyID,
		Issuer:        issuer,
		TokenTTL:      1 * time.Hour,
	}
}

// ServeHTTP implements http.Handler for the token endpoint.
func (s *AuthorizationServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, ErrorInvalidRequest, "method not allowed")
		return
	}

	// Limit request body size to prevent memory exhaustion (G120)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, "invalid request body")
		return
	}

	grantType := r.Form.Get("grant_type")

	switch grantType {
	case GrantTypeTokenExchange:
		s.handleTokenExchange(w, r)
	case GrantTypeJWTBearer:
		s.handleJWTBearer(w, r)
	default:
		s.writeError(w, http.StatusBadRequest, ErrorUnsupportedGrantType, fmt.Sprintf("unsupported grant type: %s", grantType))
	}
}

func (s *AuthorizationServer) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	subjectToken := r.Form.Get("subject_token")
	subjectTokenType := r.Form.Get("subject_token_type")
	scope := r.Form.Get("scope")

	if subjectToken == "" {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, "subject_token required")
		return
	}
	if subjectTokenType == "" {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, "subject_token_type required")
		return
	}
	if subjectTokenType != TokenTypeJWT {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, "unsupported subject_token_type")
		return
	}

	assertion, err := s.Verifier.Verify(r.Context(), subjectToken)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, ErrorInvalidGrant, err.Error())
		return
	}

	if err := s.validateScope(assertion, scope); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidScope, err.Error())
		return
	}

	accessToken, err := s.issueAccessToken(assertion, scope)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, ErrorInvalidGrant, "failed to issue token")
		return
	}

	resp := &TokenExchangeResponse{
		AccessToken:     accessToken,
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(s.TokenTTL.Seconds()),
		Scope:           scope,
	}

	s.writeJSON(w, http.StatusOK, resp)
}

func (s *AuthorizationServer) handleJWTBearer(w http.ResponseWriter, r *http.Request) {
	assertion := r.Form.Get("assertion")
	scope := r.Form.Get("scope")

	if assertion == "" {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, "assertion required")
		return
	}

	parsed, err := s.Verifier.Verify(r.Context(), assertion)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, ErrorInvalidGrant, err.Error())
		return
	}

	if err := s.validateScope(parsed, scope); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidScope, err.Error())
		return
	}

	accessToken, err := s.issueAccessToken(parsed, scope)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, ErrorInvalidGrant, "failed to issue token")
		return
	}

	resp := &TokenExchangeResponse{
		AccessToken:     accessToken,
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(s.TokenTTL.Seconds()),
		Scope:           scope,
	}

	s.writeJSON(w, http.StatusOK, resp)
}

func (s *AuthorizationServer) validateScope(assertion *Assertion, scope string) error {
	if s.ScopeValidator != nil {
		return s.ScopeValidator(assertion, scope)
	}

	if len(s.AllowedScopes) == 0 {
		return nil
	}

	requestedScopes := strings.Fields(scope)
	for _, rs := range requestedScopes {
		found := false
		for _, as := range s.AllowedScopes {
			if rs == as {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("scope not allowed: %s", rs)
		}
	}

	return nil
}

func (s *AuthorizationServer) issueAccessToken(assertion *Assertion, scope string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		ClaimIssuer:         s.Issuer,
		ClaimSubject:        assertion.Subject,
		ClaimIssuedAt:       jwt.NewNumericDate(now),
		ClaimExpirationTime: jwt.NewNumericDate(now.Add(s.TokenTTL)),
	}

	if scope != "" {
		claims[ClaimScope] = scope
	}

	// Include actor claim if present in assertion
	if assertion.Actor != nil {
		claims[ClaimActor] = assertion.Actor.toMap()
	}

	token := jwt.NewWithClaims(s.SigningMethod, claims)
	if s.KeyID != "" {
		token.Header["kid"] = s.KeyID
	}

	return token.SignedString(s.SigningKey)
}

func (s *AuthorizationServer) writeError(w http.ResponseWriter, status int, errorCode, description string) {
	resp := &TokenErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	}
	s.writeJSON(w, status, resp)
}

func (s *AuthorizationServer) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// ResourceServer provides middleware for validating access tokens.
type ResourceServer struct {
	// Verifier validates incoming access tokens.
	Verifier Verifier
}

// NewResourceServer creates a new resource server middleware.
func NewResourceServer(verifier Verifier) *ResourceServer {
	return &ResourceServer{Verifier: verifier}
}

// Middleware returns an HTTP middleware that validates Bearer tokens.
func (rs *ResourceServer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearerToken(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		assertion, err := rs.Verifier.Verify(r.Context(), token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Add assertion to request context
		ctx := ContextWithAssertion(r.Context(), assertion)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractBearerToken extracts the Bearer token from the Authorization header.
func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get(HeaderAuthorization)
	if auth == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

// Context key for storing assertion in request context.
type contextKey string

const assertionContextKey contextKey = "idjag_assertion"

// ContextWithAssertion adds an Assertion to the context.
func ContextWithAssertion(ctx context.Context, assertion *Assertion) context.Context {
	return context.WithValue(ctx, assertionContextKey, assertion)
}

// AssertionFromContext retrieves an Assertion from the context.
// Returns nil if no assertion is present.
func AssertionFromContext(ctx context.Context) *Assertion {
	v := ctx.Value(assertionContextKey)
	if v == nil {
		return nil
	}
	assertion, ok := v.(*Assertion)
	if !ok {
		return nil
	}
	return assertion
}

// JWKSHandler serves a JWKS endpoint.
type JWKSHandler struct {
	jwks *JWKS
}

// NewJWKSHandler creates a handler that serves the given JWKS.
func NewJWKSHandler(jwks *JWKS) *JWKSHandler {
	return &JWKSHandler{jwks: jwks}
}

// ServeHTTP implements http.Handler.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if err := json.NewEncoder(w).Encode(h.jwks); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
