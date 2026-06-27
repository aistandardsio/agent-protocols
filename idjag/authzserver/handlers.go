package authzserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

// OAuth 2.0 grant types.
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // Not a credential
	GrantTypeJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"     //nolint:gosec // Not a credential
)

// Token types.
const (
	TokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"          //nolint:gosec // Not a credential
	TokenTypeIDJAG       = "urn:ietf:params:oauth:token-type:id-jag"       //nolint:gosec // Not a credential
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // Not a credential
)

// ============================================================================
// Discovery Handlers
// ============================================================================

// HandleMetadata returns the server metadata (/.well-known/oauth-authorization-server).
func (s *Server) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]any{
		"issuer":                 s.issuer,
		"token_endpoint":         s.issuer + "/token",
		"introspection_endpoint": s.issuer + "/introspect",
		"revocation_endpoint":    s.issuer + "/revoke",
		"jwks_uri":               s.issuer + "/.well-known/jwks.json",
		"grant_types_supported": []string{
			GrantTypeTokenExchange,
			GrantTypeJWTBearer,
		},
		"token_endpoint_auth_methods_supported": []string{
			"private_key_jwt",
			"client_secret_basic",
		},
		"token_exchange_subject_token_types_supported": []string{
			TokenTypeJWT,
			TokenTypeIDJAG,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		s.logger.Error("failed to encode metadata", "error", err)
	}
}

// HandleJWKS returns the public key set (/.well-known/jwks.json).
func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk, err := aauth.PublicKeyToJWK(s.publicKey, s.keyID)
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "failed to generate JWK")
		return
	}

	jwks := map[string]any{
		"keys": []any{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		s.logger.Error("failed to encode jwks", "error", err)
	}
}

// ============================================================================
// Token Handlers
// ============================================================================

// HandleToken handles token exchange requests (POST /token).
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case GrantTypeTokenExchange:
		s.handleTokenExchange(w, r)
	case GrantTypeJWTBearer:
		s.handleJWTBearer(w, r)
	default:
		s.errorResponse(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type: "+grantType)
	}
}

func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	subjectToken := r.FormValue("subject_token")
	subjectTokenType := r.FormValue("subject_token_type")
	scope := r.FormValue("scope")

	if subjectToken == "" {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "subject_token required")
		return
	}
	if subjectTokenType == "" {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "subject_token_type required")
		return
	}
	if subjectTokenType != TokenTypeJWT && subjectTokenType != TokenTypeIDJAG {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "unsupported subject_token_type")
		return
	}

	// Verify the subject token
	var assertion *idjag.Assertion
	var err error
	if s.verifier != nil {
		assertion, err = s.verifier.Verify(r.Context(), subjectToken)
		if err != nil {
			s.errorResponse(w, http.StatusUnauthorized, "invalid_grant", err.Error())
			return
		}
	} else {
		// Parse without verification (for demo/testing)
		assertion, err = idjag.ParseAssertion(subjectToken)
		if err != nil {
			s.errorResponse(w, http.StatusUnauthorized, "invalid_grant", "invalid assertion")
			return
		}
	}

	// Evaluate policy for requested scopes
	scopes := splitScopes(scope)
	agentID := ""
	if assertion.Actor != nil {
		agentID = assertion.Actor.Subject
	}

	decision, err := s.policyEvaluator.Evaluate(r.Context(), agentID, scopes)
	if err != nil {
		s.logger.Error("policy evaluation failed", "error", err)
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "policy evaluation failed")
		return
	}

	// If any scope requires consent, return a redirect
	if decision.Protocol == "aauth" && s.personServerURL != "" {
		s.errorResponse(w, http.StatusForbidden, "consent_required",
			"scopes require human consent; redirect to "+s.personServerURL+"/authorize")
		return
	}

	// Issue access token
	accessToken, err := s.issueAccessToken(r.Context(), assertion, scope)
	if err != nil {
		s.logger.Error("failed to issue token", "error", err)
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		return
	}

	resp := TokenResponse{
		AccessToken:     accessToken,
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(s.tokenTTL.Seconds()),
		Scope:           scope,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil { //nolint:gosec // Access token encoding is expected
		s.logger.Error("failed to encode response", "error", err)
	}
}

func (s *Server) handleJWTBearer(w http.ResponseWriter, r *http.Request) {
	assertion := r.FormValue("assertion")
	scope := r.FormValue("scope")

	if assertion == "" {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "assertion required")
		return
	}

	// Verify the assertion
	var parsed *idjag.Assertion
	var err error
	if s.verifier != nil {
		parsed, err = s.verifier.Verify(r.Context(), assertion)
		if err != nil {
			s.errorResponse(w, http.StatusUnauthorized, "invalid_grant", err.Error())
			return
		}
	} else {
		parsed, err = idjag.ParseAssertion(assertion)
		if err != nil {
			s.errorResponse(w, http.StatusUnauthorized, "invalid_grant", "invalid assertion")
			return
		}
	}

	// Evaluate policy
	scopes := splitScopes(scope)
	agentID := ""
	if parsed.Actor != nil {
		agentID = parsed.Actor.Subject
	}

	decision, err := s.policyEvaluator.Evaluate(r.Context(), agentID, scopes)
	if err != nil {
		s.logger.Error("policy evaluation failed", "error", err)
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "policy evaluation failed")
		return
	}

	if decision.Protocol == "aauth" && s.personServerURL != "" {
		s.errorResponse(w, http.StatusForbidden, "consent_required",
			"scopes require human consent; redirect to "+s.personServerURL+"/authorize")
		return
	}

	// Issue access token
	accessToken, err := s.issueAccessToken(r.Context(), parsed, scope)
	if err != nil {
		s.logger.Error("failed to issue token", "error", err)
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		return
	}

	resp := TokenResponse{
		AccessToken:     accessToken,
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(s.tokenTTL.Seconds()),
		Scope:           scope,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil { //nolint:gosec // Access token encoding is expected
		s.logger.Error("failed to encode response", "error", err)
	}
}

// HandleIntrospect handles token introspection (POST /introspect).
func (s *Server) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "token required")
		return
	}

	// Parse the token
	parsed, _, _ := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if parsed == nil {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(IntrospectionResponse{Active: false}); err != nil {
			s.logger.Error("failed to encode response", "error", err)
		}
		return
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(IntrospectionResponse{Active: false}); err != nil {
			s.logger.Error("failed to encode response", "error", err)
		}
		return
	}

	// Check expiration
	exp, _ := claims.GetExpirationTime()
	if exp != nil && time.Now().After(exp.Time) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(IntrospectionResponse{Active: false}); err != nil {
			s.logger.Error("failed to encode response", "error", err)
		}
		return
	}

	resp := IntrospectionResponse{
		Active:    true,
		TokenType: "Bearer",
	}

	if sub, ok := claims["sub"].(string); ok {
		resp.Sub = sub
	}
	if iss, ok := claims["iss"].(string); ok {
		resp.Iss = iss
	}
	if scope, ok := claims["scope"].(string); ok {
		resp.Scope = scope
	}
	if exp != nil {
		resp.Exp = exp.Unix()
	}
	if iat, _ := claims.GetIssuedAt(); iat != nil {
		resp.Iat = iat.Unix()
	}
	if act, ok := claims["act"].(map[string]any); ok {
		resp.Act = act
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("failed to encode response", "error", err)
	}
}

// HandleRevoke handles token revocation (POST /revoke).
func (s *Server) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "token required")
		return
	}

	// For JWTs, we can't truly revoke them, but we can record the revocation
	// Parse token to get ID if available
	parsed, _, _ := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if parsed != nil {
		if claims, ok := parsed.Claims.(jwt.MapClaims); ok {
			if jti, ok := claims["jti"].(string); ok {
				if err := s.store.RevokeToken(r.Context(), jti); err != nil {
					s.logger.Error("failed to revoke token", "error", err)
				}
			}
		}
	}

	// Per RFC 7009, always return 200 for revocation
	w.WriteHeader(http.StatusOK)
}

// ============================================================================
// Policy Handlers
// ============================================================================

// HandlePolicyEvaluate evaluates policy for given scopes (POST /policy/evaluate).
func (s *Server) HandlePolicyEvaluate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID string   `json:"agent_id"`
		Scopes  []string `json:"scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}

	decision, err := s.policyEvaluator.Evaluate(r.Context(), req.AgentID, req.Scopes)
	if err != nil {
		s.logger.Error("policy evaluation failed", "error", err)
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "policy evaluation failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(decision); err != nil {
		s.logger.Error("failed to encode response", "error", err)
	}
}

// ============================================================================
// Admin Handlers
// ============================================================================

// HandleListPolicies lists all scope policies (GET /admin/policies).
func (s *Server) HandleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListScopePolicies(r.Context())
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(policies); err != nil {
		s.logger.Error("failed to encode policies", "error", err)
	}
}

// HandleCreatePolicy creates a new scope policy (POST /admin/policies).
func (s *Server) HandleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var policy ScopePolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}

	if err := s.store.CreateScopePolicy(r.Context(), &policy); err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(policy); err != nil {
		s.logger.Error("failed to encode policy", "error", err)
	}
}

// HandleDeletePolicy deletes a scope policy (DELETE /admin/policies/{id}).
func (s *Server) HandleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	policyID := r.PathValue("id")
	if policyID == "" {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "policy ID required")
		return
	}

	if err := s.store.DeleteScopePolicy(r.Context(), policyID); err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleListTokens lists issued tokens (GET /admin/tokens).
func (s *Server) HandleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.store.ListTokens(r.Context())
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokens); err != nil {
		s.logger.Error("failed to encode tokens", "error", err)
	}
}

// ============================================================================
// Helper methods
// ============================================================================

func (s *Server) issueAccessToken(ctx context.Context, assertion *idjag.Assertion, scope string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(s.tokenTTL)

	claims := jwt.MapClaims{
		"iss":   s.issuer,
		"sub":   assertion.Subject,
		"aud":   s.issuer,
		"iat":   now.Unix(),
		"exp":   expiresAt.Unix(),
		"scope": scope,
	}

	// Include actor claim if present
	if assertion.Actor != nil {
		claims["act"] = map[string]string{
			"sub": assertion.Actor.Subject,
		}
	}

	token := jwt.NewWithClaims(s.signingMethod, claims)
	token.Header["kid"] = s.keyID

	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", err
	}

	// Store token record
	agentID := ""
	if assertion.Actor != nil {
		agentID = assertion.Actor.Subject
	}
	tokenRecord := &Token{
		AgentID:   agentID,
		UserID:    assertion.Subject,
		Scopes:    scope,
		Protocol:  "idjag",
		ExpiresAt: expiresAt,
	}
	if err := s.store.CreateToken(ctx, tokenRecord); err != nil {
		s.logger.Error("failed to store token record", "error", err)
		// Continue anyway - token is valid
	}

	return signedToken, nil
}

func (s *Server) errorResponse(w http.ResponseWriter, status int, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:       errCode,
		Description: errDesc,
	}); err != nil {
		s.logger.Error("failed to encode error response", "error", err)
	}
}

// splitScopes splits a space-separated scope string.
func splitScopes(scopes string) []string {
	if scopes == "" {
		return nil
	}
	return strings.Fields(scopes)
}
