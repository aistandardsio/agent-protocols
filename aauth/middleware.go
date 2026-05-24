package aauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aistandardsio/agent-protocols/aauth/httpsig"
)

// Middleware returns HTTP middleware that enforces AAuth authentication.
func (rs *ResourceServer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, err := rs.verifyRequest(r)
		if err != nil {
			rs.writeUnauthorized(w, err)
			return
		}

		// Add verification result to context
		ctx := ContextWithVerificationResult(r.Context(), result)
		if result.AgentID != nil {
			ctx = ContextWithAgentID(ctx, result.AgentID)
		}
		if result.AgentToken != nil {
			ctx = ContextWithAgentToken(ctx, result.AgentToken)
		}
		if result.AuthToken != nil {
			ctx = ContextWithAuthToken(ctx, result.AuthToken)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MiddlewareFunc returns a middleware function for use with various routers.
func (rs *ResourceServer) MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return rs.Middleware(next).ServeHTTP
}

// verifyRequest verifies an incoming request.
func (rs *ResourceServer) verifyRequest(r *http.Request) (*RequestVerificationResult, error) {
	result := &RequestVerificationResult{}
	ctx := r.Context()

	// Get Signature-Key header
	signatureKey := r.Header.Get(HeaderSignatureKey)
	if signatureKey == "" {
		return nil, ErrMissingSignature
	}

	// Extract agent token from Signature-Key header
	// Format: scheme=jwt <token>
	agentTokenStr, err := extractSignatureKeyToken(signatureKey)
	if err != nil {
		return nil, err
	}

	// Verify agent token
	agentToken, err := rs.VerifyAgentToken(ctx, agentTokenStr)
	if err != nil {
		return nil, err
	}
	result.AgentToken = agentToken

	// Parse agent ID
	agentID, err := ParseAAuthID(agentToken.Subject)
	if err != nil {
		return nil, err
	}
	result.AgentID = agentID

	// Get CNF and verify HTTP signature
	if agentToken.CNF == nil {
		return nil, ErrMissingCNF
	}

	publicKey, err := agentToken.CNF.GetPublicKey()
	if err != nil {
		return nil, err
	}

	// Verify HTTP signature
	httpVerifier, err := httpsig.NewVerifier(httpsig.VerifierOptions{
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, err
	}

	sigResult, err := httpVerifier.Verify(r)
	if err != nil {
		return nil, err
	}
	if !sigResult.Valid {
		return nil, ErrSignatureInvalid
	}
	result.KeyID = sigResult.KeyID

	// Check for auth token (Authorization header)
	authHeader := r.Header.Get(HeaderAuthorization)
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		authTokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		authToken, err := rs.VerifyAuthToken(ctx, authTokenStr)
		if err != nil {
			return nil, err
		}
		result.AuthToken = authToken

		// Verify auth token CNF matches agent token CNF
		if authToken.CNF != nil {
			matches, err := rs.verifyCNFMatch(agentToken.CNF, authToken.CNF)
			if err != nil {
				return nil, err
			}
			if !matches {
				return nil, ErrCNFMismatch
			}
		}
	} else if !rs.opts.allowIdentityOnly {
		// Auth token required but not present
		// In a real implementation, we'd initiate the token exchange flow here
		return nil, fmt.Errorf("%w: auth token required", ErrInvalidToken)
	}

	return result, nil
}

// verifyCNFMatch checks if two CNF claims reference the same key.
func (rs *ResourceServer) verifyCNFMatch(cnf1, cnf2 *CNF) (bool, error) {
	// If both have embedded JWKs, compare thumbprints
	if cnf1.IsEmbedded() && cnf2.IsEmbedded() {
		tp1, err := cnf1.GetThumbprint()
		if err != nil {
			return false, err
		}
		tp2, err := cnf2.GetThumbprint()
		if err != nil {
			return false, err
		}
		return tp1 == tp2, nil
	}

	// If both are references, compare kid
	if cnf1.IsReference() && cnf2.IsReference() {
		return cnf1.Kid == cnf2.Kid, nil
	}

	return false, nil
}

// extractSignatureKeyToken extracts the token from a Signature-Key header.
func extractSignatureKeyToken(header string) (string, error) {
	// Format: scheme=jwt <token>
	if !strings.HasPrefix(header, "scheme=jwt ") {
		return "", fmt.Errorf("%w: invalid Signature-Key format", ErrInvalidToken)
	}

	return strings.TrimPrefix(header, "scheme=jwt "), nil
}

// writeUnauthorized writes an unauthorized response.
func (rs *ResourceServer) writeUnauthorized(w http.ResponseWriter, err error) {
	w.Header().Set(HeaderWWWAuthenticate, rs.ChallengeHeader())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	errResp := &TokenErrorResponse{
		Error:            ErrorUnauthorizedClient,
		ErrorDescription: err.Error(),
	}
	_ = json.NewEncoder(w).Encode(errResp)
}

// RequireScope returns middleware that requires a specific scope.
func RequireScope(rs *ResourceServer, requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result, ok := VerificationResultFromContext(r.Context())
			if !ok {
				rs.writeUnauthorized(w, fmt.Errorf("no verification result"))
				return
			}

			// Check scope in auth token
			if result.AuthToken != nil {
				if !hasScope(result.AuthToken.Scope, requiredScope) {
					w.Header().Set(HeaderWWWAuthenticate,
						InsufficientScopeChallenge(rs.url, requiredScope).String())
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// hasScope checks if a scope string contains a required scope.
func hasScope(scopeStr, required string) bool {
	scopes := strings.Fields(scopeStr)
	for _, s := range scopes {
		if s == required {
			return true
		}
	}
	return false
}

// VerifyHandler wraps a handler with AAuth verification.
// This is a convenience function for simple use cases.
func VerifyHandler(rs *ResourceServer, handler http.HandlerFunc) http.HandlerFunc {
	return rs.MiddlewareFunc(handler)
}

// HandleVerified is a helper that extracts verification context.
type VerifiedHandler func(w http.ResponseWriter, r *http.Request, result *RequestVerificationResult)

// WithVerification wraps a handler to provide the verification result.
func WithVerification(rs *ResourceServer, handler VerifiedHandler) http.HandlerFunc {
	return rs.MiddlewareFunc(func(w http.ResponseWriter, r *http.Request) {
		result, ok := VerificationResultFromContext(r.Context())
		if !ok {
			http.Error(w, "verification result not found", http.StatusInternalServerError)
			return
		}
		handler(w, r, result)
	})
}
