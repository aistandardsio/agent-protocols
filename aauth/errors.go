package aauth

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Sentinel errors for AAuth protocol operations.
var (
	// ErrInvalidAAuthID indicates an invalid AAuth identifier format.
	ErrInvalidAAuthID = errors.New("aauth: invalid aauth identifier")

	// ErrInvalidToken indicates a malformed or invalid token.
	ErrInvalidToken = errors.New("aauth: invalid token")

	// ErrTokenExpired indicates a token has expired.
	ErrTokenExpired = errors.New("aauth: token expired")

	// ErrSignatureInvalid indicates signature verification failed.
	ErrSignatureInvalid = errors.New("aauth: signature verification failed")

	// ErrKeyNotFound indicates the signing key was not found.
	ErrKeyNotFound = errors.New("aauth: signing key not found")

	// ErrMissingCNF indicates a required cnf claim is missing.
	ErrMissingCNF = errors.New("aauth: missing cnf claim")

	// ErrCNFMismatch indicates the cnf claim does not match the request signer.
	ErrCNFMismatch = errors.New("aauth: cnf mismatch with request signer")

	// ErrMissingSignature indicates a required HTTP signature is missing.
	ErrMissingSignature = errors.New("aauth: missing http signature")

	// ErrInvalidChallenge indicates an invalid WWW-Authenticate challenge.
	ErrInvalidChallenge = errors.New("aauth: invalid challenge")

	// ErrUnsupportedAlgorithm indicates an unsupported signing algorithm.
	ErrUnsupportedAlgorithm = errors.New("aauth: unsupported algorithm")

	// ErrInvalidJWK indicates an invalid or malformed JWK.
	ErrInvalidJWK = errors.New("aauth: invalid jwk")

	// ErrInvalidKey indicates an invalid or missing cryptographic key.
	ErrInvalidKey = errors.New("aauth: invalid key")

	// ErrMissingAudience indicates a required audience claim is missing.
	ErrMissingAudience = errors.New("aauth: missing audience")

	// ErrAudienceMismatch indicates the token audience does not match.
	ErrAudienceMismatch = errors.New("aauth: audience mismatch")

	// ErrDiscoveryFailed indicates metadata discovery failed.
	ErrDiscoveryFailed = errors.New("aauth: discovery failed")

	// ErrInvalidRequest indicates a malformed request.
	ErrInvalidRequest = errors.New("aauth: invalid request")

	// ErrInvalidGrant indicates an invalid grant type or token.
	ErrInvalidGrant = errors.New("aauth: invalid grant")
)

// OAuth/protocol error codes as defined in the AAuth specification.
const (
	// ErrorInvalidRequest indicates the request is missing a required parameter
	// or includes an invalid parameter.
	ErrorInvalidRequest = "invalid_request"

	// ErrorInvalidGrant indicates the provided grant is invalid, expired, or revoked.
	ErrorInvalidGrant = "invalid_grant"

	// ErrorInvalidSignature indicates the HTTP signature verification failed.
	ErrorInvalidSignature = "invalid_signature"

	// ErrorInvalidScope indicates the requested scope is invalid or unknown.
	ErrorInvalidScope = "invalid_scope"

	// ErrorUnauthorizedClient indicates the client is not authorized.
	ErrorUnauthorizedClient = "unauthorized_client"

	// ErrorUnsupportedGrantType indicates the grant type is not supported.
	ErrorUnsupportedGrantType = "unsupported_grant_type"

	// ErrorServerError indicates an internal server error.
	ErrorServerError = "server_error"

	// ErrorTemporarilyUnavailable indicates the server is temporarily unavailable.
	ErrorTemporarilyUnavailable = "temporarily_unavailable"
)

// TokenErrorResponse represents an OAuth 2.0 error response.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// WriteJSON writes the error response as JSON.
func (e *TokenErrorResponse) WriteJSON(w http.ResponseWriter, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(e)
}
