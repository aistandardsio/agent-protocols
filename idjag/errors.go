package idjag

import "errors"

// Package-level errors for ID-JAG operations.
var (
	// ErrInvalidAssertion indicates the assertion JWT is malformed or invalid.
	ErrInvalidAssertion = errors.New("idjag: invalid assertion")

	// ErrExpiredAssertion indicates the assertion has expired (exp claim).
	ErrExpiredAssertion = errors.New("idjag: assertion expired")

	// ErrInvalidIssuer indicates the issuer claim doesn't match expected value.
	ErrInvalidIssuer = errors.New("idjag: invalid issuer")

	// ErrInvalidAudience indicates the audience claim doesn't match expected value.
	ErrInvalidAudience = errors.New("idjag: invalid audience")

	// ErrInvalidSubject indicates the subject claim is missing or invalid.
	ErrInvalidSubject = errors.New("idjag: invalid subject")

	// ErrSignatureInvalid indicates the JWT signature verification failed.
	ErrSignatureInvalid = errors.New("idjag: signature verification failed")

	// ErrKeyNotFound indicates the signing key was not found in JWKS.
	ErrKeyNotFound = errors.New("idjag: signing key not found")

	// ErrTokenExchangeFailed indicates the token exchange request failed.
	ErrTokenExchangeFailed = errors.New("idjag: token exchange failed")

	// ErrUnsupportedAlgorithm indicates the JWT uses an unsupported signing algorithm.
	ErrUnsupportedAlgorithm = errors.New("idjag: unsupported signing algorithm")

	// ErrMissingRequiredClaim indicates a required JWT claim is missing.
	ErrMissingRequiredClaim = errors.New("idjag: missing required claim")
)

// TokenErrorResponse represents an OAuth 2.0 error response from the
// authorization server during token exchange.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// Common OAuth 2.0 error codes.
const (
	ErrorInvalidRequest       = "invalid_request"
	ErrorInvalidClient        = "invalid_client"
	ErrorInvalidGrant         = "invalid_grant"
	ErrorUnauthorizedClient   = "unauthorized_client"
	ErrorUnsupportedGrantType = "unsupported_grant_type"
	ErrorInvalidScope         = "invalid_scope"
)
