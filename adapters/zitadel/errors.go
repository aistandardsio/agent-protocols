package zitadel

import "errors"

// Package-level errors for Zitadel adapter operations.
var (
	// ErrDiscoveryFailed indicates OIDC discovery failed.
	ErrDiscoveryFailed = errors.New("zitadel: OIDC discovery failed")

	// ErrTokenExchangeFailed indicates a token exchange operation failed.
	ErrTokenExchangeFailed = errors.New("zitadel: token exchange failed")

	// ErrVerificationFailed indicates token verification failed.
	ErrVerificationFailed = errors.New("zitadel: token verification failed")

	// ErrInvalidTokenType indicates an invalid or unexpected token type.
	ErrInvalidTokenType = errors.New("zitadel: invalid token type")

	// ErrInvalidIssuer indicates the token issuer doesn't match expected value.
	ErrInvalidIssuer = errors.New("zitadel: invalid issuer")

	// ErrInvalidAudience indicates the token audience doesn't match expected value.
	ErrInvalidAudience = errors.New("zitadel: invalid audience")

	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired = errors.New("zitadel: token expired")

	// ErrKeyNotFound indicates the signing key was not found in JWKS.
	ErrKeyNotFound = errors.New("zitadel: signing key not found")

	// ErrUnsupportedAlgorithm indicates an unsupported signing algorithm.
	ErrUnsupportedAlgorithm = errors.New("zitadel: unsupported signing algorithm")

	// ErrMissingToken indicates a required token is missing.
	ErrMissingToken = errors.New("zitadel: missing token")

	// ErrJWTProfileFailed indicates a JWT profile grant failed.
	ErrJWTProfileFailed = errors.New("zitadel: JWT profile grant failed")
)

// OAuth 2.0 error codes.
const (
	ErrorInvalidRequest       = "invalid_request"
	ErrorInvalidClient        = "invalid_client"
	ErrorInvalidGrant         = "invalid_grant"
	ErrorUnauthorizedClient   = "unauthorized_client"
	ErrorUnsupportedGrantType = "unsupported_grant_type"
	ErrorInvalidScope         = "invalid_scope"
	ErrorAccessDenied         = "access_denied"
)
