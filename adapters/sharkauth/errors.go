package sharkauth

import "errors"

// Package-level errors for SharkAuth adapter operations.
var (
	// ErrDiscoveryFailed indicates SharkAuth metadata discovery failed.
	ErrDiscoveryFailed = errors.New("sharkauth: discovery failed")

	// ErrTokenExchangeFailed indicates a token exchange operation failed.
	ErrTokenExchangeFailed = errors.New("sharkauth: token exchange failed")

	// ErrDelegationFailed indicates a delegation grant operation failed.
	ErrDelegationFailed = errors.New("sharkauth: delegation failed")

	// ErrDPoPFailed indicates DPoP proof creation or verification failed.
	ErrDPoPFailed = errors.New("sharkauth: DPoP failed")

	// ErrRevocationFailed indicates a token revocation operation failed.
	ErrRevocationFailed = errors.New("sharkauth: revocation failed")

	// ErrInvalidGrant indicates the grant is invalid or expired.
	ErrInvalidGrant = errors.New("sharkauth: invalid grant")

	// ErrInvalidToken indicates the token is invalid.
	ErrInvalidToken = errors.New("sharkauth: invalid token")

	// ErrUnauthorized indicates the client is not authorized.
	ErrUnauthorized = errors.New("sharkauth: unauthorized")

	// ErrInvalidDPoP indicates the DPoP proof is invalid.
	ErrInvalidDPoP = errors.New("sharkauth: invalid DPoP proof")

	// ErrDPoPRequired indicates DPoP is required but not provided.
	ErrDPoPRequired = errors.New("sharkauth: DPoP required")
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
	ErrorInvalidDPoP          = "invalid_dpop_proof"
	ErrorUseDPoPNonce         = "use_dpop_nonce"
)
