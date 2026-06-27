package authzserver

import "errors"

// Package errors.
var (
	// ErrInvalidPrivateKey is returned when the private key is invalid.
	ErrInvalidPrivateKey = errors.New("private key must implement crypto.Signer")

	// ErrMissingVerifier is returned when no verifier is configured.
	ErrMissingVerifier = errors.New("verifier is required")
)
