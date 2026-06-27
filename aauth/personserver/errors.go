package personserver

import "errors"

// Package errors.
var (
	// ErrInvalidPrivateKey is returned when the private key is invalid.
	ErrInvalidPrivateKey = errors.New("private key must implement crypto.Signer")
)
