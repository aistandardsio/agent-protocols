package scimext

import (
	"errors"
	"fmt"
)

// Common errors returned by the SCIM client.
var (
	ErrNotFound     = errors.New("scimext: resource not found")
	ErrUnauthorized = errors.New("scimext: unauthorized")
	ErrForbidden    = errors.New("scimext: forbidden")
	ErrConflict     = errors.New("scimext: conflict")
	ErrBadRequest   = errors.New("scimext: bad request")
)

// APIError represents an error returned by the SCIM API.
type APIError struct {
	StatusCode int
	SCIMType   string
	Detail     string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("scimext: API error (status %d, type %s): %s", e.StatusCode, e.SCIMType, e.Detail)
	}
	return fmt.Sprintf("scimext: API error (status %d, type %s)", e.StatusCode, e.SCIMType)
}

// IsNotFound returns true if the error indicates a resource was not found.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsUnauthorized returns true if the error indicates an authentication failure.
func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrUnauthorized)
}

// IsForbidden returns true if the error indicates an authorization failure.
func IsForbidden(err error) bool {
	return errors.Is(err, ErrForbidden)
}

// IsConflict returns true if the error indicates a conflict (e.g., duplicate resource).
func IsConflict(err error) bool {
	return errors.Is(err, ErrConflict)
}

// IsBadRequest returns true if the error indicates invalid input.
func IsBadRequest(err error) bool {
	return errors.Is(err, ErrBadRequest)
}
