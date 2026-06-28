package a2a

import "errors"

// Common errors.
var (
	// ErrAgentNotFound indicates the agent card was not found.
	ErrAgentNotFound = errors.New("agent not found")

	// ErrCapabilityNotFound indicates the capability was not found.
	ErrCapabilityNotFound = errors.New("capability not found")

	// ErrTaskNotFound indicates the task was not found.
	ErrTaskNotFound = errors.New("task not found")

	// ErrUnauthorized indicates authentication failed.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden indicates the agent lacks required permissions.
	ErrForbidden = errors.New("forbidden")

	// ErrRateLimited indicates rate limit exceeded.
	ErrRateLimited = errors.New("rate limited")
)
