package scimext

import (
	"errors"
	"fmt"
	"testing"
)

func TestAPIError(t *testing.T) {
	tests := []struct {
		name     string
		err      *APIError
		expected string
	}{
		{
			name: "with detail",
			err: &APIError{
				StatusCode: 400,
				SCIMType:   "invalidSyntax",
				Detail:     "Invalid filter expression",
			},
			expected: "scimext: API error (status 400, type invalidSyntax): Invalid filter expression",
		},
		{
			name: "without detail",
			err: &APIError{
				StatusCode: 401,
				SCIMType:   "unauthorized",
			},
			expected: "scimext: API error (status 401, type unauthorized)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("APIError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrorHelpers(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		checkFn  func(error) bool
		expected bool
	}{
		{
			name:     "IsNotFound with ErrNotFound",
			err:      ErrNotFound,
			checkFn:  IsNotFound,
			expected: true,
		},
		{
			name:     "IsNotFound with wrapped ErrNotFound",
			err:      fmt.Errorf("failed: %w", ErrNotFound),
			checkFn:  IsNotFound,
			expected: true,
		},
		{
			name:     "IsNotFound with different error",
			err:      ErrUnauthorized,
			checkFn:  IsNotFound,
			expected: false,
		},
		{
			name:     "IsUnauthorized with ErrUnauthorized",
			err:      ErrUnauthorized,
			checkFn:  IsUnauthorized,
			expected: true,
		},
		{
			name:     "IsForbidden with ErrForbidden",
			err:      ErrForbidden,
			checkFn:  IsForbidden,
			expected: true,
		},
		{
			name:     "IsConflict with ErrConflict",
			err:      ErrConflict,
			checkFn:  IsConflict,
			expected: true,
		},
		{
			name:     "IsBadRequest with ErrBadRequest",
			err:      ErrBadRequest,
			checkFn:  IsBadRequest,
			expected: true,
		},
		{
			name:     "IsNotFound with nil error",
			err:      nil,
			checkFn:  IsNotFound,
			expected: false,
		},
		{
			name:     "IsNotFound with unrelated error",
			err:      errors.New("some other error"),
			checkFn:  IsNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.checkFn(tt.err); got != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}
