package aauth

import (
	"net/http"
	"strings"
)

// AdaptiveSignatureConfig defines rules for adaptive signature component selection.
// This allows agents to dynamically select which HTTP components to include
// in signatures based on request characteristics.
type AdaptiveSignatureConfig struct {
	// BaseComponents are always included in signatures.
	BaseComponents []string

	// ContentComponents are added when the request has a body.
	ContentComponents []string

	// AuthComponents are added when the request has authorization headers.
	AuthComponents []string

	// PathRules map path patterns to additional components.
	PathRules map[string][]string

	// MethodRules map HTTP methods to additional components.
	MethodRules map[string][]string

	// HeaderRules specify headers that should be signed if present.
	HeaderRules []string

	// MinComponents is the minimum number of components required.
	MinComponents int

	// MaxComponents is the maximum number of components to include.
	MaxComponents int
}

// DefaultAdaptiveConfig returns the default adaptive signature configuration.
func DefaultAdaptiveConfig() *AdaptiveSignatureConfig {
	return &AdaptiveSignatureConfig{
		BaseComponents: []string{
			"@method",
			"@target-uri",
			"@request-target",
		},
		ContentComponents: []string{
			"content-type",
			"content-length",
			"content-digest",
		},
		AuthComponents: []string{
			"authorization",
			"signature-key",
		},
		MethodRules: map[string][]string{
			"POST":   {"content-type", "content-length"},
			"PUT":    {"content-type", "content-length"},
			"PATCH":  {"content-type", "content-length"},
			"DELETE": {},
			"GET":    {},
		},
		HeaderRules: []string{
			"x-request-id",
			"x-correlation-id",
			"date",
			"host",
		},
		MinComponents: 2,
		MaxComponents: 15,
	}
}

// StrictAdaptiveConfig returns a strict configuration that signs more components.
func StrictAdaptiveConfig() *AdaptiveSignatureConfig {
	return &AdaptiveSignatureConfig{
		BaseComponents: []string{
			"@method",
			"@target-uri",
			"@request-target",
			"@authority",
			"@scheme",
			"@path",
			"@query",
		},
		ContentComponents: []string{
			"content-type",
			"content-length",
			"content-digest",
		},
		AuthComponents: []string{
			"authorization",
			"signature-key",
		},
		MethodRules: map[string][]string{
			"POST":   {"content-type", "content-length", "content-digest"},
			"PUT":    {"content-type", "content-length", "content-digest"},
			"PATCH":  {"content-type", "content-length", "content-digest"},
			"DELETE": {},
			"GET":    {},
		},
		HeaderRules: []string{
			"x-request-id",
			"x-correlation-id",
			"date",
			"host",
			"user-agent",
			"accept",
		},
		MinComponents: 3,
		MaxComponents: 20,
	}
}

// MinimalAdaptiveConfig returns a minimal configuration for lightweight signatures.
func MinimalAdaptiveConfig() *AdaptiveSignatureConfig {
	return &AdaptiveSignatureConfig{
		BaseComponents: []string{
			"@method",
			"@target-uri",
		},
		ContentComponents: []string{
			"content-digest",
		},
		AuthComponents: []string{
			"signature-key",
		},
		MinComponents: 2,
		MaxComponents: 5,
	}
}

// AdaptiveComponentSelector selects signature components based on request characteristics.
type AdaptiveComponentSelector struct {
	config *AdaptiveSignatureConfig
}

// NewAdaptiveComponentSelector creates a new adaptive component selector.
func NewAdaptiveComponentSelector(config *AdaptiveSignatureConfig) *AdaptiveComponentSelector {
	if config == nil {
		config = DefaultAdaptiveConfig()
	}
	return &AdaptiveComponentSelector{config: config}
}

// SelectComponents selects the appropriate signature components for a request.
func (s *AdaptiveComponentSelector) SelectComponents(req *http.Request) []string {
	components := make([]string, 0, s.config.MaxComponents)
	seen := make(map[string]bool)

	// Helper to add unique components
	addUnique := func(comps []string) {
		for _, c := range comps {
			if !seen[c] && len(components) < s.config.MaxComponents {
				components = append(components, c)
				seen[c] = true
			}
		}
	}

	// Always add base components
	addUnique(s.config.BaseComponents)

	// Add content components if request has a body
	if req.Body != nil && req.ContentLength > 0 {
		addUnique(s.config.ContentComponents)
	}

	// Add auth components if authorization headers are present
	if req.Header.Get("Authorization") != "" || req.Header.Get("Signature-Key") != "" {
		addUnique(s.config.AuthComponents)
	}

	// Add method-specific components
	if methodComps, ok := s.config.MethodRules[req.Method]; ok {
		addUnique(methodComps)
	}

	// Add path-specific components
	for pattern, pathComps := range s.config.PathRules {
		if matchesPath(pattern, req.URL.Path) {
			addUnique(pathComps)
		}
	}

	// Add optional headers if present
	for _, header := range s.config.HeaderRules {
		if req.Header.Get(header) != "" && !seen[strings.ToLower(header)] {
			if len(components) < s.config.MaxComponents {
				components = append(components, strings.ToLower(header))
				seen[strings.ToLower(header)] = true
			}
		}
	}

	// Ensure minimum components
	if len(components) < s.config.MinComponents {
		// This shouldn't happen with proper base components, but handle it
		// by padding with base components
		for _, c := range []string{"@method", "@target-uri", "@request-target"} {
			if !seen[c] && len(components) < s.config.MinComponents {
				components = append(components, c)
				seen[c] = true
			}
		}
	}

	return components
}

// matchesPath checks if a path matches a pattern.
// Supports * as wildcard and ** as recursive wildcard.
func matchesPath(pattern, path string) bool {
	if pattern == path {
		return true
	}

	// Handle ** (recursive wildcard)
	if strings.HasSuffix(pattern, "**") {
		prefix := pattern[:len(pattern)-2]
		// "/api/**" should match both "/api" and "/api/anything"
		return strings.HasPrefix(path, prefix) || path+"/" == prefix
	}

	// Handle * (single segment wildcard)
	if strings.Contains(pattern, "*") {
		patternParts := strings.Split(pattern, "/")
		pathParts := strings.Split(path, "/")

		if len(patternParts) != len(pathParts) {
			return false
		}

		for i := range patternParts {
			if patternParts[i] != "*" && patternParts[i] != pathParts[i] {
				return false
			}
		}
		return true
	}

	return false
}

// ComponentRequirement defines requirements for a signature component.
type ComponentRequirement struct {
	// Component is the component identifier.
	Component string

	// Required indicates if the component must be present.
	Required bool

	// Conditions are conditions under which the component is required.
	Conditions []ComponentCondition
}

// ComponentCondition defines when a component is required.
type ComponentCondition struct {
	// Type is the condition type (method, header, path, content).
	Type string

	// Value is the value to match.
	Value string
}

// SignaturePolicy defines a policy for signature validation.
type SignaturePolicy struct {
	// Name is the policy name.
	Name string

	// RequiredComponents are components that must be in all signatures.
	RequiredComponents []string

	// ConditionalComponents have conditional requirements.
	ConditionalComponents []ComponentRequirement

	// MaxAge is the maximum signature age in seconds.
	MaxAge int

	// RequireNonce indicates if nonce is required.
	RequireNonce bool

	// AllowedAlgorithms are the allowed signature algorithms.
	AllowedAlgorithms []string
}

// DefaultSignaturePolicy returns the default signature policy.
func DefaultSignaturePolicy() *SignaturePolicy {
	return &SignaturePolicy{
		Name:               "default",
		RequiredComponents: []string{"@method", "@target-uri"},
		ConditionalComponents: []ComponentRequirement{
			{
				Component: "content-digest",
				Conditions: []ComponentCondition{
					{Type: "method", Value: "POST"},
					{Type: "method", Value: "PUT"},
					{Type: "method", Value: "PATCH"},
				},
			},
			{
				Component: "signature-key",
				Required:  true,
			},
		},
		MaxAge:       300, // 5 minutes
		RequireNonce: true,
		AllowedAlgorithms: []string{
			HTTPSigAlgorithmECDSAP256SHA256,
			HTTPSigAlgorithmECDSAP384SHA384,
			HTTPSigAlgorithmRSAPSSSHA256,
			HTTPSigAlgorithmEdDSA,
		},
	}
}

// ValidateSignedComponents checks if the signed components meet the policy requirements.
func (p *SignaturePolicy) ValidateSignedComponents(components []string, req *http.Request) error {
	signed := make(map[string]bool)
	for _, c := range components {
		signed[c] = true
	}

	// Check required components
	for _, required := range p.RequiredComponents {
		if !signed[required] {
			return &SignatureValidationError{
				Component: required,
				Message:   "required component not signed",
			}
		}
	}

	// Check conditional components
	for _, cond := range p.ConditionalComponents {
		if cond.Required {
			if !signed[cond.Component] {
				return &SignatureValidationError{
					Component: cond.Component,
					Message:   "required component not signed",
				}
			}
			continue
		}

		// Check if conditions are met
		conditionMet := false
		for _, c := range cond.Conditions {
			switch c.Type {
			case "method":
				if req.Method == c.Value {
					conditionMet = true
				}
			case "header":
				if req.Header.Get(c.Value) != "" {
					conditionMet = true
				}
			case "path":
				if matchesPath(c.Value, req.URL.Path) {
					conditionMet = true
				}
			case "content":
				if req.ContentLength > 0 {
					conditionMet = true
				}
			}
		}

		if conditionMet && !signed[cond.Component] {
			return &SignatureValidationError{
				Component: cond.Component,
				Message:   "conditional component not signed when required",
			}
		}
	}

	return nil
}

// SignatureValidationError represents a signature validation error.
type SignatureValidationError struct {
	Component string
	Message   string
}

func (e *SignatureValidationError) Error() string {
	return "signature validation failed for " + e.Component + ": " + e.Message
}
