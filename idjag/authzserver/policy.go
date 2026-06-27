package authzserver

import (
	"context"
	"path"
	"strings"
)

// PolicyEvaluator determines which protocol to use for a given scope.
type PolicyEvaluator interface {
	// Evaluate determines the authorization protocol for the requested scopes.
	Evaluate(ctx context.Context, agentID string, scopes []string) (*PolicyDecision, error)
}

// DefaultPolicyEvaluator uses the store's scope policies to route scopes.
type DefaultPolicyEvaluator struct {
	store Store

	// DefaultProtocol is the protocol to use when no policy matches.
	// Default is "aauth" (require human consent for unknown scopes).
	DefaultProtocol string
}

// NewDefaultPolicyEvaluator creates a new policy evaluator backed by the store.
func NewDefaultPolicyEvaluator(store Store) *DefaultPolicyEvaluator {
	return &DefaultPolicyEvaluator{
		store:           store,
		DefaultProtocol: "aauth", // Safe default: require human consent
	}
}

// Evaluate determines which protocol to use for the requested scopes.
func (pe *DefaultPolicyEvaluator) Evaluate(ctx context.Context, agentID string, scopes []string) (*PolicyDecision, error) {
	policies, err := pe.store.ListScopePolicies(ctx)
	if err != nil {
		return nil, err
	}

	decision := &PolicyDecision{
		Protocol:              pe.DefaultProtocol,
		AllowedScopes:         []string{},
		RequiredConsentScopes: []string{},
	}

	for _, scope := range scopes {
		matched := false
		for _, policy := range policies {
			if matchesPattern(scope, policy.Pattern) {
				matched = true
				if policy.Protocol == "idjag" {
					decision.AllowedScopes = append(decision.AllowedScopes, scope)
				} else {
					decision.RequiredConsentScopes = append(decision.RequiredConsentScopes, scope)
					if policy.InteractionType != "" {
						decision.InteractionType = policy.InteractionType
					}
				}
				break
			}
		}
		if !matched {
			// No policy matches - use default (require consent)
			decision.RequiredConsentScopes = append(decision.RequiredConsentScopes, scope)
		}
	}

	// Determine final protocol
	if len(decision.RequiredConsentScopes) > 0 {
		decision.Protocol = "aauth"
		decision.Reason = "Some scopes require human consent"
	} else if len(decision.AllowedScopes) > 0 {
		decision.Protocol = "idjag"
		decision.Reason = "All scopes can be automatically authorized"
	}

	return decision, nil
}

// matchesPattern checks if a scope matches a policy pattern.
// Patterns support:
// - Exact match: "read:email"
// - Wildcard: "read:*" matches "read:email", "read:profile", etc.
// - Glob: "api:*/read" matches "api:users/read", "api:posts/read", etc.
func matchesPattern(scope, pattern string) bool {
	// Exact match
	if scope == pattern {
		return true
	}

	// Use path.Match for glob-style matching
	if strings.Contains(pattern, "*") {
		matched, _ := path.Match(pattern, scope)
		return matched
	}

	return false
}

// StaticPolicyEvaluator uses a static list of rules for evaluation.
// Useful for testing or simple deployments.
type StaticPolicyEvaluator struct {
	// IDJAGScopes are scopes that can be automatically authorized via ID-JAG.
	IDJAGScopes []string

	// AAuthScopes are scopes that require human consent via AAuth.
	AAuthScopes []string

	// DefaultProtocol is used for scopes not in either list.
	DefaultProtocol string
}

// NewStaticPolicyEvaluator creates a new static policy evaluator.
func NewStaticPolicyEvaluator() *StaticPolicyEvaluator {
	return &StaticPolicyEvaluator{
		DefaultProtocol: "aauth",
	}
}

// WithIDJAGScopes sets the scopes that can use ID-JAG.
func (pe *StaticPolicyEvaluator) WithIDJAGScopes(scopes ...string) *StaticPolicyEvaluator {
	pe.IDJAGScopes = scopes
	return pe
}

// WithAAuthScopes sets the scopes that require AAuth.
func (pe *StaticPolicyEvaluator) WithAAuthScopes(scopes ...string) *StaticPolicyEvaluator {
	pe.AAuthScopes = scopes
	return pe
}

// WithDefaultProtocol sets the default protocol.
func (pe *StaticPolicyEvaluator) WithDefaultProtocol(protocol string) *StaticPolicyEvaluator {
	pe.DefaultProtocol = protocol
	return pe
}

// Evaluate determines which protocol to use for the requested scopes.
func (pe *StaticPolicyEvaluator) Evaluate(ctx context.Context, agentID string, scopes []string) (*PolicyDecision, error) {
	decision := &PolicyDecision{
		Protocol:              pe.DefaultProtocol,
		AllowedScopes:         []string{},
		RequiredConsentScopes: []string{},
	}

	for _, scope := range scopes {
		found := false

		// Check ID-JAG scopes
		for _, pattern := range pe.IDJAGScopes {
			if matchesPattern(scope, pattern) {
				decision.AllowedScopes = append(decision.AllowedScopes, scope)
				found = true
				break
			}
		}
		if found {
			continue
		}

		// Check AAuth scopes
		for _, pattern := range pe.AAuthScopes {
			if matchesPattern(scope, pattern) {
				decision.RequiredConsentScopes = append(decision.RequiredConsentScopes, scope)
				found = true
				break
			}
		}
		if found {
			continue
		}

		// Use default
		if pe.DefaultProtocol == "idjag" {
			decision.AllowedScopes = append(decision.AllowedScopes, scope)
		} else {
			decision.RequiredConsentScopes = append(decision.RequiredConsentScopes, scope)
		}
	}

	// Determine final protocol
	if len(decision.RequiredConsentScopes) > 0 {
		decision.Protocol = "aauth"
		decision.Reason = "Some scopes require human consent"
	} else if len(decision.AllowedScopes) > 0 {
		decision.Protocol = "idjag"
		decision.Reason = "All scopes can be automatically authorized"
	}

	return decision, nil
}
