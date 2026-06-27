package aauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// Delegation chain errors.
var (
	// ErrDelegationChainTooDeep indicates the delegation chain exceeds the maximum depth.
	ErrDelegationChainTooDeep = errors.New("delegation chain too deep")

	// ErrDelegationChainInvalid indicates the delegation chain is malformed.
	ErrDelegationChainInvalid = errors.New("invalid delegation chain")

	// ErrDelegationNotAuthorized indicates the delegation is not authorized.
	ErrDelegationNotAuthorized = errors.New("delegation not authorized")

	// ErrNoRouteFound indicates no route was found for the delegation request.
	ErrNoRouteFound = errors.New("no route found for delegation")
)

// DelegationChain represents a chain of delegation from the original actor
// through one or more intermediate agents.
type DelegationChain struct {
	// Original is the original actor (usually a human).
	Original *Actor

	// Chain is the sequence of intermediate actors.
	// The first element is the first delegatee, and the last is the current agent.
	Chain []*Actor
}

// Depth returns the depth of the delegation chain.
func (d *DelegationChain) Depth() int {
	return len(d.Chain)
}

// CurrentActor returns the current (innermost) actor.
func (d *DelegationChain) CurrentActor() *Actor {
	if len(d.Chain) == 0 {
		return d.Original
	}
	return d.Chain[len(d.Chain)-1]
}

// RootActor returns the root (original) actor.
func (d *DelegationChain) RootActor() *Actor {
	return d.Original
}

// AllActors returns all actors in the chain, from root to current.
func (d *DelegationChain) AllActors() []*Actor {
	result := make([]*Actor, 0, len(d.Chain)+1)
	if d.Original != nil {
		result = append(result, d.Original)
	}
	result = append(result, d.Chain...)
	return result
}

// ParseDelegationChain extracts the delegation chain from nested act claims.
func ParseDelegationChain(act *Actor) *DelegationChain {
	if act == nil {
		return nil
	}

	chain := &DelegationChain{
		Chain: make([]*Actor, 0),
	}

	// Walk the nested act claims
	current := act
	for current != nil {
		// Add to the front of the chain (we're walking from inner to outer)
		chain.Chain = append([]*Actor{current}, chain.Chain...)

		// The innermost actor without a nested act is the original
		if current.Actor == nil {
			chain.Original = current
			// Remove it from the chain since it's the original
			if len(chain.Chain) > 0 {
				chain.Chain = chain.Chain[1:]
			}
		}

		current = current.Actor
	}

	return chain
}

// ValidateDelegationChain validates a delegation chain for integrity.
func ValidateDelegationChain(chain *DelegationChain, maxDepth int) error {
	if chain == nil {
		return nil
	}

	if chain.Depth() > maxDepth {
		return fmt.Errorf("%w: depth %d exceeds max %d", ErrDelegationChainTooDeep, chain.Depth(), maxDepth)
	}

	// Validate that all actors have subjects
	for i, actor := range chain.AllActors() {
		if actor.Subject == "" {
			return fmt.Errorf("%w: actor at position %d has no subject", ErrDelegationChainInvalid, i)
		}
	}

	return nil
}

// DelegationRouter routes requests through a delegation chain.
// It handles multi-agent scenarios where requests pass through multiple agents.
type DelegationRouter struct {
	mu       sync.RWMutex
	routes   map[string]*DelegationRoute
	maxDepth int
	verifier TokenVerifier
}

// DelegationRoute defines how to route a delegation request.
type DelegationRoute struct {
	// Pattern is the URL pattern for matching requests.
	Pattern string

	// TargetAgent is the agent to delegate to.
	TargetAgent string

	// TargetURL is the URL of the target agent.
	TargetURL string

	// Scopes are the scopes to request for this delegation.
	Scopes []string

	// MaxDepth overrides the router's default max depth for this route.
	MaxDepth int

	// PreserveChain indicates whether to preserve the existing delegation chain.
	PreserveChain bool
}

// DelegationRouterOption configures a DelegationRouter.
type DelegationRouterOption func(*DelegationRouter)

// WithDelegationMaxDepth sets the maximum delegation depth.
func WithDelegationMaxDepth(depth int) DelegationRouterOption {
	return func(r *DelegationRouter) {
		r.maxDepth = depth
	}
}

// WithDelegationVerifier sets the token verifier for validating tokens.
func WithDelegationVerifier(v TokenVerifier) DelegationRouterOption {
	return func(r *DelegationRouter) {
		r.verifier = v
	}
}

// NewDelegationRouter creates a new delegation router.
func NewDelegationRouter(opts ...DelegationRouterOption) *DelegationRouter {
	r := &DelegationRouter{
		routes:   make(map[string]*DelegationRoute),
		maxDepth: 5, // Default max depth
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// AddRoute adds a delegation route.
func (r *DelegationRouter) AddRoute(name string, route *DelegationRoute) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[name] = route
}

// RemoveRoute removes a delegation route.
func (r *DelegationRouter) RemoveRoute(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.routes, name)
}

// GetRoute retrieves a delegation route by name.
func (r *DelegationRouter) GetRoute(name string) *DelegationRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.routes[name]
}

// FindRoute finds a matching route for a request path.
func (r *DelegationRouter) FindRoute(path string) *DelegationRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Simple prefix matching for now
	for _, route := range r.routes {
		if matchPattern(route.Pattern, path) {
			return route
		}
	}
	return nil
}

// matchPattern performs simple pattern matching.
// Supports * as a wildcard at the end.
func matchPattern(pattern, path string) bool {
	if len(pattern) == 0 {
		return false
	}

	// Exact match
	if pattern == path {
		return true
	}

	// Wildcard match (pattern ends with *)
	if pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}

	return false
}

// DelegationContext holds context for a delegation operation.
type DelegationContext struct {
	// OriginalRequest is the original HTTP request.
	OriginalRequest *http.Request

	// Chain is the current delegation chain.
	Chain *DelegationChain

	// CurrentToken is the current auth token.
	CurrentToken *AuthToken

	// Route is the matched delegation route.
	Route *DelegationRoute
}

// ExtendChain creates a new actor claim that extends the delegation chain.
func ExtendChain(current *Actor, newActorSubject string, newActorIssuer string) *Actor {
	return &Actor{
		Subject: newActorSubject,
		Issuer:  newActorIssuer,
		Actor:   current,
	}
}

// FlattenChain converts a nested actor claim into a flat list of subjects.
func FlattenChain(act *Actor) []string {
	var subjects []string
	current := act
	for current != nil {
		subjects = append(subjects, current.Subject)
		current = current.Actor
	}
	// Reverse to get root first
	for i, j := 0, len(subjects)-1; i < j; i, j = i+1, j-1 {
		subjects[i], subjects[j] = subjects[j], subjects[i]
	}
	return subjects
}

// DelegationValidator validates delegation chains and permissions.
type DelegationValidator struct {
	// MaxDepth is the maximum allowed delegation depth.
	MaxDepth int

	// AllowedDelegates is a map of actors to their allowed delegates.
	// If nil, all delegates are allowed.
	AllowedDelegates map[string][]string

	// RequiredScopes are scopes required for delegation.
	RequiredScopes []string
}

// NewDelegationValidator creates a new delegation validator.
func NewDelegationValidator(maxDepth int) *DelegationValidator {
	return &DelegationValidator{
		MaxDepth: maxDepth,
	}
}

// Validate validates a delegation chain.
func (v *DelegationValidator) Validate(ctx context.Context, chain *DelegationChain) error {
	if chain == nil {
		return nil
	}

	// Check depth
	if chain.Depth() > v.MaxDepth {
		return fmt.Errorf("%w: depth %d exceeds max %d", ErrDelegationChainTooDeep, chain.Depth(), v.MaxDepth)
	}

	// Check allowed delegates
	if v.AllowedDelegates != nil {
		actors := chain.AllActors()
		for i := 0; i < len(actors)-1; i++ {
			delegator := actors[i].Subject
			delegatee := actors[i+1].Subject

			allowed, ok := v.AllowedDelegates[delegator]
			if !ok {
				return fmt.Errorf("%w: %s is not authorized to delegate", ErrDelegationNotAuthorized, delegator)
			}

			found := false
			for _, a := range allowed {
				if a == delegatee || a == "*" {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%w: %s is not an allowed delegate of %s", ErrDelegationNotAuthorized, delegatee, delegator)
			}
		}
	}

	return nil
}

// AllowDelegate adds an allowed delegate for a delegator.
func (v *DelegationValidator) AllowDelegate(delegator, delegate string) {
	if v.AllowedDelegates == nil {
		v.AllowedDelegates = make(map[string][]string)
	}
	v.AllowedDelegates[delegator] = append(v.AllowedDelegates[delegator], delegate)
}

// AllowAllDelegates allows all delegates for a delegator.
func (v *DelegationValidator) AllowAllDelegates(delegator string) {
	if v.AllowedDelegates == nil {
		v.AllowedDelegates = make(map[string][]string)
	}
	v.AllowedDelegates[delegator] = []string{"*"}
}
