package observe

import (
	"context"

	"github.com/aistandardsio/agent-protocols/bridge"
	"github.com/plexusone/omniobserve/observops"
)

// DelegationTracker provides utilities for tracking delegation chains
// as distributed traces. This is useful for understanding how agents
// are acting on behalf of users or other agents.
type DelegationTracker struct {
	provider observops.Provider
}

// NewDelegationTracker creates a new delegation tracker.
func NewDelegationTracker(provider observops.Provider) *DelegationTracker {
	return &DelegationTracker{provider: provider}
}

// TrackDelegation records a delegation chain as trace attributes.
// Call this after successful authentication to add delegation context to spans.
func (t *DelegationTracker) TrackDelegation(ctx context.Context, identity *bridge.Identity) {
	if identity == nil || !identity.HasDelegation() {
		return
	}

	tracer := t.provider.Tracer()
	logger := t.provider.Logger()
	meter := t.provider.Meter()

	// Record delegation chain depth
	depth := countDelegationDepth(identity.Actor)

	// Record metric
	if gauge, err := meter.Gauge("auth.delegation_depth",
		observops.WithDescription("Delegation chain depth"),
	); err == nil {
		gauge.Record(ctx, float64(depth), observops.WithAttributes(
			observops.Attribute("auth.protocol", string(identity.Protocol)),
			observops.Attribute("auth.subject", identity.Subject),
		))
	}

	// Add span event for delegation
	_, span := tracer.Start(ctx, "auth.delegation",
		observops.WithSpanKind(observops.SpanKindInternal),
		observops.WithSpanAttributes(
			observops.Attribute("delegation.subject", identity.Subject),
			observops.Attribute("delegation.actor", identity.Actor.Subject),
			observops.Attribute("delegation.depth", depth),
		),
	)

	// Build chain for logging
	chain := buildDelegationChain(identity)
	logger.Info(ctx, "Delegation chain detected",
		observops.LogAttr("delegation.chain", chain),
		observops.LogAttr("delegation.depth", depth),
	)

	span.End()
}

// countDelegationDepth returns the depth of the delegation chain.
func countDelegationDepth(actor *bridge.Actor) int {
	depth := 0
	for a := actor; a != nil; a = a.Actor {
		depth++
	}
	return depth
}

// buildDelegationChain builds a string representation of the delegation chain.
func buildDelegationChain(identity *bridge.Identity) string {
	if identity == nil {
		return ""
	}

	chain := identity.Subject
	for a := identity.Actor; a != nil; a = a.Actor {
		chain += " <- " + a.Subject
	}
	return chain
}

// DelegationEvent represents a delegation event for tracking.
type DelegationEvent struct {
	// Principal is the entity being acted on behalf of (the human/original user).
	Principal string

	// Agent is the agent performing the action.
	Agent string

	// Depth is the delegation chain depth.
	Depth int

	// Protocol is the authentication protocol used.
	Protocol bridge.Protocol
}

// ExtractDelegationEvent extracts delegation information from an identity.
func ExtractDelegationEvent(identity *bridge.Identity) *DelegationEvent {
	if identity == nil || !identity.HasDelegation() {
		return nil
	}

	// Find the root principal (deepest actor in chain)
	principal := identity.Actor.Subject
	for a := identity.Actor; a != nil; a = a.Actor {
		principal = a.Subject
	}

	return &DelegationEvent{
		Principal: principal,
		Agent:     identity.Subject,
		Depth:     countDelegationDepth(identity.Actor),
		Protocol:  identity.Protocol,
	}
}
