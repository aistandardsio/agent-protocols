package observe

import (
	"context"

	"github.com/aistandardsio/agent-protocols/bridge"
	"github.com/plexusone/omniobserve/observops"
)

// IdentityAttributes returns observability attributes for an identity.
// Use these when creating custom spans or recording metrics.
func IdentityAttributes(identity *bridge.Identity) []observops.KeyValue {
	if identity == nil {
		return nil
	}

	attrs := []observops.KeyValue{
		observops.Attribute("auth.protocol", string(identity.Protocol)),
		observops.Attribute("auth.subject", identity.Subject),
		observops.Attribute("auth.issuer", identity.Issuer),
	}

	if len(identity.Audience) > 0 {
		attrs = append(attrs, observops.Attribute("auth.audience", identity.Audience[0]))
	}

	if identity.HasKeyBinding() {
		attrs = append(attrs, observops.Attribute("auth.key_bound", true))
		if identity.KeyBinding.Kid != "" {
			attrs = append(attrs, observops.Attribute("auth.key_id", identity.KeyBinding.Kid))
		}
	}

	if identity.HasDelegation() {
		attrs = append(attrs, observops.Attribute("auth.delegated", true))
		attrs = append(attrs, observops.Attribute("auth.actor", identity.Actor.Subject))
	}

	return attrs
}

// AddIdentityToSpan adds identity attributes to an existing span.
func AddIdentityToSpan(span observops.Span, identity *bridge.Identity) {
	if span == nil || identity == nil {
		return
	}

	span.SetAttributes(IdentityAttributes(identity)...)
}

// LogIdentity logs identity information using the provider's logger.
func LogIdentity(ctx context.Context, provider observops.Provider, identity *bridge.Identity, message string) {
	if identity == nil {
		return
	}

	logger := provider.Logger()

	attrs := []observops.LogAttribute{
		observops.LogAttr("auth.protocol", string(identity.Protocol)),
		observops.LogAttr("auth.subject", identity.Subject),
		observops.LogAttr("auth.issuer", identity.Issuer),
	}

	if identity.HasKeyBinding() {
		attrs = append(attrs, observops.LogAttr("auth.key_bound", true))
	}

	if identity.HasDelegation() {
		attrs = append(attrs, observops.LogAttr("auth.delegated", true))
		attrs = append(attrs, observops.LogAttr("auth.actor", identity.Actor.Subject))
	}

	logger.Info(ctx, message, attrs...)
}

// StartIdentitySpan creates a span with identity context.
// Use this for operations that should be traced with identity information.
func StartIdentitySpan(ctx context.Context, provider observops.Provider, name string, identity *bridge.Identity) (context.Context, observops.Span) {
	tracer := provider.Tracer()

	opts := []observops.SpanOption{
		observops.WithSpanKind(observops.SpanKindInternal),
	}

	if identity != nil {
		opts = append(opts, observops.WithSpanAttributes(IdentityAttributes(identity)...))
	}

	return tracer.Start(ctx, name, opts...)
}

// RecordAuthMetric records a metric with identity context.
func RecordAuthMetric(ctx context.Context, provider observops.Provider, name string, value float64, identity *bridge.Identity) error {
	gauge, err := provider.Meter().Gauge(name)
	if err != nil {
		return err
	}

	var attrs []observops.KeyValue
	if identity != nil {
		attrs = append(attrs, observops.Attribute("auth.protocol", string(identity.Protocol)))
		attrs = append(attrs, observops.Attribute("auth.subject", identity.Subject))
	}

	gauge.Record(ctx, value, observops.WithAttributes(attrs...))
	return nil
}

// IncrementAuthCounter increments a counter with identity context.
func IncrementAuthCounter(ctx context.Context, provider observops.Provider, name string, identity *bridge.Identity) error {
	counter, err := provider.Meter().Counter(name)
	if err != nil {
		return err
	}

	var attrs []observops.KeyValue
	if identity != nil {
		attrs = append(attrs, observops.Attribute("auth.protocol", string(identity.Protocol)))
		attrs = append(attrs, observops.Attribute("auth.subject", identity.Subject))
	}

	counter.Add(ctx, 1, observops.WithAttributes(attrs...))
	return nil
}
