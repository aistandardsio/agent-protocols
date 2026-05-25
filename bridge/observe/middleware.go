package observe

import (
	"context"
	"net/http"
	"time"

	"github.com/aistandardsio/agent-protocols/bridge"
	"github.com/plexusone/omniobserve/observops"
)

// Middleware creates an observed multi-protocol authentication middleware.
// It wraps bridge.MultiProtocolMiddleware with tracing, metrics, and logging.
func Middleware(provider observops.Provider, opts ...bridge.MiddlewareOption) func(http.Handler) http.Handler {
	// Create the underlying bridge middleware
	bridgeMiddleware := bridge.MultiProtocolMiddleware(opts...)

	return func(next http.Handler) http.Handler {
		// Wrap with bridge authentication
		authenticated := bridgeMiddleware(next)

		// Wrap with observability
		return &observedHandler{
			next:     authenticated,
			provider: provider,
		}
	}
}

type observedHandler struct {
	next     http.Handler
	provider observops.Provider
}

func (h *observedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tracer := h.provider.Tracer()
	logger := h.provider.Logger()
	meter := h.provider.Meter()
	ctx := r.Context()

	// Start authentication span
	ctx, span := tracer.Start(ctx, "auth.verify",
		observops.WithSpanKind(observops.SpanKindInternal),
		observops.WithSpanAttributes(
			observops.Attribute("http.method", r.Method),
			observops.Attribute("http.path", r.URL.Path),
		),
	)

	startTime := time.Now()

	// Record request counter
	if counter, err := meter.Counter("auth.requests",
		observops.WithDescription("Total authentication requests"),
	); err == nil {
		counter.Add(ctx, 1)
	}

	// Wrap response writer to capture status
	wrapped := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}

	// Serve request (includes bridge authentication)
	h.next.ServeHTTP(wrapped, r.WithContext(ctx))

	duration := time.Since(startTime)

	// Get identity from context (if authentication succeeded)
	identity, hasIdentity := bridge.IdentityFromContext(r.Context())
	protocol := bridge.ProtocolFromContext(r.Context())

	// Set span attributes based on result
	span.SetAttributes(observops.Attribute("auth.protocol", string(protocol)))
	span.SetAttributes(observops.Attribute("http.status_code", wrapped.statusCode))

	if hasIdentity && identity != nil {
		// Authentication succeeded
		span.SetAttributes(
			observops.Attribute("auth.subject", identity.Subject),
			observops.Attribute("auth.issuer", identity.Issuer),
			observops.Attribute("auth.delegated", identity.HasDelegation()),
			observops.Attribute("auth.key_bound", identity.HasKeyBinding()),
		)
		span.SetStatus(observops.StatusCodeOK, "")

		// Record success metrics
		h.recordSuccess(ctx, meter, protocol, duration)

		// Log success
		logger.Info(ctx, "Authentication successful",
			observops.LogAttr("auth.protocol", string(protocol)),
			observops.LogAttr("auth.subject", identity.Subject),
			observops.LogAttr("auth.issuer", identity.Issuer),
			observops.LogAttr("auth.delegated", identity.HasDelegation()),
			observops.LogAttr("auth.key_bound", identity.HasKeyBinding()),
			observops.LogAttr("duration_ms", duration.Milliseconds()),
		)
	} else if wrapped.statusCode == http.StatusUnauthorized {
		// Authentication failed
		span.SetStatus(observops.StatusCodeError, "authentication failed")

		// Record failure metrics
		h.recordFailure(ctx, meter, protocol, "unauthorized", duration)

		// Log failure
		logger.Warn(ctx, "Authentication failed",
			observops.LogAttr("auth.protocol", string(protocol)),
			observops.LogAttr("http.status_code", wrapped.statusCode),
			observops.LogAttr("duration_ms", duration.Milliseconds()),
		)
	}

	span.End()
}

func (h *observedHandler) recordSuccess(ctx context.Context, meter observops.Meter, protocol bridge.Protocol, duration time.Duration) {
	// Success counter
	if counter, err := meter.Counter("auth.success",
		observops.WithDescription("Successful authentications"),
	); err == nil {
		counter.Add(ctx, 1, observops.WithAttributes(
			observops.Attribute("auth.protocol", string(protocol)),
		))
	}

	// Duration histogram
	if hist, err := meter.Histogram("auth.duration",
		observops.WithDescription("Authentication duration"),
		observops.WithUnit("ms"),
	); err == nil {
		hist.Record(ctx, float64(duration.Milliseconds()), observops.WithAttributes(
			observops.Attribute("auth.protocol", string(protocol)),
			observops.Attribute("auth.success", true),
		))
	}
}

func (h *observedHandler) recordFailure(ctx context.Context, meter observops.Meter, protocol bridge.Protocol, reason string, duration time.Duration) {
	// Failure counter
	if counter, err := meter.Counter("auth.failure",
		observops.WithDescription("Failed authentications"),
	); err == nil {
		counter.Add(ctx, 1, observops.WithAttributes(
			observops.Attribute("auth.protocol", string(protocol)),
			observops.Attribute("auth.failure_reason", reason),
		))
	}

	// Duration histogram
	if hist, err := meter.Histogram("auth.duration",
		observops.WithDescription("Authentication duration"),
		observops.WithUnit("ms"),
	); err == nil {
		hist.Record(ctx, float64(duration.Milliseconds()), observops.WithAttributes(
			observops.Attribute("auth.protocol", string(protocol)),
			observops.Attribute("auth.success", false),
		))
	}
}

type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// WrapHandler wraps an http.Handler with authentication observability.
// Use this when you already have a bridge middleware configured and want
// to add observability on top.
func WrapHandler(handler http.Handler, provider observops.Provider) http.Handler {
	return &observedHandler{
		next:     handler,
		provider: provider,
	}
}
