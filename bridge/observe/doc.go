// Package observe provides observability integration for the bridge package
// using the omniobserve library.
//
// This package wraps bridge.MultiProtocolMiddleware with tracing, metrics,
// and logging capabilities. It integrates with any observops.Provider backend
// (OTLP, Datadog, New Relic, etc.).
//
// # Basic Usage
//
// Wrap the multi-protocol middleware with observability:
//
//	import (
//		"github.com/aistandardsio/agent-protocols/bridge"
//		"github.com/aistandardsio/agent-protocols/bridge/observe"
//		"github.com/plexusone/omniobserve/observops"
//		_ "github.com/plexusone/omniobserve/observops/otlp"
//	)
//
//	// Open observability provider
//	provider, _ := observops.Open("otlp",
//		observops.WithEndpoint("localhost:4317"),
//		observops.WithServiceName("api-gateway"),
//	)
//	defer provider.Close()
//
//	// Create observed middleware
//	middleware := observe.Middleware(provider,
//		bridge.WithIDJAGVerifier(idjagVerifier),
//		bridge.WithAAuthVerifier(aauthVerifier),
//	)
//
//	http.Handle("/api/", middleware(apiHandler))
//
// # Metrics
//
// The following metrics are recorded:
//
//   - auth.requests (counter): Total authentication requests by protocol
//   - auth.success (counter): Successful authentications by protocol
//   - auth.failure (counter): Failed authentications by protocol and reason
//   - auth.duration (histogram): Authentication duration in milliseconds
//
// # Tracing
//
// A span is created for each authentication attempt with attributes:
//
//   - auth.protocol: The detected protocol (id-jag, aims, aauth)
//   - auth.subject: The authenticated subject
//   - auth.issuer: The token issuer
//   - auth.delegated: Whether the request has delegation
//   - auth.key_bound: Whether the request has proof-of-possession
//
// # Logging
//
// Structured logs are emitted for authentication events:
//
//   - auth.success: Successful authentication with identity details
//   - auth.failure: Failed authentication with error details
package observe
