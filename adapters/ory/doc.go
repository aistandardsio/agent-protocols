// Package ory provides integration between agent-protocols and Ory infrastructure.
//
// This adapter enables agent authentication flows using:
//   - Ory Fosite: Extensible OAuth 2.0 SDK for custom grant handlers
//   - Ory Hydra: Production OAuth 2.0 and OpenID Connect server
//
// # Architecture
//
// The Ory adapter provides two integration modes:
//
//  1. Fosite Integration (library-level): Custom grant handlers for embedding
//     agent-aware authentication directly into your OAuth server.
//
//  2. Hydra Integration (server-level): Client library for interacting with
//     Ory Hydra's admin and public APIs with agent token support.
//
// # Fosite Custom Handlers
//
// The fosite subpackage provides custom OAuth handlers:
//
//	import "github.com/aistandardsio/agent-protocols/adapters/ory/fosite"
//
//	// Create ID-JAG assertion handler
//	handler := fosite.NewIDJAGHandler(verifier, config)
//
//	// Register with Fosite OAuth provider
//	provider.RegisterHandler(handler)
//
// # Hydra Client
//
// The hydra subpackage provides a client for Hydra's APIs:
//
//	import "github.com/aistandardsio/agent-protocols/adapters/ory/hydra"
//
//	// Create Hydra client
//	client, err := hydra.NewClient("https://hydra.example.com")
//
//	// Exchange agent token
//	resp, err := client.TokenExchange(ctx, agentToken, opts...)
//
// # Supported Protocols
//
//   - ID-JAG: JWT assertion grants via custom Fosite handler
//   - AAuth: Agent token grants via custom Fosite handler
//   - AIMS: WIT verification via JWKS integration
//
// # Example
//
// See the examples directory for complete working examples:
//
//	# ID-JAG with Hydra
//	go run ./adapters/ory/examples/idjag
//
//	# Custom Fosite grant
//	go run ./adapters/ory/examples/custom-grant
//
// # Resources
//
//   - Ory Fosite: https://github.com/ory/fosite
//   - Ory Hydra: https://github.com/ory/hydra
//   - RFC 8693 Token Exchange: https://www.rfc-editor.org/rfc/rfc8693
package ory
