// Package sharkauth provides adapters integrating agent-protocols with SharkAuth,
// a purpose-built OAuth 2.0 server for agent delegation.
//
// SharkAuth is architecturally aligned with the AAuth protocol, providing:
//   - Native RFC 8693 Token Exchange support
//   - DPoP (Demonstrating Proof-of-Possession) binding
//   - may_act_grants for structured delegation
//   - Cascade revocation for delegation chains
//   - Grant ID audit trail
//
// # Delegation Support
//
// SharkAuth's may_act_grants map directly to AAuth delegation chains:
//
//	client := sharkauth.NewClient("https://auth.example.com")
//
//	// Create a delegation grant
//	grant, err := client.CreateDelegationGrant(ctx, sharkauth.DelegationGrantRequest{
//	    ActorSubject: "agent:calendar-bot",
//	    UserSubject:  "user:alice",
//	    Scopes:       []string{"calendar:read"},
//	})
//
// # DPoP Integration
//
// The package provides DPoP proof generation and verification:
//
//	// Create DPoP proof for a request
//	proof, err := sharkauth.CreateDPoPProof(privateKey, "POST", tokenEndpoint)
//
//	// Use with token exchange
//	resp, err := client.Exchange(ctx, assertion,
//	    sharkauth.WithDPoP(proof),
//	)
//
// # Token Exchange
//
// Exchange AAuth assertions for SharkAuth access tokens:
//
//	resp, err := client.ExchangeAAuthToken(ctx, agentToken,
//	    sharkauth.WithScope("api:read"),
//	    sharkauth.WithDPoP(proof),
//	)
//
// # References
//
//   - SharkAuth: https://github.com/shark-auth/shark
//   - RFC 8693 Token Exchange: https://tools.ietf.org/html/rfc8693
//   - RFC 9449 DPoP: https://tools.ietf.org/html/rfc9449
//   - AAuth Protocol: https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/
package sharkauth
