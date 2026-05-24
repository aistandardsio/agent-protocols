// Package aauth implements the AAuth protocol for agent-to-resource authentication.
//
// # EXPERIMENTAL
//
// This package implements a draft specification that is subject to change.
// The AAuth protocol is defined in [draft-hardt-oauth-aauth-protocol].
//
// # Protocol Overview
//
// AAuth (Agent Authentication and Authorization) enables AI agents to prove their
// identity cryptographically without pre-registration. Unlike traditional OAuth 2.0,
// which requires shared secrets (client_id/client_secret), AAuth uses:
//
//   - Self-published agent identities: aauth:local@domain URIs
//   - Cryptographic proof-of-possession: Every token bound via cnf.jwk
//   - HTTP request signing: RFC 9421 signatures on all requests
//   - Delegation chains: act claim for human-to-agent authorization
//   - No pre-registration: Agents prove identity via signatures
//
// # Token Types
//
// AAuth defines three token types:
//
//   - aa-agent+jwt: Agent identity token issued by an Agent Provider
//   - aa-auth+jwt: Authorization token issued by Person Server or Access Server
//   - aa-resource+jwt: Exchange token issued by Resource for PS/AS exchange
//
// # Authorization Modes
//
// The protocol supports multiple authorization modes:
//
//  1. Identity-only: Agent identity is sufficient for access
//  2. Resource-managed: Resource controls access internally
//  3. PS-asserted (3-party): Person Server provides human authorization
//  4. Federated (4-party): External Access Server handles authorization
//
// # Example Usage
//
//	// Create an agent with a key pair
//	agent, err := aauth.NewAgent(
//		&aauth.AAuthID{Local: "calendar-bot", Domain: "example.com"},
//		privateKey,
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Make an authenticated request
//	client := &http.Client{Transport: agent.Transport()}
//	resp, err := client.Get("https://api.example.com/calendar")
//
// # Token Verification
//
// All verify methods accept a context for proper cancellation and timeout handling:
//
//	// Verify tokens on a resource server
//	rs := aauth.NewResourceServer(...)
//	agentToken, err := rs.VerifyAgentToken(ctx, tokenString)
//	authToken, err := rs.VerifyAuthToken(ctx, tokenString)
//
//	// Parse tokens for inspection (without verification)
//	agentToken, err := aauth.ParseAgentToken(tokenString)
//	authToken, err := aauth.ParseAuthToken(tokenString)
//	resourceToken, err := aauth.ParseResourceToken(tokenString)
//
// # References
//
//   - AAuth Protocol: https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol
//   - HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421
//   - Proof-of-Possession Key: https://www.rfc-editor.org/rfc/rfc7800
//   - OAuth 2.0 Token Exchange: https://www.rfc-editor.org/rfc/rfc8693
//
// [draft-hardt-oauth-aauth-protocol]: https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol
package aauth
