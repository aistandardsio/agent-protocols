// Package idjag implements Identity Assertion JWT Authorization Grant (ID-JAG)
// based on draft-ietf-oauth-identity-assertion-authz-grant.
//
// ID-JAG enables secure token exchange where an agent presents a signed JWT
// assertion to obtain an access token. The assertion can represent:
//   - An agent acting on its own behalf (no delegation)
//   - An agent acting on behalf of a human (delegation via "act" claim)
//   - Nested delegation chains (multiple levels of actors)
//
// # EXPERIMENTAL
//
// This package implements a draft specification that is subject to change.
// The API may change in backwards-incompatible ways as the specification evolves.
//
// # Protocol Overview
//
// The ID-JAG flow involves three parties:
//   - Assertion Issuer: Creates and signs the identity assertion JWT
//   - Authorization Server: Validates assertions and issues access tokens
//   - Resource Server: Accepts access tokens to authorize requests
//
// Basic flow:
//  1. Agent obtains or creates a signed identity assertion
//  2. Agent sends assertion to Authorization Server via token exchange
//  3. Authorization Server validates assertion and returns access token
//  4. Agent uses access token to call Resource Server
//
// # Delegation
//
// When an agent acts on behalf of a human, the assertion includes an "act"
// (actor) claim identifying the agent:
//
//	{
//	  "iss": "https://issuer.example.com",
//	  "sub": "user:alice",
//	  "act": {
//	    "sub": "agent:calendar-bot"
//	  }
//	}
//
// Nested delegation is supported by including nested "act" claims.
//
// # References
//
//   - IETF Draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/
//   - RFC 8693 (Token Exchange): https://tools.ietf.org/html/rfc8693
//   - RFC 7519 (JWT): https://tools.ietf.org/html/rfc7519
package idjag
