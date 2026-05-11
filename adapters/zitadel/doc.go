// Package zitadel provides production-quality adapters integrating agent-protocols
// with Zitadel OIDC infrastructure.
//
// This package bridges the agent-protocols library (idjag, aims, aauth) with
// Zitadel's identity platform, enabling secure token exchange, JWT profile grants,
// and token verification using Zitadel as the authorization server.
//
// # Protocol Support
//
// The adapter supports three agent identity protocols:
//
//   - ID-JAG (Identity Assertion JWT Authorization Grant): Exchange signed identity
//     assertions for access tokens via RFC 8693 token exchange.
//   - AIMS (Agent Identity and Metadata Service): Verify Workload Identity Tokens
//     (WIT) using Zitadel's JWKS infrastructure.
//   - AAuth (Agent Authentication): Verify agent tokens and integrate with
//     HTTP message signatures.
//
// # Token Exchange (RFC 8693)
//
// The TokenExchanger handles OAuth 2.0 token exchange with Zitadel:
//
//	exchanger, err := zitadel.NewTokenExchanger("https://issuer.zitadel.cloud")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Exchange an ID-JAG assertion for an access token
//	resp, err := exchanger.ExchangeAssertion(ctx, signedAssertion)
//
// # JWT Profile Grants (RFC 7523)
//
// The JWTProfileSource implements oauth2.TokenSource for service-to-service
// authentication using JWT bearer assertions:
//
//	source := zitadel.NewJWTProfileSource(
//	    "https://issuer.zitadel.cloud",
//	    clientID,
//	    signer,
//	)
//	token, err := source.Token()
//
// # Token Verification
//
// The Verifier validates tokens issued by Zitadel:
//
//	verifier, err := zitadel.NewVerifier("https://issuer.zitadel.cloud")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify an ID-JAG assertion
//	assertion, err := verifier.VerifyIDJAGAssertion(ctx, token)
//
// # HTTP Middleware
//
// The Middleware provides HTTP handler integration for token validation:
//
//	mw := zitadel.NewMiddleware(verifier, zitadel.MiddlewareOptions{
//	    RequiredAudience: "https://api.example.com",
//	})
//	http.Handle("/api/", mw.Handler(apiHandler))
//
// # Dependencies
//
// This package depends on:
//
//   - github.com/zitadel/oidc/v3 for OIDC operations
//   - github.com/aistandardsio/agent-protocols/idjag for ID-JAG support
//   - github.com/aistandardsio/agent-protocols/aims for AIMS support
//   - github.com/aistandardsio/agent-protocols/aauth for AAuth support
//
// # References
//
//   - Zitadel OIDC: https://zitadel.com/docs/apis/openidoauth
//   - RFC 8693 Token Exchange: https://tools.ietf.org/html/rfc8693
//   - RFC 7523 JWT Bearer: https://tools.ietf.org/html/rfc7523
package zitadel
