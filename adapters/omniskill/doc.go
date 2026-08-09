// Package omniskill bridges agent-protocols ID-JAG verification into the
// omniskill MCP runtime (github.com/plexusone/omniskill).
//
// omniskill's mcp/oauth2 package defines a protocol-agnostic TokenVerifier
// seam (ExternalAuthOptions) that turns an MCP server into a pure OAuth
// resource server. This adapter supplies an ID-JAG-aware implementation of
// that seam: incoming bearer JWTs (access tokens issued by a resource
// authorization server such as Keycloak with the identity-assertion-jwt
// feature, or the reference idjag/authzserver) are verified against the
// issuer's JWKS, and the verified identity — subject, RFC 8693 act
// delegation chain, scope, and claims — is surfaced to omniskill's context
// helpers and tool-authorization middleware.
//
// # Usage
//
//	verifier := omniskill.NewVerifier(
//	    "https://keycloak.example/realms/agents", // issuer
//	    "https://mcp.example/mcp",                // expected audience
//	)
//
//	rt.ServeHTTP(ctx, &runtime.HTTPServerOptions{
//	    Addr: ":8080",
//	    ExternalAuth: &runtime.ExternalAuthOptions{
//	        Verifier:             verifier,
//	        AuthorizationServers: []string{"https://keycloak.example/realms/agents"},
//	        Resource:             "https://mcp.example/mcp",
//	    },
//	})
//
// The JWKS endpoint is resolved lazily from the issuer via OIDC discovery
// (/.well-known/openid-configuration), falling back to OAuth authorization
// server metadata (/.well-known/oauth-authorization-server) and finally to
// {issuer}/.well-known/jwks.json. Use WithJWKSURL to pin it explicitly, or
// WithIDJAGVerifier to supply a fully custom idjag.Verifier (e.g. a static
// key verifier in tests).
//
// # References
//
//   - ID-JAG: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/
//   - MCP Enterprise-Managed Authorization: https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/
//   - omniskill: https://github.com/plexusone/omniskill
package omniskill
