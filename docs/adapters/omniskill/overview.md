# omniskill Adapter

Integration of agent-protocols ID-JAG verification with the [omniskill](https://github.com/plexusone/omniskill) MCP runtime.

## Overview

omniskill's `mcp/oauth2` package exposes a protocol-agnostic `TokenVerifier` seam (`ExternalAuthOptions`) that turns any omniskill-based MCP server into a pure OAuth **resource server** — no local authorization server, just validation of externally-issued bearer tokens. This adapter supplies the ID-JAG-aware implementation of that seam, so MCP servers gain enterprise-managed authorization (MCP EMA) via configuration instead of per-repo protocol code.

The adapter verifies incoming JWT access tokens issued by a resource authorization server — Keycloak 26.7 with the experimental `identity-assertion-jwt` feature, or the reference `idjag/authzserver` — and surfaces the verified identity to omniskill:

- **`sub`** → `TokenInfo.Subject` (the delegating principal, e.g. `user:alice`)
- **`act` chain** (RFC 8693) → `TokenInfo.Actor` (outermost first, e.g. `["agent:orchestrator", "agent:worker"]`)
- **`scope`, `client_id`, extra claims** → `TokenInfo.Scope` / `ClientID` / `Claims`

Identity flows through omniskill's context helpers (`GetSubjectFromContext`, `GetActorFromContext`) into its `ToolAuthorizer`/`PolicyAuthorizer` middleware, enabling per-identity, per-agent tool policy.

## Usage

```go
import (
    adapter "github.com/aistandardsio/agent-protocols/adapters/omniskill"
    runtime "github.com/plexusone/omniskill/mcp/server"
)

verifier := adapter.NewVerifier(
    "https://keycloak.example/realms/agents", // issuer
    "https://mcp.example/mcp",                // expected audience
)

rt.ServeHTTP(ctx, &runtime.HTTPServerOptions{
    Addr: ":8080",
    ExternalAuth: &runtime.ExternalAuthOptions{
        Verifier:             verifier,
        AuthorizationServers: []string{"https://keycloak.example/realms/agents"},
        Resource:             "https://mcp.example/mcp",
    },
})
```

## JWKS Resolution

The issuer's JWKS endpoint is resolved lazily, in order:

1. OIDC discovery: `{issuer}/.well-known/openid-configuration` → `jwks_uri`
2. OAuth AS metadata: `{issuer}/.well-known/oauth-authorization-server` → `jwks_uri`
3. Convention fallback: `{issuer}/.well-known/jwks.json`

Pin explicitly with `WithJWKSURL(...)`, or inject a custom `idjag.Verifier` (e.g. `NewStaticKeyVerifier` in tests) with `WithIDJAGVerifier(...)`.

## Options

| Option | Purpose |
|--------|---------|
| `WithJWKSURL(url)` | Pin the JWKS endpoint, skip discovery |
| `WithHTTPClient(c)` | Custom HTTP client for discovery/JWKS |
| `WithClockSkew(d)` | Tolerate clock differences |
| `WithAllowedAlgorithms(algs...)` | Restrict signing algorithms (HS*/none always rejected) |
| `WithIDJAGVerifier(v)` | Fully custom verifier, bypass discovery |

## Security Notes

- Asymmetric signing only; HS256 and `none` are rejected by the underlying idjag verifier.
- Audience validation is mandatory — set the audience to the MCP resource identifier.
- Raw tokens are never logged; log `sub`/`act`/`client_id`/`jti` for audit instead.
