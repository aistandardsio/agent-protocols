# TRD — ID-JAG for MCP Servers — omniskill Auth Seam, Keycloak Interop, mcp-google Pilot

## Architecture

```
IdPAuthorizationServer (issuer, agent-protocols)        Keycloak 26.7 --features=identity-assertion-jwt
        │  RFC 8693 token exchange                              │  RFC 7523 jwt-bearer (ID-JAG assertion)
        │  requested_token_type=...:id-jag                      │  → access token (JWT)
        ▼                                                       ▼
   MCP client ──────────────── Bearer JWT ──────────────▶ mcp-google (resource server, omniskill runtime)
                                                          ExternalAuth: TokenVerifier (idjag JWKS verifier)
```

Roles: the MCP server is a **pure resource server** — it never runs an authorization server. It validates externally-issued JWT access tokens (issuer/audience/JWKS) and advertises its authorization servers via RFC 9728 protected-resource metadata.

## Dependency Direction

`agent-protocols → omniskill` (adapters already depend outward). omniskill gains **no new dependencies**; all spec-shaped code (JWT/JWKS, `act` semantics, Keycloak bootstrap) lives in agent-protocols. MCP servers import both only when opting in.

## Component Design

### omniskill `mcp/oauth2` (RMI-OMNISKILL-022)

- `TokenVerifier` interface: `VerifyToken(ctx, token string) (*TokenInfo, error)`.
- `ExternalAuthOptions{Verifier TokenVerifier; AuthorizationServers []string; Resource string}` as an alternative to the built-in `OAuth2Options` on `HTTPServerOptions`.
- `TokenInfo` extended with `Actor []string` (delegation chain, outermost first) and `Claims map[string]any` so policy middleware can reason about identity; existing context helpers (`GetSubjectFromContext` etc.) unchanged.
- Bearer middleware variant delegating to the injected verifier; 401 responses carry `WWW-Authenticate: Bearer resource_metadata="…"` per the MCP authorization spec; RFC 9728 metadata lists the external `authorization_servers`.
- Existing `ToolAuthorizer`/`PolicyAuthorizer` middleware consume the populated context unchanged.

### agent-protocols `adapters/omniskill` (RMI-AGENTPROTOCOLS-001)

- `NewVerifier(issuer, audience string, opts ...Option)` returning a type satisfying omniskill's `TokenVerifier`.
- Wraps the idjag JWKS verifier (`VerifierOptions{ExpectedIssuer, ExpectedAudience}`), maps JWT `sub`, nested `act` chain (via `DelegationChain`), `scope`, `client_id`, `exp` into `TokenInfo`.
- Options: static keys (tests), custom HTTP client, clock skew.

### agent-protocols `adapters/keycloak` (RMI-AGENTPROTOCOLS-002)

- Admin REST bootstrap: create realm, register the external issuer as an OIDC IdP with JWT-authorization-grant trust settings, create a confidential client with `oauth2.jwt.authorization.grant.enabled=true`, identity mapping.
- Discovery/JWKS helpers mirroring the zitadel adapter (`discoverOIDCConfig` pattern).
- Version pin: `quay.io/keycloak/keycloak:26.7` started with `--features=identity-assertion-jwt`. Documented as experimental upstream.

### mcp-google (RMI-MCPGOOGLE-001)

- `serve --http --listen :8080 --idjag-issuer <url> --idjag-audience <id>` (env: `MCP_GOOGLE_IDJAG_ISSUER`, `MCP_GOOGLE_IDJAG_AUDIENCE`).
- Wires `Runtime.ServeHTTP` with `ExternalAuth` using the agent-protocols omniskill adapter; logs `sub` and `act` per tool call; optional policy maps identities to allowed tools via existing omniskill `PolicyAuthorizer`.
- Google credentials unchanged (service account at startup); stdio remains default transport.

### Demo (RMI-AGENTPROTOCOLS-003)

- `examples/mcp-ema/` compose: default profile = in-repo `authzserver` receiver (offline, CI-safe); `--profile keycloak` = pinned Keycloak receiver.
- Demo client performs the two-step flow (RFC 8693 at issuer → RFC 7523 at receiver) and calls an mcp-google tool; PIDL sequence diagram added under `idjag/pidl/`.

## Security Considerations

- Asymmetric signing only (RS/ES/PS families); HS256 and `none` rejected (existing idjag verifier behavior).
- Audience validation mandatory; short assertion lifetimes (≤5 min) with clock-skew tolerance.
- Tokens never logged; only `sub`, `act`, `client_id`, `jti` appear in audit logs.
- Keycloak path labeled experimental; not for production until upstream stabilizes the feature.

## Testing

- Unit: httptest JWKS + static keys across omniskill seam and adapter; 401/metadata contract tests; `act` chain mapping tests.
- Integration: compose default profile exercised by a scripted client (CI-safe, offline); Keycloak profile behind env guard (`KEYCLOAK_URL`), run manually/nightly.
- Lint: `golangci-lint run` clean in all three repos.
