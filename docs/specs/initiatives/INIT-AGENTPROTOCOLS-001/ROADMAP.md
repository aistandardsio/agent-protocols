# ROADMAP — ID-JAG for MCP Servers — omniskill Auth Seam, Keycloak Interop, mcp-google Pilot

Initiative: `INIT-AGENTPROTOCOLS-001` · Home repo: `github.com/aistandardsio/agent-protocols` · Workflow: pbhq-standard

## Phase 1 — omniskill External Auth Seam

Theme: protocol-agnostic inbound JWT verification in omniskill.

- `RMI-OMNISKILL-022` — External TokenVerifier seam in `mcp/oauth2` (`ExternalAuthOptions`, `TokenInfo.Actor`/`Claims`, external bearer middleware, RFC 9728 metadata for external authorization servers).

## Phase 2 — agent-protocols Adapters

Theme: idjag-to-omniskill verifier adapter and Keycloak receiver adapter.

- `RMI-AGENTPROTOCOLS-001` — `adapters/omniskill`: idjag JWKS verifier exposed as omniskill `TokenVerifier` (requires `RMI-OMNISKILL-022`).
- `RMI-AGENTPROTOCOLS-002` — `adapters/keycloak`: Keycloak 26.7 `identity-assertion-jwt` receiver bootstrap (admin REST, kcadm script, version pin, experimental labeling).

## Phase 3 — mcp-google Pilot + Interop Demo

Theme: HTTP transport with ID-JAG auth and Keycloak compose demo.

- `RMI-MCPGOOGLE-001` — mcp-google `serve --http` with ID-JAG external auth and per-identity tool policy (requires `RMI-AGENTPROTOCOLS-001`, `RMI-OMNISKILL-022`).
- `RMI-AGENTPROTOCOLS-003` — End-to-end demo: `IdPAuthorizationServer` issuer → Keycloak/authzserver receiver → mcp-google resource server; offline default profile + `--profile keycloak`; PIDL diagram + docs (requires `RMI-MCPGOOGLE-001`, `RMI-AGENTPROTOCOLS-002`).

Phase status derives from member RMI statuses; do not set phase status directly.
