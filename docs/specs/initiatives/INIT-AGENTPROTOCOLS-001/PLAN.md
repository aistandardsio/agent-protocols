# PLAN — ID-JAG for MCP Servers — omniskill Auth Seam, Keycloak Interop, mcp-google Pilot

## Sequencing

Strict dependency order across repos; each phase lands, tests, and tags before dependents consume it.

1. **Phase 1 — omniskill External Auth Seam** (`RMI-OMNISKILL-022`)
   - Add `TokenVerifier`, `ExternalAuthOptions`, `TokenInfo.Actor`/`Claims`, external bearer middleware, RFC 9728 metadata for external AS.
   - Unit tests; `golangci-lint`; tag omniskill (minor bump) so adapters can pin it.

2. **Phase 2 — agent-protocols Adapters** (`RMI-AGENTPROTOCOLS-001`, `RMI-AGENTPROTOCOLS-002`)
   - `adapters/omniskill` verifier bridging idjag JWKS verification into the omniskill seam (requires Phase 1 tag).
   - `adapters/keycloak` receiver bootstrap (admin REST + kcadm script), docs under `docs/adapters/{omniskill,keycloak}`.
   - Unit tests with httptest JWKS; Keycloak integration test skipped without `KEYCLOAK_URL`.

3. **Phase 3 — mcp-google Pilot + Interop Demo** (`RMI-MCPGOOGLE-001`, `RMI-AGENTPROTOCOLS-003`)
   - mcp-google `serve --http` with ID-JAG flags, identity-aware logging/policy (requires Phase 2).
   - `examples/mcp-ema` compose demo: offline authzserver profile (default) + pinned Keycloak 26.7 profile; scripted demo client; PIDL diagram; docs update.

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Keycloak `identity-assertion-jwt` is experimental and may change | Pin `quay.io/keycloak/keycloak:26.7`; offline authzserver profile is the CI default; Keycloak profile is opt-in |
| IETF draft evolves (claim shapes, `typ`) | All spec-shaped code isolated in agent-protocols; rolls out to servers via `go get -u` |
| omniskill API break for existing consumers | `ExternalAuth` is additive; built-in `OAuth2Options` path untouched; new `TokenInfo` fields are additive |
| Interop mismatch between idjag assertions and Keycloak expectations | Treat as conformance findings; fix in idjag or file upstream Keycloak issues (high-visibility contribution) |
| mcp-google per-request identity vs. startup-time Google client | Out of scope: identity used for policy/audit only; Google impersonation deferred |

## Delivery Conventions

- Conventional Commits with `Refs: RMI-<REPOSLUG>-<NNN>` git trailer per repo.
- Each commit compiles and passes tests; push after CI-verifiable state per repo's pre-push checklist.
- Phase status derives from member RMI statuses in vistudio; no direct phase status writes.
