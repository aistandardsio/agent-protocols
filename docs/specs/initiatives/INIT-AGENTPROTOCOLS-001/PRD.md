# PRD — ID-JAG for MCP Servers — omniskill Auth Seam, Keycloak Interop, mcp-google Pilot

## Problem

MCP servers built on omniskill (mcp-google, mcp-atlassian, and future servers) have no enterprise-managed authorization. mcp-google runs stdio-only with process-level trust; omniskill's built-in OAuth 2.1 server issues opaque tokens and cannot validate externally-issued JWTs. Enterprises adopting MCP's Enterprise-Managed Authorization (EMA) extension expect MCP servers to act as resource servers governed by their IdP via ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant). Implementing ID-JAG separately in every MCP server would duplicate protocol code that will keep changing as the IETF draft evolves.

## Goals

- One implementation of ID-JAG verification, consumed by every omniskill-based MCP server via configuration (~5 lines), not per-repo protocol code.
- Interoperate with a major independent implementation: Keycloak 26.7's experimental `identity-assertion-jwt` receiver.
- A fully self-hosted end-to-end demo (issuer → receiver → MCP resource server) — every published ID-JAG demo to date uses Okta or hosted sandboxes as issuer; a self-hosted issuer + Keycloak receiver pairing is novel.
- Per-identity governance: verified `sub`/`act` delegation chains drive per-tool authorization policy in MCP servers.

## Non-Goals

- Implementing the ID-JAG issuer role inside Keycloak (upstream marks it TBD).
- Production hardening of the Keycloak path (the feature is experimental upstream; the demo pins the version and labels it accordingly).
- Per-user Google credential impersonation in mcp-google (domain-wide delegation is a follow-on; this initiative uses verified identity for policy and audit only).
- DPoP sender-constraining (tracked for a future initiative alongside SharkAuth maturation).

## Users

- **Enterprise platform teams** governing which users/agents may reach which MCP servers and tools through their IdP.
- **MCP server authors in the plexusone ecosystem** who want EMA-grade auth without owning OAuth protocol code.
- **agent-protocols adopters** evaluating the idjag reference implementation, who benefit from demonstrated Keycloak interop.

## Success Criteria

- mcp-google serves MCP over HTTP behind ID-JAG-derived bearer JWT validation; unauthorized requests get MCP-spec 401 + `WWW-Authenticate` discovery; stdio behavior unchanged.
- omniskill exposes a protocol-agnostic external-verifier seam with no new dependencies; agent-protocols owns all spec-shaped code.
- Compose demo: default profile runs fully offline against the in-repo `authzserver`; `--profile keycloak` exchanges an ID-JAG minted by the in-repo `IdPAuthorizationServer` at pinned Keycloak 26.7 and calls an mcp-google tool with the resulting access token.
- `act` delegation chain visible in mcp-google logs and enforceable via tool policy.
