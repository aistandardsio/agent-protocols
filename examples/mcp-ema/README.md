# MCP Enterprise-Managed Authorization (EMA) Demo

End-to-end ID-JAG flow (draft-ietf-oauth-identity-assertion-authz-grant) with an MCP server as the protected resource:

```
IdP AS (issuer, :18081)      Receiver (resource AS)          mcp-google (:18090)
  RFC 8693 token exchange     RFC 7523 jwt-bearer            MCP over HTTP
  ID token → ID-JAG           ID-JAG → access token (JWT)    Bearer JWT → tools
```

Two receiver modes:

| Mode | Receiver | Use |
|------|----------|-----|
| **Offline** (default) | in-process reference `idjag.AuthorizationServer` | CI-safe, no containers |
| **Keycloak interop** (`KEYCLOAK_URL` set) | Keycloak 26.7, experimental `identity-assertion-jwt` feature | conformance against a major independent implementation |

## 1. Start mcp-google as the resource server

mcp-google (github.com/plexusone/mcp-google) serves MCP over HTTP as a pure OAuth resource server via omniskill's `ExternalAuth` seam and this repo's `adapters/omniskill` verifier:

```bash
mcp-google serve --http :18090 \
  --idjag-issuer http://localhost:18082 \
  --credentials service-account.json
```

Note: the reference receiver currently issues access tokens **without an `aud` claim**, so `--idjag-audience` must be left unset in offline mode (audience validation is skipped, with a warning). Keycloak-issued tokens carry `aud`; set `--idjag-audience` in interop mode.

## 2. Run the demo

```bash
# Offline mode
MCP_URL=http://localhost:18090/mcp go run ./examples/mcp-ema

# Keycloak interop mode
docker compose up -d           # starts pinned Keycloak 26.7 with the feature flag
KEYCLOAK_URL=http://localhost:8081 MCP_URL=http://localhost:18090/mcp \
  go run ./examples/mcp-ema    # bootstraps realm, exchanges ID-JAG at Keycloak
```

The demo:

1. Simulates user OIDC authentication at the enterprise IdP.
2. Obtains an ID-JAG (`grant_type=token-exchange`, `requested_token_type=...:id-jag`), scoped to `docs:read`.
3. Exchanges it at the receiver (`grant_type=jwt-bearer`) for an access token.
4. Connects to mcp-google over streamable HTTP with the Bearer token and lists tools.
5. Demonstrates governance: a sheets tool call is **denied** (`docs:read` scope only), a docs tool call is **admitted**; mcp-google audit-logs `sub`, `act`, and `scope` per call.

Expected output ends with:

```
   sheets tool DENIED as expected: ... requires scope sheets:read
   docs tool ADMITTED by authorization ...
Demo completed: ID-JAG issued, exchanged, and enforced end to end.
```

## Known conformance notes

- The reference `idjag.AuthorizationServer` omits `aud` and `client_id` from issued access tokens; Keycloak includes them. Aligning the reference server is tracked as follow-up work.
- Keycloak's `identity-assertion-jwt` feature is experimental (26.7); the compose file pins the image and the demo labels interop mode accordingly.
