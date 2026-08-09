# Keycloak Adapter

Integration of agent-protocols with [Keycloak](https://www.keycloak.org/) as an **ID-JAG receiver**.

!!! warning "Experimental upstream feature"
    Keycloak's `identity-assertion-jwt` feature is **experimental** (introduced in Keycloak 26.7) and not for production. This adapter is developed and tested against `quay.io/keycloak/keycloak:26.7` only; admin attribute names may change between releases.

## Overview

Keycloak 26.7 is the first major self-hosted IdP with native support for the Identity Assertion JWT Authorization Grant draft — specifically the **receiver** role: Keycloak accepts an ID-JAG minted by an external issuer at its token endpoint (RFC 7523 jwt-bearer grant) and issues a realm access token. The **issuer** role is not yet implemented upstream ("TBD"), so pair Keycloak with the reference `idjag.IdPAuthorizationServer` as the enterprise IdP.

```
IdPAuthorizationServer          Keycloak 26.7 (receiver)              MCP server
  (issuer, this repo)     --features=identity-assertion-jwt     (omniskill adapter)
        │                              │                               │
        │ RFC 8693: ID token → ID-JAG  │ RFC 7523: ID-JAG → access tok │ Bearer JWT
        ▼                              ▼                               ▼
      agent ─────────────────────── agent ─────────────────────────  tools
```

## Why interop with Keycloak?

Testing the agent-protocols issuer against an independent implementation of the same draft is genuine conformance validation — and every published ID-JAG demo to date uses Okta or hosted sandboxes as issuer, so a self-hosted issuer + Keycloak receiver pairing is novel.

## Components

### AdminClient — realm bootstrap

```go
admin := keycloak.NewAdminClient("http://localhost:8081", "admin", "admin")
err := admin.BootstrapReceiver(ctx, "agents",
    keycloak.ExternalIssuer{
        Alias:     "corp-idp",
        IssuerURL: "http://localhost:18081",
        JWKSURL:   "http://localhost:18081/.well-known/jwks.json",
    },
    keycloak.ReceiverClient{ClientID: "mcp-google", ClientSecret: "demo-secret"},
)
```

Idempotent (409s are treated as success). The kcadm.sh equivalent lives at `adapters/keycloak/scripts/keycloak-bootstrap.sh`.

### Exchanger — ID-JAG → access token

```go
exchanger, _ := keycloak.NewExchanger(ctx, "http://localhost:8081", "agents", "mcp-google", "demo-secret")
resp, err := exchanger.Exchange(ctx, signedIDJAG, "docs:read")
// resp.AccessToken is a Keycloak-issued JWT for the MCP server
```

### Discovery helpers

`DiscoverRealm` fetches the realm's OIDC configuration; `OIDCConfig.SupportsJWTBearer()` sanity-checks that the jwt-bearer grant is enabled (i.e., the feature flag is on).

## Validating Keycloak-issued tokens in MCP servers

Use the [omniskill adapter](../omniskill/overview.md) pointed at the realm issuer:

```go
verifier := omniskilladapter.NewVerifier(
    keycloak.RealmIssuer("http://localhost:8081", "agents"),
    "http://localhost:8080/mcp", // audience = MCP resource
)
```

## Integration testing

Unit tests run against a mock; the live-Keycloak integration test is skipped unless `KEYCLOAK_URL` is set:

```bash
docker run -p 8081:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7 start-dev --features=identity-assertion-jwt

KEYCLOAK_URL=http://localhost:8081 go test ./adapters/keycloak/ -run Integration
```
