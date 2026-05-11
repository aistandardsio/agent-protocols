# Zitadel Adapter

Integration of agent-protocols with [Zitadel](https://zitadel.com/) OIDC infrastructure.

## Overview

The Zitadel adapter provides production-ready integration between all three agent protocols (ID-JAG, AIMS, AAuth) and Zitadel's identity infrastructure. It leverages Zitadel's native support for:

- **RFC 8693 Token Exchange** - Exchange assertions for access tokens
- **RFC 7523 JWT Profile** - JWT bearer grants for service authentication
- **OIDC Discovery** - Automatic endpoint discovery
- **JWKS Verification** - Key rotation and validation

## Why Zitadel?

| Feature | Benefit |
|---------|---------|
| Written in Go (75%) | Native integration, shared tooling |
| RFC 8693 Support | Direct token exchange for ID-JAG |
| JWT Profile (RFC 7523) | Service-to-service authentication |
| OpenID Certified | Standards compliance |
| Multi-tenant | Fits agent scenarios |
| [zitadel/oidc](https://github.com/zitadel/oidc) library | Battle-tested Go OIDC library |

## Components

### TokenExchanger

Exchanges ID-JAG assertions for Zitadel access tokens using RFC 8693.

```go
exchanger, _ := zitadel.NewTokenExchanger("https://zitadel.example.com")
resp, _ := exchanger.ExchangeAssertion(ctx, signedAssertion,
    zitadel.WithScope("openid profile"),
    zitadel.WithAudience("https://api.example.com"),
)
```

### JWTProfileSource

Implements `oauth2.TokenSource` for automatic token management with JWT profile grants.

```go
source, _ := zitadel.NewJWTProfileSource(
    "https://zitadel.example.com",
    "client-id",
    signer,
    zitadel.WithJWTProfileScopes("openid", "profile"),
)
token, _ := source.Token() // Automatically cached and refreshed
```

### Verifier

Validates tokens from all three protocols against Zitadel's JWKS.

```go
verifier, _ := zitadel.NewVerifier("https://zitadel.example.com")

// Verify ID-JAG assertion
assertion, _ := verifier.VerifyIDJAGAssertion(ctx, tokenString)

// Verify AIMS WIT
wit, _ := verifier.VerifyAIMSWIT(ctx, tokenString)

// Verify AAuth agent token
agentToken, _ := verifier.VerifyAAuthAgentToken(ctx, tokenString)
```

### Middleware

HTTP middleware for protecting endpoints with Zitadel token validation.

```go
verifier, _ := zitadel.NewVerifier("https://zitadel.example.com")

// Protocol-specific middleware
http.Handle("/api/", zitadel.RequireIDJAG(verifier, opts).Handler(apiHandler))
http.Handle("/workload/", zitadel.RequireAIMS(verifier, opts).Handler(workloadHandler))
http.Handle("/agent/", zitadel.RequireAAuth(verifier, opts).Handler(agentHandler))
```

## Protocol Mappings

| Protocol | Input | Zitadel Operation | Output |
|----------|-------|-------------------|--------|
| ID-JAG | Signed assertion | Token exchange (RFC 8693) | Access token |
| ID-JAG | Signed assertion | JWT profile (RFC 7523) | Access token |
| AIMS | WIT (JWT-SVID) | JWKS verification | Validated claims |
| AAuth | Agent token | JWKS verification | Verified identity |

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Agent         │     │  Zitadel Adapter │     │    Zitadel      │
│                 │     │                  │     │                 │
│  ID-JAG ────────┼────▶│  TokenExchanger  │────▶│  Token Endpoint │
│  Assertion      │     │                  │     │                 │
│                 │     │  JWTProfileSource│────▶│  JWT Profile    │
│  AIMS WIT ──────┼────▶│                  │     │                 │
│                 │     │  Verifier ◀──────┼─────│  JWKS Endpoint  │
│  AAuth Token ───┼────▶│                  │     │                 │
│                 │     │  Middleware      │     │  Discovery      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Next Steps

- [Getting Started](getting-started.md) - Installation and configuration
- [Examples](examples.md) - Running the demo applications
- [API Reference](api-reference.md) - Complete API documentation
