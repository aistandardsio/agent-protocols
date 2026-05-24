# Bridge Package Overview

The bridge package provides cross-protocol interoperability for agent-protocols, enabling services to accept authentication from any supported protocol (ID-JAG, AIMS, AAuth) through a unified interface.

## Key Features

- **Canonical Identity** - Common representation across all protocols
- **Protocol Detection** - Auto-detect protocol from JWT `typ` header
- **Multi-Protocol Middleware** - Single HTTP middleware accepting any protocol
- **Token Conversion** - Convert tokens between protocols

## When to Use Bridge

Use the bridge package when you need to:

| Use Case | Solution |
|----------|----------|
| Accept multiple authentication protocols | `MultiProtocolMiddleware` |
| Detect which protocol a token uses | `DetectProtocol` |
| Convert tokens between protocols | `From*` + `To*` functions |
| Work with identity regardless of protocol | `Identity` type |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     HTTP Request                            │
│   Authorization: Bearer <token>                             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│               MultiProtocolMiddleware                       │
├─────────────────────────────────────────────────────────────┤
│   1. Extract token from Authorization header                │
│   2. Detect protocol (ID-JAG, AIMS, AAuth)                  │
│   3. Verify with appropriate verifier                       │
│   4. Convert to canonical Identity                          │
│   5. Store in request context                               │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Application Handler                        │
│   identity, _ := bridge.IdentityFromContext(r.Context())   │
└─────────────────────────────────────────────────────────────┘
```

## Canonical Identity

All three protocols share common identity fields:

```go
type Identity struct {
    Protocol   Protocol      // id-jag, aims, or aauth
    Issuer     string        // Token issuer (iss claim)
    Subject    string        // Primary identity (sub claim)
    Audience   []string      // Intended recipients (aud claim)
    IssuedAt   time.Time     // Token creation time (iat claim)
    ExpiresAt  time.Time     // Token expiration (exp claim)
    JWTID      string        // Unique token ID (jti claim)
    KeyBinding *KeyBinding   // Proof-of-possession (cnf claim)
    Actor      *Actor        // Delegation chain (act claim)
}
```

## Protocol Detection

The bridge package detects protocols from JWT `typ` headers:

| Protocol | JWT `typ` Header |
|----------|------------------|
| ID-JAG | `oauth-id-jag+jwt` |
| AIMS | `wimse-id+jwt` |
| AAuth | `aa-agent+jwt` |

If no `typ` header is present, detection falls back to claim analysis:

- `client_id` claim → ID-JAG
- `spiffe://` subject prefix → AIMS
- `aauth:` subject prefix or `dwk`/`ps` claims → AAuth

## Protocol Comparison

| Feature | ID-JAG | AIMS | AAuth |
|---------|--------|------|-------|
| Primary Use | OAuth token exchange | Workload identity | Agent delegation |
| Identity Format | OAuth subject | SPIFFE ID | AAuth URI |
| Key Binding | Optional | Via CNF | Required |
| Delegation | `act` claim | N/A | `act` claim + Person Server |

## Next Steps

- [Getting Started](getting-started.md) - Quick start with bridge package
- [OAuth to Agent Migration](../guides/oauth-to-agent-migration.md) - Migration strategies
- [Hybrid Authentication](../guides/hybrid-authentication.md) - Multi-protocol setup
