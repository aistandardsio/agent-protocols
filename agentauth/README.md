# AgentAuth

AgentAuth provides a unified authorization layer for AI agents, combining two complementary protocols:

- **ID-JAG** (Identity Assertion Authorization Grant) - Automated, policy-based authorization
- **AAuth** (Agent Authorization) - Human-in-the-loop consent for sensitive operations

## Package Structure

This repository provides interface-based packages for implementing authorization servers:

### Interface-Based Packages

For composable architectures with custom storage backends:

- **[`aauth/personserver`](../aauth/personserver/)** - AAuth Person Server with `Store` interface
- **[`idjag/authzserver`](../idjag/authzserver/)** - ID-JAG Authorization Server with `Store` interface

These packages define `Store` interfaces, allowing you to implement your own storage (DynamoDB, PostgreSQL, etc.).

### Storage Implementations

For production use, storage implementations are available in a separate package:

- **[`plexusone/agentauth/store`](https://github.com/plexusone/agentauth)** - SQLite and DynamoDB implementations
  - `store.SQLiteStore` - SQLite-backed storage
  - `store.DynamoDBStore` - AWS DynamoDB storage (requires build tag)
  - `store.PersonServerAdapter` - Adapts `Storer` to `personserver.Store`
  - `store.AuthzServerAdapter` - Adapts `Storer` to `authzserver.Store`

### Core Package

The `agentauth` package provides shared types and helper functionality:

- Policy-based protocol routing (`HybridProvider`)
- Provider interfaces for unified authorization
- Token caching and refresh handling

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Your Application                           │
│                                                              │
│  ┌─────────────────────┐    ┌─────────────────────┐         │
│  │ aauth/personserver  │    │ idjag/authzserver   │         │
│  │ (Store interface)   │    │ (Store interface)   │         │
│  └──────────┬──────────┘    └──────────┬──────────┘         │
│             │                          │                     │
│             └──────────┬───────────────┘                     │
│                        │                                     │
│         ┌──────────────┴──────────────┐                      │
│         │ plexusone/agentauth/store   │                      │
│         │ (SQLite, DynamoDB, etc.)    │                      │
│         └─────────────────────────────┘                      │
└──────────────────────────────────────────────────────────────┘
```

## Quick Start

### Basic Server Setup

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "log"
    "net/http"

    "github.com/aistandardsio/agent-protocols/aauth/personserver"
    "github.com/aistandardsio/agent-protocols/idjag/authzserver"
    "github.com/plexusone/agentauth/store"
)

func main() {
    // Create SQLite store
    sqliteStore, _ := store.NewSQLite("agentauth.db")
    defer sqliteStore.Close()

    // Create adapters for both server types
    psStore := store.NewPersonServerAdapter(sqliteStore)
    asStore := store.NewAuthzServerAdapter(sqliteStore)

    // Generate signing key
    privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    keyID := "key-1"
    issuer := "http://localhost:8080"

    // Create servers
    ps, _ := personserver.New(psStore, issuer, privateKey, keyID)
    as, _ := authzserver.New(asStore, issuer, privateKey, keyID)

    // Register handlers
    mux := http.NewServeMux()

    // AAuth endpoints under /aauth
    psMux := http.NewServeMux()
    ps.RegisterHandlers(psMux)
    mux.Handle("/aauth/", http.StripPrefix("/aauth", psMux))

    // ID-JAG endpoints under /oauth
    asMux := http.NewServeMux()
    as.RegisterHandlers(asMux)
    mux.Handle("/oauth/", http.StripPrefix("/oauth", asMux))

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

### Using the CLI Server

```bash
# Run with default settings (in-memory database)
go run ./cmd/agentauth-server

# Run with persistent storage
go run ./cmd/agentauth-server --db ./agentauth.db

# Run with custom port
go run ./cmd/agentauth-server --port 9000
```

## Packages

### aauth/personserver

AAuth Person Server with interface-based storage:

```go
import "github.com/aistandardsio/agent-protocols/aauth/personserver"

// Implement personserver.Store interface for your storage backend
type MyStore struct { /* ... */ }

// Create server with your custom store
ps, err := personserver.New(myStore, issuer, privateKey, keyID,
    personserver.WithTokenTTL(2*time.Hour),
)
```

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/aauth-configuration` | Discovery metadata |
| GET | `/.well-known/jwks.json` | Public key set |
| POST | `/authorize` | Request authorization |
| GET | `/consent/{id}` | Consent page |
| POST | `/consent/{id}` | Submit consent |
| GET | `/consent/status/{id}` | Poll consent status |
| POST | `/token` | Token endpoint |
| POST | `/revoke` | Token revocation |

### idjag/authzserver

ID-JAG Authorization Server with interface-based storage:

```go
import "github.com/aistandardsio/agent-protocols/idjag/authzserver"

// Implement authzserver.Store interface for your storage backend
type MyStore struct { /* ... */ }

// Create server with your custom store
as, err := authzserver.New(myStore, issuer, privateKey, keyID,
    authzserver.WithTokenTTL(time.Hour),
    authzserver.WithPersonServerURL("http://localhost:8080/aauth"),
)
```

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/oauth-authorization-server` | Discovery metadata |
| GET | `/.well-known/jwks.json` | Public key set |
| POST | `/token` | Token exchange (RFC 8693) |
| POST | `/introspect` | Token introspection (RFC 7662) |
| POST | `/revoke` | Token revocation (RFC 7009) |
| POST | `/policy/evaluate` | Evaluate scope policy |

## Policy-Based Routing

The authorization server uses scope policies to route requests:

```go
// Create policies using the store
policies := []*store.ScopePolicy{
    {
        Pattern:  "read:*",
        Protocol: "idjag",  // Auto-approve via ID-JAG
    },
    {
        Pattern:  "write:*",
        Protocol: "aauth",  // Require human consent
        InteractionType: "supervised",
    },
    {
        Pattern:  "admin:*",
        Protocol: "aauth",
        Priority: 200,  // Higher priority
    },
}

for _, p := range policies {
    sqliteStore.CreateScopePolicy(ctx, p)
}
```

**Pattern Syntax:**

- `read:email` - Exact match
- `read:*` - Wildcard (matches `read:email`, `read:profile`, etc.)
- `api:*:read` - Glob pattern (matches `api:v1:read`, `api:v2:read`, etc.)

## Authorization Flows

### ID-JAG Flow (Automated)

```
Agent                    AuthZ Server              IdP
  │                           │                     │
  │──── Request ID-JAG ──────>│                     │
  │                           │                     │
  │<─── ID-JAG Assertion ─────│                     │
  │                           │                     │
  │──── Token Exchange ──────>│                     │
  │     (grant_type=token-exchange)                 │
  │                           │                     │
  │<─── Access Token ────────│                      │
```

### AAuth Flow (Human Consent)

```
Agent                    Person Server            User
  │                           │                     │
  │──── POST /authorize ─────>│                     │
  │                           │                     │
  │<─── 202 Accepted ────────│                      │
  │     (consent_uri, status_uri)                   │
  │                           │                     │
  │                           │<─── Visit consent ──│
  │                           │                     │
  │                           │──── Consent page ──>│
  │                           │                     │
  │                           │<─── Approve/Deny ───│
  │                           │                     │
  │──── Poll status_uri ─────>│                     │
  │                           │                     │
  │<─── Access Token ────────│                      │
```

## Client SDK

The `agentauth/client` package provides a Go SDK for agents to interact with AgentAuth servers.

### ID-JAG Token Exchange

```go
import "github.com/aistandardsio/agent-protocols/agentauth/client"

c := client.New("https://authz.example.com")

// Exchange an ID-JAG assertion for an access token
token, err := c.ExchangeIDJAG(ctx, idJagAssertion, "read:email read:profile")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Access token:", token.AccessToken)
```

### AAuth Authorization (Human Consent)

```go
// Request authorization that may require consent
result, err := c.RequestAuthorization(ctx, &client.AuthorizationRequest{
    AgentToken:  agentToken,
    UserID:      "user-123",
    Scopes:      "write:profile",
    MissionName: "Update Profile",
})
if err != nil {
    log.Fatal(err)
}

switch result.Status {
case "approved":
    // Immediate approval (pre-authorized)
    fmt.Println("Token:", result.Token.AccessToken)
case "pending":
    // User needs to approve
    fmt.Println("Please approve at:", result.ConsentURI)

    // Wait for approval
    token, err := c.WaitForConsent(ctx, result.StatusURI)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Token:", token.AccessToken)
}
```

## Examples

See the [agentauth-demo](../examples/agentauth-demo/) for a complete working example.

## Related Documentation

- [AAuth Protocol](../docs/aauth/overview.md)
- [ID-JAG Protocol](../docs/idjag/protocol-overview.md)
- [Roadmap](../docs/specs/ROADMAP.md)
