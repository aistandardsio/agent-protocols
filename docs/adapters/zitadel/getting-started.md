# Getting Started with Zitadel Adapter

This guide walks you through integrating agent-protocols with Zitadel.

## Installation

```bash
go get github.com/aistandardsio/agent-protocols/adapters/zitadel
```

## Prerequisites

- Go 1.21 or later
- A Zitadel instance (cloud or self-hosted)
- Basic familiarity with one of the agent protocols (ID-JAG, AIMS, or AAuth)

## Quick Start

### 1. Token Exchange (ID-JAG)

Exchange an ID-JAG assertion for a Zitadel access token:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/aistandardsio/agent-protocols/adapters/zitadel"
    "github.com/aistandardsio/agent-protocols/idjag"
)

func main() {
    ctx := context.Background()

    // Create token exchanger with OIDC discovery
    exchanger, err := zitadel.NewTokenExchanger("https://your-instance.zitadel.cloud")
    if err != nil {
        log.Fatal(err)
    }

    // Create and sign an ID-JAG assertion
    assertion := idjag.NewAssertion(
        "https://your-instance.zitadel.cloud",
        "agent:my-agent",
        []string{"https://your-instance.zitadel.cloud"},
        5*time.Minute,
    )
    signedAssertion, _ := assertion.Sign(jwt.SigningMethodRS256, privateKey, "key-1")

    // Exchange for access token
    resp, err := exchanger.ExchangeAssertion(ctx, signedAssertion,
        zitadel.WithScope("openid profile"),
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Access Token: %s\n", resp.AccessToken)
}
```

### 2. JWT Profile Source

Use `JWTProfileSource` for automatic token management:

```go
package main

import (
    "net/http"

    "github.com/aistandardsio/agent-protocols/adapters/zitadel"
    "golang.org/x/oauth2"
)

func main() {
    // Create assertion signer
    signer := zitadel.NewIDJAGAssertionSigner(
        "https://your-instance.zitadel.cloud",
        "agent:my-agent",
        jwt.SigningMethodRS256,
        privateKey,
        "key-1",
    )

    // Create token source
    source, _ := zitadel.NewJWTProfileSource(
        "https://your-instance.zitadel.cloud",
        "your-client-id",
        signer,
        zitadel.WithJWTProfileScopes("openid", "profile"),
    )

    // Use with oauth2 HTTP client
    client := oauth2.NewClient(context.Background(), source)
    resp, _ := client.Get("https://api.example.com/data")
}
```

### 3. Token Verification

Verify tokens from any protocol:

```go
package main

import (
    "context"
    "fmt"

    "github.com/aistandardsio/agent-protocols/adapters/zitadel"
)

func main() {
    ctx := context.Background()

    // Create verifier with OIDC discovery
    verifier, _ := zitadel.NewVerifier("https://your-instance.zitadel.cloud")

    // Verify an ID-JAG assertion
    assertion, err := verifier.VerifyIDJAGAssertion(ctx, tokenString)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Subject: %s\n", assertion.Subject)
    if assertion.Actor != nil {
        fmt.Printf("Actor: %s\n", assertion.Actor.Subject)
    }
}
```

### 4. HTTP Middleware

Protect your API endpoints:

```go
package main

import (
    "net/http"

    "github.com/aistandardsio/agent-protocols/adapters/zitadel"
)

func main() {
    verifier, _ := zitadel.NewVerifier("https://your-instance.zitadel.cloud")

    // Create middleware options
    opts := zitadel.MiddlewareOptions{
        RequiredAudience: "https://api.example.com",
    }

    // Protected handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get verified assertion from context
        assertion, _ := zitadel.IDJAGAssertionFromContext(r.Context())
        w.Write([]byte("Hello, " + assertion.Subject))
    })

    // Apply middleware
    http.Handle("/api/", zitadel.RequireIDJAG(verifier, opts).Handler(handler))
    http.ListenAndServe(":8080", nil)
}
```

## Configuration Options

### TokenExchanger Options

```go
exchanger, _ := zitadel.NewTokenExchanger(issuer,
    // Use custom HTTP client
    zitadel.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),

    // Skip OIDC discovery, use static endpoint
    zitadel.WithStaticTokenEndpoint("https://example.com/oauth/token"),

    // Add client credentials for authentication
    zitadel.WithClientCredentials("client-id", "client-secret"),
)
```

### Verifier Options

```go
verifier, _ := zitadel.NewVerifier(issuer,
    // Skip OIDC discovery
    zitadel.WithStaticJWKSURL("https://example.com/.well-known/jwks.json"),

    // Allow clock skew
    zitadel.WithClockSkew(5 * time.Minute),

    // Restrict allowed algorithms
    zitadel.WithAllowedAlgorithms("RS256", "ES256"),

    // Require specific audience
    zitadel.WithRequiredAudience("https://api.example.com"),
)
```

### Middleware Options

```go
opts := zitadel.MiddlewareOptions{
    // Require specific audience
    RequiredAudience: "https://api.example.com",

    // Allow unauthenticated requests (check in handler)
    AllowAnonymous: true,

    // Custom error handler
    ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
    },
}
```

## Error Handling

The adapter defines specific error types:

```go
import "github.com/aistandardsio/agent-protocols/adapters/zitadel"

resp, err := exchanger.ExchangeAssertion(ctx, assertion)
if err != nil {
    switch {
    case errors.Is(err, zitadel.ErrDiscoveryFailed):
        // OIDC discovery failed
    case errors.Is(err, zitadel.ErrTokenExchangeFailed):
        // Token exchange request failed
    case errors.Is(err, zitadel.ErrVerificationFailed):
        // Token verification failed
    case errors.Is(err, zitadel.ErrInvalidTokenType):
        // Wrong token type for operation
    default:
        // Other error
    }
}
```

## Next Steps

- [Examples](examples.md) - Run the demo applications
- [API Reference](api-reference.md) - Complete API documentation
- [Overview](overview.md) - Architecture and design
