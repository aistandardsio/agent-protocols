# Getting Started

This guide walks you through setting up and using the ID-JAG library.

## Installation

```bash
go get github.com/grokify/agent-protocols
```

## Understanding ID-JAG

Before diving into code, understand the two authentication modes:

### Simple Mode (Agent-Only)

![Simple Flow](diagrams/simple-flow.svg)

The agent authenticates as itself without human delegation. Use this for:

- Autonomous agents with their own credentials
- Service-to-service communication
- Background jobs and scheduled tasks

### Delegation Mode (Human-to-Agent)

![Delegation Flow](diagrams/delegation-flow.svg)

The agent acts on behalf of a human user. Use this for:

- Personal assistants accessing user data
- Agents performing actions requiring user authorization
- Workflows that need audit trails of human authorization

---

## Basic Usage

### Step 1: Create an Assertion

An assertion is a JWT that represents an identity claim.

**Agent-only authentication:**

```go
import (
    "time"
    "github.com/grokify/agent-protocols/idjag"
)

// Agent authenticates as itself
assertion := idjag.NewAssertion(
    "https://issuer.example.com",  // Issuer
    "agent:my-agent",               // Subject (agent's identity)
    []string{"https://auth.example.com"}, // Audience
    5 * time.Minute,                // TTL
)
```

**Human-to-agent delegation:**

```go
// Agent acts on behalf of human
assertion := idjag.NewDelegatedAssertion(
    "https://issuer.example.com",
    "user:alice",           // Human user (sub)
    "agent:calendar-bot",   // Acting agent (act)
    []string{"https://auth.example.com"},
    5 * time.Minute,
)
```

### Step 2: Sign the Assertion

```go
import (
    "crypto/rand"
    "crypto/rsa"
    "github.com/golang-jwt/jwt/v5"
)

// Generate or load your private key
privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

// Sign the assertion
signedJWT, err := assertion.Sign(
    jwt.SigningMethodRS256,
    privateKey,
    "my-key-id",  // Key ID for JWKS lookup
)
if err != nil {
    log.Fatal(err)
}
```

### Step 3: Exchange for Access Token

```go
import "context"

ctx := context.Background()

// Create token exchange client
client := idjag.NewTokenExchangeClient("https://auth.example.com/token")

// Exchange assertion for access token
resp, err := client.ExchangeAssertion(ctx, signedJWT, "read:data")
if err != nil {
    log.Fatal(err)
}

// Use the access token
fmt.Println("Access Token:", resp.AccessToken)
fmt.Println("Expires In:", resp.ExpiresIn, "seconds")
```

### Step 4: Call Protected APIs

```go
import "net/http"

req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
req.Header.Set("Authorization", "Bearer " + resp.AccessToken)

apiResp, err := http.DefaultClient.Do(req)
// Handle response...
```

---

## Working with Delegation

### Creating Delegated Assertions

```go
// Single-level delegation: Human -> Agent
assertion := idjag.NewDelegatedAssertion(
    "https://issuer.example.com",
    "user:alice",           // Human user
    "agent:calendar-bot",   // Acting agent
    []string{"https://auth.example.com"},
    5 * time.Minute,
)
```

### Nested Delegation Chains

For multi-agent workflows:

```go
// Nested delegation: Human -> Agent1 -> Agent2
assertion := idjag.NewAssertion(
    "https://issuer.example.com",
    "user:bob",
    []string{"https://auth.example.com"},
    5 * time.Minute,
)

assertion.Actor = &idjag.Actor{
    Subject: "agent:orchestrator",
    Actor: &idjag.Actor{
        Subject: "agent:worker",
    },
}
```

### Reading Delegation Information

```go
// Check if assertion is delegated
if assertion.IsDelegated() {
    fmt.Printf("User: %s\n", assertion.Subject)
    fmt.Printf("Actor: %s\n", assertion.Actor.Subject)
}

// Get full delegation chain
chain := assertion.DelegationChain()
for i, actor := range chain {
    fmt.Printf("Level %d: %s\n", i+1, actor.Subject)
}
```

---

## Verifying Tokens

### Using a Static Key

For scenarios where you have the public key:

```go
verifier := idjag.NewStaticKeyVerifier(
    publicKey,
    "my-key-id",
    idjag.VerifierOptions{
        ExpectedIssuer:   "https://issuer.example.com",
        ExpectedAudience: "https://auth.example.com",
    },
)

assertion, err := verifier.Verify(ctx, tokenString)
if err != nil {
    log.Fatal("Token verification failed:", err)
}
```

### Using JWKS

For dynamic key discovery from a JWKS endpoint:

```go
verifier := idjag.NewJWKSVerifier(
    "https://issuer.example.com/.well-known/jwks.json",
    idjag.VerifierOptions{
        ExpectedIssuer: "https://issuer.example.com",
    },
)

assertion, err := verifier.Verify(ctx, tokenString)
```

### Verification Options

```go
opts := idjag.VerifierOptions{
    // Required claims
    ExpectedIssuer:   "https://issuer.example.com",
    ExpectedAudience: "https://auth.example.com",

    // Allowed signing algorithms (default: RS256, ES256, etc.)
    AllowedAlgorithms: []string{"RS256", "RS384"},

    // Clock skew tolerance
    ClockSkew: 30 * time.Second,

    // Require delegation (act claim must be present)
    RequireActor: true,
}
```

---

## Server-Side Components

### Authorization Server

Handle token exchange requests:

```go
verifier := idjag.NewStaticKeyVerifier(publicKey, keyID, opts)

authServer := idjag.NewAuthorizationServer(
    verifier,
    jwt.SigningMethodRS256,
    privateKey,
    keyID,
    "https://auth.example.com",  // Issuer for access tokens
)
authServer.TokenTTL = 1 * time.Hour
authServer.AllowedScopes = []string{"read:data", "write:data"}

// Register as HTTP handler
http.HandleFunc("POST /token", authServer.ServeHTTP)
```

### Resource Server

Validate access tokens with middleware:

```go
verifier := idjag.NewStaticKeyVerifier(publicKey, keyID, opts)
resourceServer := idjag.NewResourceServer(verifier)

// Wrap your handler with authentication middleware
http.HandleFunc("GET /api/data",
    resourceServer.Middleware(http.HandlerFunc(handleData)).ServeHTTP)

func handleData(w http.ResponseWriter, r *http.Request) {
    // Access the verified assertion
    assertion := idjag.AssertionFromContext(r.Context())

    fmt.Printf("Request from: %s\n", assertion.Subject)
    if assertion.IsDelegated() {
        fmt.Printf("Acting as: %s\n", assertion.Actor.Subject)
    }

    // Handle request...
}
```

### JWKS Endpoint

Serve your public keys:

```go
jwks := &idjag.JWKS{
    Keys: []idjag.JWK{
        idjag.NewJWKFromRSAPublicKey(publicKey, "key-1", "RS256"),
    },
}

http.HandleFunc("GET /.well-known/jwks.json",
    idjag.NewJWKSHandler(jwks).ServeHTTP)
```

---

## Running the Examples

```bash
# Simple agent-only flow
go run ./examples/simple

# Human-to-agent delegation
go run ./examples/delegation
```

---

## Next Steps

- Read the [Protocol Overview](protocol-overview.md) to understand ID-JAG concepts in depth
- Explore the [Examples](examples.md) for complete working demos
- Check the [API Reference](api-reference.md) for complete documentation
