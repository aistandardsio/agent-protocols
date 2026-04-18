# Examples

This library includes two example applications demonstrating ID-JAG flows.

## Simple Example (Agent-Only)

The simple example demonstrates an agent authenticating on its own behalf without human delegation.

![Simple Flow](diagrams/simple-flow.svg)

### What It Demonstrates

- Agent creates a JWT assertion with its own identity (`sub: agent:demo-client`)
- Agent exchanges the assertion for an access token
- Agent calls a protected endpoint with the Bearer token
- Resource server validates the token and returns data

### Running the Example

```bash
go run ./examples/simple
```

### Expected Output

```
Server starting on localhost:18080

=== ID-JAG Simple Demo ===
This demo shows an agent authenticating without human delegation.

1. Creating assertion for agent...
   Subject: agent:demo-client
   Assertion created (JWT length: 574)

2. Exchanging assertion for access token...
   Access token received (length: 556)
   Token type: Bearer
   Expires in: 3600 seconds

3. Calling protected resource with access token...
   Response: {"delegated":false,"message":"Hello from protected resource!",
              "subject":"agent:demo-client","timestamp":"..."}

Demo completed successfully!
```

### Key Code Sections

#### Creating the Assertion

```go
assertion := idjag.NewAssertion(
    issuer,
    "agent:demo-client",  // Agent's own identity
    []string{audience},
    5*time.Minute,
)
```

#### Signing and Exchanging

```go
// Sign with RSA private key
signedAssertion, err := assertion.Sign(jwt.SigningMethodRS256, privateKey, keyID)

// Exchange for access token
client := idjag.NewTokenExchangeClient(tokenURL)
tokenResp, err := client.ExchangeAssertion(ctx, signedAssertion, "read:data")
```

#### Calling Protected API

```go
req, _ := http.NewRequest("GET", dataURL, nil)
req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
resp, _ := http.DefaultClient.Do(req)
```

---

## Delegation Example (Human-to-Agent)

The delegation example demonstrates an agent acting on behalf of a human user using the `act` claim.

![Delegation Flow](diagrams/delegation-flow.svg)

### What It Demonstrates

- Human delegates to an agent (via `act` claim)
- Agent exchanges the delegated assertion for an access token
- Resource server sees both the user identity AND the acting agent
- Nested delegation chains with multiple agents

### Running the Example

```bash
go run ./examples/delegation
```

### Expected Output

```
Server starting on localhost:18081

=== ID-JAG Delegation Demo ===
This demo shows an agent acting on behalf of a human user.

1. Creating delegated assertion...
   Subject (human): user:alice
   Actor (agent):   agent:calendar-bot
   Assertion created (JWT length: 613)

2. Exchanging delegated assertion for access token...
   Access token received (length: 598)
   Scope: calendar:read

3. Agent calling calendar API on behalf of user...
   Response: {"acting_as":["agent:calendar-bot"],"delegated":true,
              "events":[...],"message":"Calendar access granted",
              "user":"user:alice",...}

4. Demonstrating nested delegation (User -> Agent1 -> Agent2)...
   Subject (human):        user:bob
   Actor 1 (orchestrator): agent:orchestrator
   Actor 2 (worker):       agent:calendar-worker
   Delegation chain depth: 2
   Level 1: agent:orchestrator
   Level 2: agent:calendar-worker
   Response: {"acting_as":["agent:orchestrator","agent:calendar-worker"],
              "delegated":true,...}

Demo completed successfully!
```

### Key Code Sections

#### Creating Delegated Assertion

```go
assertion := idjag.NewDelegatedAssertion(
    issuer,
    "user:alice",           // Human user (sub claim)
    "agent:calendar-bot",   // Acting agent (act claim)
    []string{audience},
    5*time.Minute,
)
```

This creates a JWT with structure:

```json
{
  "iss": "https://issuer.example.com",
  "sub": "user:alice",
  "aud": ["http://localhost:18081"],
  "act": {
    "sub": "agent:calendar-bot"
  },
  "iat": 1609459200,
  "exp": 1609459500
}
```

#### Nested Delegation

```go
assertion := idjag.NewAssertion(issuer, "user:bob", audience, ttl)
assertion.Actor = &idjag.Actor{
    Subject: "agent:orchestrator",
    Actor: &idjag.Actor{
        Subject: "agent:calendar-worker",
    },
}
```

This creates a nested chain:

```json
{
  "sub": "user:bob",
  "act": {
    "sub": "agent:orchestrator",
    "act": {
      "sub": "agent:calendar-worker"
    }
  }
}
```

#### Reading the Delegation Chain

```go
chain := parsed.DelegationChain()
fmt.Printf("Delegation chain depth: %d\n", len(chain))
for i, actor := range chain {
    fmt.Printf("Level %d: %s\n", i+1, actor.Subject)
}
```

#### Resource Server Handler

```go
func handleCalendar(w http.ResponseWriter, r *http.Request) {
    assertion := idjag.AssertionFromContext(r.Context())

    response := map[string]any{
        "user":      assertion.Subject,    // "user:alice"
        "delegated": assertion.IsDelegated(), // true
    }

    // Include delegation chain
    if assertion.IsDelegated() {
        chain := assertion.DelegationChain()
        actors := make([]string, len(chain))
        for i, actor := range chain {
            actors[i] = actor.Subject
        }
        response["acting_as"] = actors
    }

    json.NewEncoder(w).Encode(response)
}
```

---

## Architecture of Examples

Both examples run three services in a single binary for simplicity:

```
┌────────────────────────────────────────────────────┐
│                  Example Binary                     │
├───────────────┬───────────────┬────────────────────┤
│     JWKS      │ Authorization │   Resource         │
│   Endpoint    │    Server     │    Server          │
│               │               │                    │
│ GET           │ POST          │ GET                │
│ /.well-known/ │ /token        │ /data or /calendar │
│ jwks.json     │               │                    │
└───────────────┴───────────────┴────────────────────┘
```

In production, these would typically be separate services with independent scaling and security boundaries.

---

## Nested Delegation Visualization

The delegation example includes a demonstration of nested delegation:

![Nested Delegation](diagrams/nested-delegation.svg)

### Interpreting Nested Chains

When you see a delegation chain like:

```
user:bob → agent:orchestrator → agent:calendar-worker
```

This means:

1. **Bob** authorized the orchestrator to act on his behalf
2. **Orchestrator** further delegated to the worker
3. **Worker** is the entity making the actual API call
4. The API sees **all three identities** and can make authorization decisions accordingly

### Authorization Decisions

Resource servers can implement various policies:

```go
func authorize(assertion *idjag.Assertion) bool {
    // Policy 1: Only allow specific users
    if assertion.Subject != "user:alice" && assertion.Subject != "user:bob" {
        return false
    }

    // Policy 2: Limit delegation depth
    if len(assertion.DelegationChain()) > 3 {
        return false
    }

    // Policy 3: Only allow trusted agents
    for _, actor := range assertion.DelegationChain() {
        if !isTrustedAgent(actor.Subject) {
            return false
        }
    }

    return true
}
```

---

## Building Your Own Application

Use these examples as templates:

1. **Copy the example structure**
2. **Replace key generation** with your key management system
3. **Connect to your authorization server** instead of the embedded one
4. **Implement your resource server logic** for your specific APIs
5. **Add your authorization policies** based on users and actors

### Minimal Client Example

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/grokify/agent-protocols/idjag"
    "github.com/golang-jwt/jwt/v5"
)

func main() {
    ctx := context.Background()

    // Load your private key (from file, vault, etc.)
    privateKey := loadPrivateKey()

    // Create assertion
    assertion := idjag.NewDelegatedAssertion(
        "https://your-issuer.com",
        "user:current-user",
        "agent:your-agent",
        []string{"https://your-auth-server.com"},
        5*time.Minute,
    )

    // Sign and exchange
    signed, _ := assertion.Sign(jwt.SigningMethodRS256, privateKey, "your-key-id")

    client := idjag.NewTokenExchangeClient("https://your-auth-server.com/token")
    resp, _ := client.ExchangeAssertion(ctx, signed, "your:scope")

    fmt.Printf("Access token: %s\n", resp.AccessToken)
}
```
