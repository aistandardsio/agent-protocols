# Protocol Overview

ID-JAG (Identity Assertion JWT Authorization Grant) enables secure token exchange for agent authentication and delegation. This page provides a comprehensive overview of how ID-JAG works.

## Architecture

ID-JAG builds on established OAuth 2.0 and JWT standards to create a flexible authentication framework for AI agents.

![ID-JAG Architecture](diagrams/architecture.svg)

### Components

| Component | Role |
|-----------|------|
| **Human User** | The principal whose identity may be delegated to an agent |
| **AI Agent** | Software that authenticates to access protected resources |
| **Identity Provider** | Issues identity credentials and assertions |
| **Assertion Issuer** | Creates signed JWT assertions for token exchange |
| **Authorization Server** | Validates assertions and issues access tokens |
| **Resource Server** | Hosts protected APIs, validates access tokens |
| **JWKS Endpoint** | Distributes public keys for signature verification |

## The Problem ID-JAG Solves

Traditional OAuth 2.0 flows were designed for web applications where users directly interact with authorization servers. AI agents face unique challenges:

1. **Agent Identity**: Agents need their own identities, distinct from users
2. **Delegation**: Agents often act on behalf of humans with proper authorization
3. **Chain of Trust**: Complex workflows involve multiple agents delegating to each other
4. **Audit Trail**: Systems need to track both who authorized an action and who performed it

ID-JAG addresses these challenges by introducing the **actor claim** (`act`) for delegation while maintaining compatibility with existing OAuth infrastructure.

## Two Authentication Modes

ID-JAG supports two primary authentication modes:

### 1. Simple Mode (Agent-Only)

The agent authenticates as itself without any human delegation. This is suitable for:

- Autonomous agents with their own credentials
- Service-to-service communication
- Scheduled tasks and background jobs

### 2. Delegation Mode (Human-to-Agent)

The agent acts on behalf of a human user. The assertion contains:

- `sub`: The human user's identity
- `act`: The agent's identity

This preserves the human's identity while allowing the agent to perform actions on their behalf.

---

## Simple Flow (Agent-Only)

In the simple flow, an agent authenticates using its own identity without human delegation.

![Simple Flow](diagrams/simple-flow.svg)

### Step-by-Step Walkthrough

#### Step 1: Create Identity Assertion

The agent creates a JWT assertion claiming its identity:

```json
{
  "iss": "https://issuer.example.com",
  "sub": "agent:calendar-bot",
  "aud": ["https://auth.example.com"],
  "iat": 1609459200,
  "exp": 1609459500
}
```

**Claims explained:**

| Claim | Description |
|-------|-------------|
| `iss` | Issuer - who created this assertion |
| `sub` | Subject - the agent's identity |
| `aud` | Audience - the authorization server |
| `iat` | Issued At - when the assertion was created |
| `exp` | Expires - when the assertion expires (short-lived!) |

#### Step 2: Sign the Assertion

The agent signs the assertion using its private key (RS256, ES256, etc.):

```go
signedJWT, err := assertion.Sign(jwt.SigningMethodRS256, privateKey, "key-id-1")
```

#### Step 3: Token Exchange Request

The agent sends the signed assertion to the authorization server:

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&scope=read:calendar
```

#### Step 4: Authorization Server Validates

The authorization server:

1. Parses the JWT header to find the `kid` (key ID)
2. Fetches the public key from the JWKS endpoint
3. Verifies the signature
4. Validates all claims (issuer, audience, expiration)
5. Applies any additional policies

#### Step 5: Access Token Issued

If validation succeeds, the server returns an access token:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

#### Step 6: Access Protected Resources

The agent uses the access token to call protected APIs:

```http
GET /api/calendar HTTP/1.1
Host: resource.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

### Go Code Example

```go
// Create assertion for agent-only authentication
assertion := idjag.NewAssertion(
    "https://issuer.example.com",
    "agent:calendar-bot",
    []string{"https://auth.example.com"},
    5*time.Minute,
)

// Sign the assertion
signed, _ := assertion.Sign(jwt.SigningMethodRS256, privateKey, "key-1")

// Exchange for access token
client := idjag.NewTokenExchangeClient("https://auth.example.com/token")
resp, _ := client.ExchangeAssertion(ctx, signed, "read:calendar")

// Use the access token
fmt.Println("Token:", resp.AccessToken)
```

---

## Delegation Flow (Human-to-Agent)

In the delegation flow, an agent acts on behalf of a human user. The key difference is the `act` (actor) claim.

![Delegation Flow](diagrams/delegation-flow.svg)

### Step-by-Step Walkthrough

#### Step 1: Human Authenticates

The human user authenticates with their identity provider using standard mechanisms (OAuth, OIDC, SAML, etc.).

#### Step 2: Delegation Assertion Created

An assertion is created that identifies:

- **Subject (`sub`)**: The human user being represented
- **Actor (`act`)**: The agent performing actions

```json
{
  "iss": "https://idp.example.com",
  "sub": "user:alice",
  "aud": ["https://auth.example.com"],
  "act": {
    "sub": "agent:calendar-bot"
  },
  "iat": 1609459200,
  "exp": 1609459500
}
```

**Key insight**: The `sub` claim is the human's identity, preserving their authorization context. The `act` claim identifies who is actually making the request.

#### Step 3: Token Exchange

The agent exchanges the delegated assertion:

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIs...
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&scope=calendar:read
```

#### Step 4: Access Token with Delegation

The returned access token preserves the delegation context:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user:alice",
  "act": {
    "sub": "agent:calendar-bot"
  },
  "scope": "calendar:read",
  "exp": 1609463100
}
```

#### Step 5: Resource Server Authorization

The resource server can make authorization decisions based on:

- **Who is being represented** (`sub: user:alice`) - for data access
- **Who is acting** (`act.sub: agent:calendar-bot`) - for audit and agent-specific policies

### Go Code Example

```go
// Create delegated assertion
assertion := idjag.NewDelegatedAssertion(
    "https://idp.example.com",
    "user:alice",           // Human user
    "agent:calendar-bot",   // Acting agent
    []string{"https://auth.example.com"},
    5*time.Minute,
)

// Sign and exchange
signed, _ := assertion.Sign(jwt.SigningMethodRS256, privateKey, "key-1")
client := idjag.NewTokenExchangeClient("https://auth.example.com/token")
resp, _ := client.ExchangeAssertion(ctx, signed, "calendar:read")

// Access Alice's calendar
req, _ := http.NewRequest("GET", "https://api.example.com/calendar", nil)
req.Header.Set("Authorization", "Bearer "+resp.AccessToken)
```

---

## Nested Delegation

ID-JAG supports nested delegation chains where multiple agents are involved. This is common in orchestration scenarios.

![Nested Delegation](diagrams/nested-delegation.svg)

### Use Case: Multi-Agent Workflow

Consider a scenario where:

1. **User Bob** asks an orchestrator to schedule meetings
2. **Orchestrator Agent** breaks this into subtasks
3. **Worker Agent** performs the actual calendar operations

The delegation chain is: `user:bob` → `agent:orchestrator` → `agent:worker`

### Nested Actor Claim

```json
{
  "iss": "https://issuer.example.com",
  "sub": "user:bob",
  "aud": ["https://auth.example.com"],
  "act": {
    "sub": "agent:orchestrator",
    "act": {
      "sub": "agent:worker"
    }
  }
}
```

### Reading the Delegation Chain

In Go, you can traverse the delegation chain:

```go
assertion := idjag.AssertionFromContext(ctx)

// Check if delegated
if assertion.IsDelegated() {
    fmt.Printf("User: %s\n", assertion.Subject)

    // Traverse the chain
    for i, actor := range assertion.DelegationChain() {
        fmt.Printf("Actor %d: %s\n", i+1, actor.Subject)
    }
}
```

Output:
```
User: user:bob
Actor 1: agent:orchestrator
Actor 2: agent:worker
```

### Authorization Considerations

With nested delegation, resource servers can implement policies like:

- **Allow only specific chains**: `user:* → agent:orchestrator → agent:worker`
- **Limit delegation depth**: Maximum 3 levels of delegation
- **Restrict by actor type**: Only allow trusted agent identities
- **Audit complete chains**: Log the full delegation path

---

## Token Exchange Details

The token exchange follows RFC 8693 with ID-JAG extensions. The following sequence diagram shows the complete flow from assertion creation to resource access.

![Token Exchange Sequence](diagrams/token-exchange-sequence.svg)

### Request Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Yes | The signed JWT assertion |
| `subject_token_type` | Yes | `urn:ietf:params:oauth:token-type:jwt` |
| `scope` | No | Requested scope |
| `audience` | No | Target resource server |
| `actor_token` | No | Separate actor assertion (alternative to `act` claim) |
| `actor_token_type` | Conditional | Required if `actor_token` is set |

### Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "calendar:read"
}
```

### Error Responses

| Error | Description |
|-------|-------------|
| `invalid_request` | Missing or invalid parameters |
| `invalid_grant` | Assertion validation failed |
| `invalid_client` | Unknown client identity |
| `unauthorized_client` | Client not authorized for this grant |
| `invalid_scope` | Requested scope not allowed |

---

## Security Considerations

### Assertion Lifetime

- **Short-lived**: Assertions should expire within minutes (e.g., 5 minutes)
- **Single use**: Consider implementing one-time-use tokens with `jti` claim

### Signature Algorithms

Recommended algorithms:

| Algorithm | Type | Key Size |
|-----------|------|----------|
| RS256 | RSA | 2048+ bits |
| RS384 | RSA | 2048+ bits |
| ES256 | ECDSA | P-256 |
| ES384 | ECDSA | P-384 |

**Never use**: HS256 (shared secret), none (unsigned)

### Audience Validation

Always validate the `aud` claim to prevent token reuse attacks:

```go
verifier := idjag.NewStaticKeyVerifier(publicKey, keyID, idjag.VerifierOptions{
    ExpectedAudience: "https://auth.example.com",  // Required!
})
```

### Delegation Trust

Consider implementing policies for:

1. **Allowed issuers**: Which identity providers can issue delegated assertions
2. **Allowed actors**: Which agents can act on behalf of users
3. **Delegation depth**: Maximum nesting level
4. **Scope restrictions**: Agents may have limited scope compared to users

---

## References

- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) - ID-JAG specification
- [RFC 8693](https://tools.ietf.org/html/rfc8693) - OAuth 2.0 Token Exchange
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JSON Web Token (JWT)
- [RFC 7523](https://tools.ietf.org/html/rfc7523) - JWT Bearer Assertion
