# AAuth vs OAuth: Understanding the Difference

If you're familiar with OAuth 2.0, this guide explains what AAuth adds and why it's needed for AI agents.

## The Core Difference

**OAuth 2.0**: "I authorize *this application* to access my data"

**AAuth**: "I authorize *this AI agent* to perform *this specific mission* on my behalf"

```
OAuth:  Human → Authorizes → App → Accesses → Resource
                 (once)      (trusted, registered)

AAuth:  Human → Authorizes → Agent → Performs Mission → Resource
                (per-task)   (may be autonomous)
```

## Why OAuth Isn't Enough for AI Agents

### 1. Agents Act Autonomously

OAuth assumes the application acts on direct user input—you click a button, the app makes an API call. AI agents make independent decisions:

| OAuth App | AI Agent |
|-----------|----------|
| User clicks "Send Email" | Agent decides to send email |
| User selects files to upload | Agent chooses which files |
| User initiates each action | Agent chains multiple actions |

**AAuth addresses this** with mission-based consent: the user approves a specific task, not open-ended access.

### 2. Dynamic Scope Requirements

OAuth apps request fixed scopes at registration time. AI agents need different permissions for different tasks:

```
Task 1: "Schedule a meeting"     → calendar:write
Task 2: "Summarize my emails"    → mail:read
Task 3: "Update my bio"          → profile:write
```

**AAuth addresses this** with per-mission scope requests. The agent requests only what's needed for each task.

### 3. No Mission Context

OAuth tells you *what* access is requested, not *why*:

```
OAuth consent screen:
  "App wants to access your calendar"

AAuth consent screen:
  "Agent wants to schedule a meeting with John
   for the project review you discussed"
```

**AAuth addresses this** with mission metadata: name, description, and interaction type.

### 4. Trust Model Differences

| Aspect | OAuth | AAuth |
|--------|-------|-------|
| Client identity | Pre-registered with IdP | May be dynamic/unknown |
| Client secrets | Shared secret or PKCE | Cryptographic identity |
| Consent duration | Until revoked | Per-mission, time-limited |
| Revocation | User revokes app | User can cancel mid-mission |

## Protocol Comparison

### OAuth 2.0 Authorization Code Flow

```
┌──────┐     ┌─────┐     ┌──────────┐     ┌──────────┐
│ User │     │ App │     │   IdP    │     │ Resource │
└──┬───┘     └──┬──┘     └────┬─────┘     └────┬─────┘
   │            │             │                │
   │  Click     │             │                │
   │  "Login"   │             │                │
   │───────────>│             │                │
   │            │             │                │
   │            │  Redirect   │                │
   │<───────────│─────────────>                │
   │            │             │                │
   │  Login +   │             │                │
   │  Consent   │             │                │
   │────────────────────────->│                │
   │            │             │                │
   │  Redirect  │  Code       │                │
   │<────────────────────────-│                │
   │            │             │                │
   │            │  Exchange   │                │
   │            │  Code       │                │
   │            │────────────>│                │
   │            │             │                │
   │            │  Token      │                │
   │            │<────────────│                │
   │            │             │                │
   │            │  API Call   │                │
   │            │─────────────────────────────>│
   │            │             │                │
   │            │  Response   │                │
   │            │<─────────────────────────────│
```

**Key characteristics:**
- One-time consent during login
- App is pre-registered with IdP
- Token valid until expiry/revocation
- No mission context

### AAuth Human Consent Flow

```
┌───────┐     ┌───────┐     ┌────────────┐     ┌──────────┐
│ Agent │     │  PS   │     │   Human    │     │ Resource │
└───┬───┘     └───┬───┘     └─────┬──────┘     └────┬─────┘
    │             │               │                 │
    │ POST        │               │                 │
    │ /authorize  │               │                 │
    │ (mission)   │               │                 │
    │────────────>│               │                 │
    │             │               │                 │
    │ 202         │               │                 │
    │ consent_uri │               │                 │
    │<────────────│               │                 │
    │             │               │                 │
    │             │  Open         │                 │
    │             │  consent_uri  │                 │
    │             │<──────────────│                 │
    │             │               │                 │
    │             │  Mission      │                 │
    │             │  details      │                 │
    │             │──────────────>│                 │
    │             │               │                 │
    │             │  Approve      │                 │
    │             │<──────────────│                 │
    │             │               │                 │
    │ Poll        │               │                 │
    │ status_uri  │               │                 │
    │────────────>│               │                 │
    │             │               │                 │
    │ Token       │               │                 │
    │<────────────│               │                 │
    │             │               │                 │
    │ API Call    │               │                 │
    │ + Token     │               │                 │
    │─────────────────────────────────────────────>│
    │             │               │                 │
    │ Response    │               │                 │
    │<─────────────────────────────────────────────│
```

**Key characteristics:**
- Per-mission consent
- Mission context (name, description, scopes)
- Agent identity via cryptographic keys
- Human can revoke mid-mission
- Token scoped to specific mission

## Token Comparison

### OAuth Access Token

```json
{
  "iss": "https://idp.example.com",
  "sub": "user-123",
  "aud": "app-456",
  "scope": "read write",
  "exp": 1234567890,
  "iat": 1234564290
}
```

The token represents the **user's** authorization to the **app**.

### AAuth Access Token

```json
{
  "iss": "https://personserver.example.com",
  "sub": "agent-456",
  "aud": "https://resource.example.com",
  "scope": "write:profile",
  "exp": 1234567890,
  "iat": 1234564290,
  "act": {
    "sub": "user-123"
  },
  "mission_id": "mission-789",
  "interaction_type": "supervised"
}
```

The token represents the **agent's** authorization to act **on behalf of** the user for a **specific mission**.

Key additions:

| Claim | Purpose |
|-------|---------|
| `act.sub` | The human who authorized this action |
| `mission_id` | Links to the specific approved mission |
| `interaction_type` | How the agent operates (autonomous, supervised, etc.) |

## Consent Screen Comparison

### OAuth Consent

```
┌─────────────────────────────────────┐
│  "Calendar App" wants to:           │
│                                     │
│  ☑ View your calendar               │
│  ☑ Create and edit events           │
│  ☑ Access your contacts             │
│                                     │
│  [Allow]  [Deny]                    │
└─────────────────────────────────────┘
```

### AAuth Consent

```
┌─────────────────────────────────────┐
│  Mission: Schedule Project Review   │
│                                     │
│  Agent: TaskBot                     │
│  Requested by: You (via chat)       │
│                                     │
│  "Schedule a 30-minute meeting      │
│   with John for the Q3 review       │
│   you discussed earlier"            │
│                                     │
│  Permissions needed:                │
│  ☑ calendar:write                   │
│                                     │
│  Duration: 1 hour                   │
│  Mode: Supervised                   │
│                                     │
│  [Approve]  [Deny]                  │
└─────────────────────────────────────┘
```

## When to Use Which

| Scenario | Protocol |
|----------|----------|
| User logs into a web app | OAuth/OIDC |
| App syncs user's files in background | OAuth |
| User explicitly clicks "share to Twitter" | OAuth |
| AI agent books meetings autonomously | **AAuth** |
| AI agent sends emails on user's behalf | **AAuth** |
| AI agent modifies user's documents | **AAuth** |
| Chatbot performs actions user requests | **AAuth** |

**Rule of thumb**: If an AI is making decisions about *what* to do (not just *how* to do it), use AAuth.

## AAuth Builds on OAuth

AAuth isn't a replacement—it extends OAuth:

| Component | Standard |
|-----------|----------|
| Token format | JWT (RFC 7519) |
| Token exchange | RFC 8693 |
| Key distribution | JWKS (RFC 7517) |
| Proof of possession | `cnf` claim (RFC 7800) |
| Key thumbprint | RFC 7638 |

AAuth adds:

- **Mission semantics**: Why access is needed
- **Agent identity**: Cryptographic identity for agents
- **Human-in-the-loop consent**: Per-task approval
- **Interaction types**: Autonomous, supervised, collaborative

## Migration Path

If you have an OAuth-based system and want to add AI agent support:

1. **Keep OAuth** for traditional app authentication
2. **Add AAuth** for AI agent authorization
3. **Use policy routing** to direct requests:
   - Low-risk scopes → OAuth/ID-JAG (automated)
   - High-risk scopes → AAuth (human consent)

See the [AgentAuth hybrid documentation](../agentauth/overview.md) for implementing both protocols together.

## Further Reading

- [AAuth Protocol Draft](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
- [RFC 8693 - Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 7800 - Proof of Possession](https://www.rfc-editor.org/rfc/rfc7800)
- [AAuth Overview](overview.md)
- [Getting Started](getting-started.md)
