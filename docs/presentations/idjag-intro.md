---
marp: true
theme: default
paginate: true
title: Introduction to ID-JAG
description: Identity Assertion JWT Authorization Grant for Agent Authentication
---

# Introduction to ID-JAG

## Identity Assertion JWT Authorization Grant

**Secure token exchange for AI agents**

---

# The Challenge

AI agents need to:

- 🔐 **Authenticate** to backend services
- 👤 **Act on behalf of humans** with proper authorization
- 🔗 **Chain through multiple agents** in workflows

Traditional OAuth flows weren't designed for this.

---

# What is ID-JAG?

**ID-JAG** = Identity Assertion JWT Authorization Grant

Based on draft-ietf-oauth-identity-assertion-authz-grant

Builds on existing standards:
- RFC 8693 - OAuth 2.0 Token Exchange
- RFC 7519 - JSON Web Token (JWT)
- RFC 7523 - JWT Bearer Assertion

---

# Key Concepts

## Identity Assertion

A signed JWT asserting an identity:

```json
{
  "iss": "https://issuer.example.com",
  "sub": "agent:calendar-bot",
  "aud": "https://auth.example.com",
  "iat": 1609459200,
  "exp": 1609459500
}
```

---

# Delegation with Actor Claim

When an agent acts on behalf of a human:

```json
{
  "iss": "https://issuer.example.com",
  "sub": "user:alice",
  "act": {
    "sub": "agent:calendar-bot"
  }
}
```

- `sub` = who is being represented (human)
- `act` = who is acting (agent)

---

# Nested Delegation

Multi-agent workflows:

```json
{
  "sub": "user:alice",
  "act": {
    "sub": "agent:orchestrator",
    "act": {
      "sub": "agent:worker"
    }
  }
}
```

**Chain**: `alice` → `orchestrator` → `worker`

---

# The Flow

```
                         ┌──────────────┐
         1. Assertion    │  Assertion   │
┌─────────────────────── │    Issuer    │
│                        └──────────────┘
│
│  2. Token Exchange     ┌──────────────┐
├───────────────────────→│    Auth      │
│                        │   Server     │
│  3. Access Token       └──────────────┘
│←───────────────────────
│
│  4. Bearer Token       ┌──────────────┐
└───────────────────────→│  Resource    │
                         │   Server     │
                         └──────────────┘
```

---

# Token Exchange Request

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIs...
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&scope=calendar:read
```

---

# Go Implementation

```go
// Create assertion
assertion := idjag.NewDelegatedAssertion(
    "https://issuer.example.com",
    "user:alice",          // Human
    "agent:calendar-bot",  // Agent
    []string{"https://auth.example.com"},
    5*time.Minute,
)

// Sign and exchange
jwt, _ := assertion.Sign(jwt.SigningMethodRS256, key, keyID)
client := idjag.NewTokenExchangeClient(tokenURL)
resp, _ := client.ExchangeAssertion(ctx, jwt, "calendar:read")
```

---

# Use Cases

| Scenario | Example |
|----------|---------|
| Personal Assistant | Agent accesses user's calendar |
| Multi-Agent Workflow | Orchestrator delegates to workers |
| Service-to-Service | Backend services authenticate |
| Human-in-the-Loop | Agent confirms with human, then acts |

---

# Security Considerations

- ⏱️ **Short-lived assertions** (minutes)
- 🔑 **Strong algorithms** (RS256, ES256)
- 🎯 **Audience validation** always
- 🔄 **Key rotation** via JWKS
- ✅ **Delegation policies** enforced

---

# Demo

```bash
# Simple agent-only flow
go run ./examples/simple

# Human-to-agent delegation
go run ./examples/delegation
```

---

# Resources

- **GitHub**: github.com/grokify/agent-protocols
- **IETF Draft**: datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/
- **RFC 8693**: tools.ietf.org/html/rfc8693
- **RFC 7519**: tools.ietf.org/html/rfc7519

---

# Thank You

## Questions?

**github.com/grokify/agent-protocols**
