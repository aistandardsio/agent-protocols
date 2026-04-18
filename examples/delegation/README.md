# Delegation ID-JAG Example

This example demonstrates ID-JAG with human-to-agent delegation using the "act" (actor) claim.

## Overview

The key difference from the simple example is that the assertion includes delegation information:

```json
{
  "iss": "https://issuer.example.com",
  "sub": "user:alice",
  "act": {
    "sub": "agent:calendar-bot"
  }
}
```

- `sub` (subject): The human user's identity
- `act` (actor): The agent acting on behalf of the user

## Nested Delegation

ID-JAG supports nested delegation chains. For example, when an orchestrator agent delegates to a worker agent:

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

This represents: `user:bob` → `agent:orchestrator` → `agent:calendar-worker`

## Flow

```
┌───────────┐    Delegation    ┌─────────────────┐
│   Human   │ ──────────────→  │  Calendar Bot   │
│  (Alice)  │                  │     Agent       │
└───────────┘                  └─────────────────┘
                                       │
                                       │ 1. Create Delegated Assertion
                                       │    sub: "user:alice"
                                       │    act: { sub: "agent:calendar-bot" }
                                       ↓
                               ┌──────────────────────┐
                               │ Authorization Server │
                               └──────────────────────┘
                                       │
                                       │ 2. Access Token (with act claim)
                                       ↓
                               ┌─────────────────┐
                               │  Calendar Bot   │
                               │     Agent       │
                               └─────────────────┘
                                       │
                                       │ 3. API Request (Bearer token)
                                       ↓
                               ┌─────────────────┐
                               │  Calendar API   │
                               │  (Resource)     │
                               └─────────────────┘
```

## Running

```bash
go run ./examples/delegation
```

## Expected Output

```
Server starting on localhost:8081

=== ID-JAG Delegation Demo ===
This demo shows an agent acting on behalf of a human user.

1. Creating delegated assertion...
   Subject (human): user:alice
   Actor (agent):   agent:calendar-bot
   Assertion created (JWT length: 564)

2. Exchanging delegated assertion for access token...
   Access token received (length: 523)
   Scope: calendar:read

3. Agent calling calendar API on behalf of user...
   Response: {"acting_as":["agent:calendar-bot"],"delegated":true,"events":[...],"message":"Calendar access granted","user":"user:alice",...}

4. Demonstrating nested delegation (User -> Agent1 -> Agent2)...
   Subject (human):      user:bob
   Actor 1 (orchestrator): agent:orchestrator
   Actor 2 (worker):       agent:calendar-worker
   Delegation chain depth: 2
   Level 1: agent:orchestrator
   Level 2: agent:calendar-worker
   Response: {"acting_as":["agent:orchestrator","agent:calendar-worker"],"delegated":true,...}

Demo completed successfully!
```

## Key Points

- The human identity is preserved in the `sub` claim
- The agent identity is in the `act` claim
- Nested delegation is supported for multi-agent workflows
- Resource server can inspect the full delegation chain
- Authorization can be based on both user and agent identities
