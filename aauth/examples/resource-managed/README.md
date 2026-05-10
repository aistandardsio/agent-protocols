# AAuth Resource-Managed Example: Challenge-Response Flow

This example demonstrates the **resource-managed flow** where resources challenge agents to obtain auth tokens from the Person Server before granting access.

## When to Use

Resource-managed mode is suitable when:

- Resources need to verify human authorization for the agent
- Fine-grained scope-based access control is required
- Resources want the Person Server to enforce authorization policies

## How It Works

1. **Initial request**: Agent sends a signed request without an auth token
2. **Challenge**: Resource returns `401 Unauthorized` with `WWW-Authenticate: AAuth` challenge containing a resource token
3. **Token exchange**: Agent exchanges the resource token at the Person Server for an auth token
4. **Authorized request**: Agent retries with both signature and auth token
5. **Access granted**: Resource verifies signature and auth token, then grants access

## Key Components

- `ResourceServer`: Issues resource tokens in challenges, verifies auth tokens
- `AuthServer` (Person Server): Exchanges resource tokens for auth tokens
- Resource Token (`aa-resource+jwt`): Contains agent JKT, scope, and resource URL
- Auth Token (`aa-auth+jwt`): Contains `cnf` claim binding token to agent's key

## WWW-Authenticate Challenge Format

```
WWW-Authenticate: AAuth realm="https://calendar.example.com"
  ps="https://ps.example.com"
  resource_token="eyJ..."
```

## Running the Example

```bash
go run ./aauth/examples/resource-managed
```

## Expected Output

```
Person Server running at: http://127.0.0.1:XXXXX
Created agent: aauth:calendar-bot@example.com
Created resource server: https://calendar.example.com
Resource server running at: http://127.0.0.1:XXXXX

Step 1: Attempting access without auth token...
  Response: 401 Unauthorized
  WWW-Authenticate: AAuth realm="https://calendar.example.com" ...

Step 2: Creating resource token for exchange...
  Resource token issued (length: XXX chars)

Step 3: Exchanging resource token at Person Server...
  Auth token issued (length: XXX chars)
  Auth token subject: aauth:calendar-bot@example.com
  Auth token scope: calendar:read

Step 4: Accessing resource with auth token...
  Response: 200 OK
  Response body: map[agent_id:aauth:calendar-bot@example.com auth_scope:calendar:read ...]

Resource-managed flow completed!
```

## Related

- [Simple Example](../simple/README.md) - Identity-only mode
- [Delegation Example](../delegation/README.md) - Human-to-agent delegation
