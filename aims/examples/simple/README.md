# AIMS Simple Example: WIT and WPT Authentication

This example demonstrates basic AIMS agent authentication using SPIFFE IDs and WIMSE tokens.

## Overview

The example shows:

- Creating a SPIFFE ID for an agent
- Creating a Workload Identity Token (WIT)
- Creating a WIMSE Proof Token (WPT) for a specific request
- Validating tokens

## Key Concepts

### SPIFFE ID

The canonical identifier format for workloads:

```
spiffe://trust-domain/path
```

Example: `spiffe://example.com/agent/calendar-bot`

### Workload Identity Token (WIT)

A JWT representing workload identity per draft-ietf-wimse-s2s-protocol:

```json
{
  "iss": "https://spire.example.com",
  "sub": "spiffe://example.com/agent/calendar-bot",
  "aud": ["https://api.example.com"],
  "exp": 1234567890,
  "cnf": { "kid": "key-1" }
}
```

### WIMSE Proof Token (WPT)

Binds authentication to a specific HTTP request:

```json
{
  "iss": "spiffe://example.com/agent/calendar-bot",
  "aud": "https://api.example.com",
  "htm": "POST",
  "htu": "/api/v1/events",
  "iat": 1234567890,
  "exp": 1234568190
}
```

## Running

```bash
go run ./aims/examples/simple
```

## Expected Output

```
=== AIMS Simple Authentication Demo ===
This demo shows agent authentication using SPIFFE ID and WIMSE tokens.

1. Creating SPIFFE ID for agent...
   SPIFFE ID: spiffe://example.com/agent/calendar-bot
   Trust Domain: example.com
   Path: /agent/calendar-bot
   Is Agent: true

2. Generating agent key pair...
   Key type: ECDSA P-256
   Key ID: agent-key-1

3. Creating Workload Identity Token (WIT)...
   Issuer: spiffe://example.com
   Subject: spiffe://example.com/agent/calendar-bot
   Audience: [https://api.example.com]
   Expires in: 1h0m0s
   Signed WIT (length: XXX chars)

4. Creating WIMSE Proof Token (WPT) for request...
   Issuer: spiffe://example.com/agent/calendar-bot
   Audience: https://api.example.com
   HTTP Method (htm): POST
   HTTP URI (htu): /api/v1/events
   WPT added to header: Dpop

5. Creating AgentIdentity...
   SPIFFE ID: spiffe://example.com/agent/calendar-bot
   Credential Type: jwt-svid
   Is Valid: true

6. Validating tokens...
   WIT validation: PASSED
   WPT validation: PASSED
   WPT matches request: YES

Demo completed successfully!
```

## Key Points

- SPIFFE IDs provide portable, verifiable workload identity
- WIT is the long-lived identity token (similar to an access token)
- WPT provides request binding (proof-of-possession)
- Both tokens are signed JWTs using ECDSA P-256

## Related

- [mTLS Example](../mtls/README.md) - X.509 SVID authentication
