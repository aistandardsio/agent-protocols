# Simple ID-JAG Example

This example demonstrates a basic ID-JAG token exchange flow where an agent authenticates on its own behalf (no human delegation).

## Overview

The example runs three services in a single binary:

- **Authorization Server** (`/token`): Accepts token exchange requests
- **Resource Server** (`/data`): Protected endpoint requiring valid access token
- **JWKS Endpoint** (`/.well-known/jwks.json`): Serves public keys for verification

## Flow

```
┌─────────┐     1. Create Assertion      ┌──────────────────┐
│  Agent  │ ───────────────────────────→ │ Assertion Issuer │
└─────────┘                              │  (self-signed)   │
     │                                    └──────────────────┘
     │
     │ 2. Exchange Assertion
     ↓
┌──────────────────────┐
│ Authorization Server │
│      /token          │
└──────────────────────┘
     │
     │ 3. Access Token
     ↓
┌─────────┐     4. Bearer Token          ┌─────────────────┐
│  Agent  │ ───────────────────────────→ │ Resource Server │
└─────────┘                              │     /data       │
     │                                    └─────────────────┘
     │
     │ 5. Protected Data
     ↓
```

## Running

```bash
go run ./examples/simple
```

## Expected Output

```
Server starting on localhost:8080

=== ID-JAG Simple Demo ===
This demo shows an agent authenticating without human delegation.

1. Creating assertion for agent...
   Subject: agent:demo-client
   Assertion created (JWT length: 512)

2. Exchanging assertion for access token...
   Access token received (length: 485)
   Token type: Bearer
   Expires in: 3600 seconds

3. Calling protected resource with access token...
   Response: {"message":"Hello from protected resource!","subject":"agent:demo-client","delegated":false,"timestamp":"..."}

Demo completed successfully!
```

## Key Points

- The agent (`agent:demo-client`) authenticates as itself
- No human delegation is involved (`delegated: false`)
- Uses RS256 for JWT signing
- Demonstrates RFC 8693 token exchange flow
