# AIMS mTLS Example: X.509 SVID Authentication

This example demonstrates AIMS agent authentication using X.509 SVIDs over mutual TLS (mTLS).

## Overview

The example shows:

- Creating a self-signed CA (simulating SPIFFE trust bundle)
- Creating X.509 SVIDs for server and agent
- Setting up mTLS server requiring client certificates
- Agent authenticating via client certificate

## Key Concepts

### X.509 SVID

An X.509 certificate containing a SPIFFE ID in the URI SAN:

```
Subject: CN=calendar-bot
URI SAN: spiffe://example.com/agent/calendar-bot
```

### mTLS (Mutual TLS)

Both client and server present certificates:

1. Server presents its X.509 SVID
2. Client (agent) presents its X.509 SVID
3. Both verify against the SPIFFE trust bundle

### SPIFFE Trust Bundle

The set of root CAs that can issue valid SVIDs for a trust domain. In production, this would be managed by SPIRE.

## Running

```bash
go run ./aims/examples/mtls
```

## Expected Output

```
=== AIMS mTLS Authentication Demo ===
This demo shows agent authentication using X.509 SVID over mTLS.

1. Creating CA certificate (SPIFFE trust bundle)...
   CA Subject: SPIFFE Trust Domain CA

2. Creating server X.509 SVID...
   Server SPIFFE ID: spiffe://example.com/service/api-server

3. Creating agent X.509 SVID...
   Agent SPIFFE ID: spiffe://example.com/agent/calendar-bot
   Credential Type: x509-svid
   Is Expired: false
   Expires At: 2026-05-10T15:00:00Z

4. Starting mTLS server...
   Server listening on https://localhost:18443

5. Creating mTLS client with agent SVID...
   Client configured with agent X.509 SVID

6. Making authenticated mTLS request...
   Response status: 200 OK
   Response body: {"client_spiffe":"spiffe://example.com/agent/calendar-bot","message":"Hello from protected resource!"}

7. Creating AgentIdentity with X.509 SVID...
   SPIFFE ID: spiffe://example.com/agent/calendar-bot
   Credential Type: x509-svid
   Is Valid: true
   Has Attestation: true

Demo completed successfully!
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Trust Domain                             │
│                    (example.com)                                │
│                                                                 │
│  ┌─────────────┐         ┌─────────────────────────────────┐   │
│  │     CA      │ issues  │          X.509 SVIDs            │   │
│  │ (Trust      │────────→│  - spiffe://example.com/agent/* │   │
│  │  Bundle)    │         │  - spiffe://example.com/service/*│  │
│  └─────────────┘         └─────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────┐  mTLS   ┌─────────────────────────────────┐   │
│  │   Agent     │────────→│       Resource Server           │   │
│  │ (calendar-  │◀────────│       (api-server)              │   │
│  │  bot)       │         │                                 │   │
│  └─────────────┘         └─────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Key Points

- X.509 SVIDs contain SPIFFE IDs in the URI SAN extension
- mTLS provides transport-level authentication
- Server extracts client SPIFFE ID from peer certificate
- In production, SPIRE would handle certificate issuance and rotation

## Production Considerations

In production deployments:

1. **SPIRE**: Use SPIRE for automatic SVID issuance and rotation
2. **Trust Bundle**: Distribute trust bundle via SPIFFE Federation or SPIRE APIs
3. **Short-Lived SVIDs**: Use short TTLs (1 hour or less) with automatic renewal
4. **Attestation**: Use hardware attestation (TPM, SGX) for stronger identity

## Related

- [Simple Example](../simple/README.md) - WIT/WPT token-based authentication
