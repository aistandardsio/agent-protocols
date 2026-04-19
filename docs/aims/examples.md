# AIMS Examples

The AIMS package includes working examples demonstrating agent authentication patterns.

## Simple Example

The simple example (`aims/examples/simple/`) demonstrates basic AIMS concepts:

- Creating SPIFFE IDs
- Creating and signing Workload Identity Tokens (WIT)
- Creating and binding WIMSE Proof Tokens (WPT)
- Creating an AgentIdentity

### Running the Simple Example

```bash
go run ./aims/examples/simple
```

### Expected Output

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
   Issuer: https://example.com
   Subject: spiffe://example.com/agent/calendar-bot
   Audience: [https://api.example.com]
   Expires in: 1h0m0s

4. Creating WIMSE Proof Token (WPT) for request...
   Issuer: spiffe://example.com/agent/calendar-bot
   Audience: https://api.example.com
   HTTP Method (htm): POST
   HTTP URI (htu): /api/v1/events

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

## mTLS Example

The mTLS example (`aims/examples/mtls/`) demonstrates X.509 SVID authentication:

- Creating self-signed CA (simulating SPIFFE trust bundle)
- Creating X.509 SVIDs for server and agent
- Setting up mTLS server with client certificate verification
- Making authenticated requests with X.509 credentials

### Running the mTLS Example

```bash
go run ./aims/examples/mtls
```

### Expected Output

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

4. Starting mTLS server...
   Server listening on https://localhost:18443

5. Creating mTLS client with agent SVID...
   Client configured with agent X.509 SVID

6. Making authenticated mTLS request...
   Response status: 200 OK
   Response body: {"client_spiffe":"spiffe://example.com/agent/calendar-bot",...}

7. Creating AgentIdentity with X.509 SVID...
   SPIFFE ID: spiffe://example.com/agent/calendar-bot
   Credential Type: x509-svid
   Is Valid: true
   Has Attestation: true

Demo completed successfully!
```

## Key Concepts Demonstrated

### SPIFFE ID Types

The examples demonstrate different SPIFFE ID path conventions:

| Path Prefix | Type | Example |
|-------------|------|---------|
| `/agent/` | AI Agent | `spiffe://example.com/agent/calendar-bot` |
| `/service/` | Backend Service | `spiffe://example.com/service/api-server` |
| `/workload/` | Generic Workload | `spiffe://example.com/workload/processor` |

### Credential Types

| Credential | Use Case | Example |
|------------|----------|---------|
| JWT-SVID | Token-based auth | Simple example |
| X.509 SVID | mTLS auth | mTLS example |
| WIT | WIMSE S2S | Both examples |

### Authentication Flows

**WIT/WPT Flow (Simple Example):**

```
Agent → Create WIT → Sign WIT → Create WPT → Sign WPT → Send Request
                                                         ↓
                                               Target Service
                                                         ↓
                                           Verify WIT + WPT → Authorize
```

**mTLS Flow (mTLS Example):**

```
Agent ←→ TLS Handshake (X.509 SVID) ←→ Server
          ↓
    Client Certificate Verified
          ↓
    SPIFFE ID Extracted
          ↓
    Request Authorized
```
