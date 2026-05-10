# Multi-Protocol Agent Authentication Demo

This demo shows all three agent authentication protocols working together in a single application.

## Overview

The demo demonstrates:

| Protocol | Identity Model | Authentication Method |
|----------|----------------|----------------------|
| **ID-JAG** | OAuth assertion | Token exchange (RFC 8693) |
| **AIMS** | SPIFFE ID | WIT + WPT tokens |
| **AAuth** | AAuth URI | HTTP signatures (RFC 9421) |

## Running

```bash
go run ./demos/multi-protocol
```

## Expected Output

```
╔═══════════════════════════════════════════════════════════════╗
║           Multi-Protocol Agent Authentication Demo           ║
╠═══════════════════════════════════════════════════════════════╣
║  Protocol  │  Identity Model  │  Authentication Method       ║
╠════════════╪══════════════════╪══════════════════════════════╣
║  ID-JAG    │  OAuth assertion │  Token exchange (RFC 8693)   ║
║  AIMS      │  SPIFFE ID       │  WIT + WPT tokens            ║
║  AAuth     │  AAuth URI       │  HTTP signatures (RFC 9421)  ║
╚═══════════════════════════════════════════════════════════════╝

┌───────────────────────────────────────────────────────────────┐
│                     ID-JAG Protocol Demo                      │
└───────────────────────────────────────────────────────────────┘

  Issuer URL: https://issuer.example.com
  Subject: agent:calendar-bot
  Audience: [https://auth.example.com]
  Signed assertion: 512 chars
  Access token received: 485 chars
  Token type: Bearer
  Expires in: 3600 seconds

  ✓ ID-JAG: Token exchange completed

┌───────────────────────────────────────────────────────────────┐
│                      AIMS Protocol Demo                       │
└───────────────────────────────────────────────────────────────┘

  SPIFFE ID: spiffe://example.com/agent/calendar-bot
  Trust Domain: example.com
  Is Agent: true
  WIT Subject: spiffe://example.com/agent/calendar-bot
  WIT Audience: [https://api.example.com]
  Signed WIT: 450 chars
  WPT Method (htm): POST
  WPT URI (htu): /api/v1/events
  WPT bound to request header: Dpop
  WIT validation: PASSED
  WPT matches request: YES

  ✓ AIMS: WIT/WPT authentication completed

┌───────────────────────────────────────────────────────────────┐
│                     AAuth Protocol Demo                       │
└───────────────────────────────────────────────────────────────┘

  AAuth ID: aauth:calendar-bot@example.com
  Local: calendar-bot
  Domain: example.com
  Agent created with signing key
  Signature-Key header: true
  Signature header: true
  Response status: 200
  Response: Access granted!

  ✓ AAuth: HTTP signature authentication completed

┌───────────────────────────────────────────────────────────────┐
│                    Protocol Comparison                        │
└───────────────────────────────────────────────────────────────┘

  Aspect             │ ID-JAG         │ AIMS           │ AAuth
  ───────────────────┼────────────────┼────────────────┼────────────────
  Identity Format    │ OAuth subject  │ SPIFFE ID      │ AAuth URI
  Credential         │ JWT assertion  │ X.509/JWT SVID │ Signed HTTP
  Request Binding    │ None           │ WPT token      │ HTTP signature
  Delegation         │ act claim      │ SPIFFE path    │ Person Server
  Best For           │ OAuth envs     │ K8s/mTLS       │ Agent-to-agent

╔═══════════════════════════════════════════════════════════════╗
║                    Demo Completed Successfully                ║
╚═══════════════════════════════════════════════════════════════╝
```

## When to Use Each Protocol

### ID-JAG

Best for environments with existing OAuth 2.0 infrastructure:

- Integration with existing identity providers
- Human-to-agent delegation via `act` claim
- Standard OAuth token exchange flow

### AIMS

Best for Kubernetes and cloud-native environments:

- SPIFFE/SPIRE integration
- mTLS authentication with X.509 SVIDs
- Hardware attestation support
- Zero-trust architectures

### AAuth

Best for agent-to-agent communication:

- HTTP message signatures (RFC 9421)
- Proof-of-possession at transport level
- Human delegation via Person Server
- Fine-grained scope control

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Multi-Agent Environment                      │
│                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │
│  │   ID-JAG    │    │    AIMS     │    │   AAuth     │             │
│  │   Agent     │    │   Agent     │    │   Agent     │             │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘             │
│         │                  │                  │                     │
│         │ JWT assertion    │ WIT + WPT        │ HTTP signature      │
│         ▼                  ▼                  ▼                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐             │
│  │   OAuth     │    │   SPIFFE    │    │  Resource   │             │
│  │   AS        │    │   Verifier  │    │   Server    │             │
│  └─────────────┘    └─────────────┘    └─────────────┘             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Protocol Bridging

In real deployments, protocols can be bridged:

1. **ID-JAG → AAuth**: Exchange OAuth token for AAuth auth token
2. **AIMS → ID-JAG**: Use SPIFFE ID as assertion subject
3. **AAuth → AIMS**: Map AAuth URI to SPIFFE ID path

See the `adapters/` directory for ecosystem-specific integrations.

## Related

- [ID-JAG Examples](../../idjag/examples/)
- [AIMS Examples](../../aims/examples/)
- [AAuth Examples](../../aauth/examples/)
