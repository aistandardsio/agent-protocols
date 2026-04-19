# AIMS Protocol Diagrams

Protocol Interaction Description Language (PIDL) definitions for AIMS (Agent Identity Management System) flows.

## Files

| File | Description |
|------|-------------|
| [`aims_wit_flow.json`](aims_wit_flow.json) | WIT (Workload Identity Token) issuance via SPIRE attestation |
| [`aims_wpt_flow.json`](aims_wpt_flow.json) | WPT (WIMSE Proof Token) authentication to target services |

## AIMS Overview

AIMS is a framework for AI agent authentication that composes:

- **SPIFFE** - Workload identity (SPIFFE IDs as canonical identifiers)
- **WIMSE** - Workload Identity Tokens (WIT) and Proof Tokens (WPT)
- **OAuth 2.0** - Authorization grants for delegation scenarios

## WIT Issuance Flow

```
Agent → SPIRE Agent → Attestor → SPIRE Server → WIT
```

The agent obtains a Workload Identity Token through:

1. Request SVID via SPIRE Workload API
2. Workload attestation (K8s, TPM, Unix socket, etc.)
3. SPIRE server matches registration entry
4. Server issues JWT-SVID (WIT) with SPIFFE ID

## WPT Authentication Flow

```
Agent (WIT + WPT) → Target Service → Trust Bundle → Verify → Authorize
```

The agent authenticates to a service using:

1. Create WPT bound to specific HTTP request (method, URI)
2. Sign WPT with key from WIT's `cnf` claim
3. Send request with WIT and WPT headers
4. Service verifies WIT signature, then WPT signature
5. Service validates request binding (htm, htu)
6. Authorize based on SPIFFE ID

## References

- [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00)
- [draft-ietf-wimse-s2s-protocol](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/)
- [SPIFFE](https://spiffe.io/)

## Using PIDL

These JSON files can be visualized using the [pidl](https://github.com/grokify/pidl) tool:

```bash
pidl render aims_wit_flow.json --format mermaid
pidl render aims_wpt_flow.json --format d2
```
