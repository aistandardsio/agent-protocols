# AIMS Overview

Agent Identity Management System (AIMS) is a framework for AI agent authentication based on [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00).

!!! warning "Experimental"
    This package implements a draft specification that is subject to change.

## What is AIMS?

Unlike ID-JAG (which is a specific protocol), AIMS is a **framework** that composes multiple identity and security standards:

| Standard | Purpose |
|----------|---------|
| **SPIFFE** | Workload identity (SPIFFE IDs as canonical identifiers) |
| **WIMSE** | Token-based authentication (WIT and WPT) |
| **OAuth 2.0** | Authorization delegation for various scenarios |

## The Nine Layers

AIMS defines nine architectural layers for agent identity management:

| Layer | Name | Description |
|-------|------|-------------|
| 1 | Identifiers | SPIFFE IDs as canonical workload identifiers |
| 2 | Credentials | X.509 SVIDs, JWT-SVIDs, WITs |
| 3 | Attestation | TPM, SGX, SEV-SNP, cloud attestation |
| 4 | Provisioning | SPIRE, cloud-native credential issuance |
| 5 | Authentication | mTLS, WIT/WPT token flows |
| 6 | Authorization | Policy-based access control |
| 7 | Monitoring | Audit logging and telemetry |
| 8 | Policy | Centralized policy management |
| 9 | Compliance | Regulatory and audit requirements |

## Key Components

### SPIFFE ID

The canonical identifier format for workloads:

```
spiffe://trust-domain/path
```

Examples:

- `spiffe://example.com/agent/calendar-bot`
- `spiffe://prod.example.com/workload/api-server`
- `spiffe://example.com/service/auth`

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

## Credential Types

| Type | Description | Use Case |
|------|-------------|----------|
| **X.509 SVID** | Certificate-based identity | mTLS authentication |
| **JWT-SVID** | JWT-based identity | Token-based authentication |
| **WIT** | Workload Identity Token | WIMSE S2S protocol |

## Attestation Types

| Type | Description |
|------|-------------|
| TPM | TPM-based hardware attestation |
| SGX | Intel SGX enclave attestation |
| SEV-SNP | AMD SEV-SNP confidential VM attestation |
| TDX | Intel TDX trusted domain attestation |
| Kubernetes | Kubernetes service account attestation |
| AWS | AWS instance identity document attestation |
| GCP | GCP instance identity token attestation |
| Azure | Azure managed identity attestation |
| GitHub | GitHub Actions OIDC token attestation |

## AIMS vs ID-JAG

| Aspect | ID-JAG | AIMS |
|--------|--------|------|
| Type | Protocol | Framework |
| Identity Model | OAuth assertions | SPIFFE IDs |
| Credential Format | JWT assertions | X.509 SVIDs, JWT-SVIDs, WITs |
| Authentication | Token exchange | mTLS or WIT/WPT |
| Standards | RFC 8693 | SPIFFE, WIMSE |

## References

- [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00)
- [draft-ietf-wimse-s2s-protocol](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/)
- [SPIFFE](https://spiffe.io/)
- [SPIRE](https://spiffe.io/spire/)
