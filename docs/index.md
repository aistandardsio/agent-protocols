# Agent Protocols

Go implementation of agent-to-agent communication protocols.

!!! warning "Experimental"
    This library implements draft specifications that are subject to change.

## Overview

This repository provides Go libraries for emerging AI agent authentication and authorization protocols. As AI agents become more prevalent, standardized approaches to agent identity and authentication are critical for secure multi-agent systems.

## Protocols

<div class="grid cards" markdown>

-   :material-key-chain:{ .lg .middle } **ID-JAG**

    ---

    Identity Assertion JWT Authorization Grant for OAuth 2.0 token exchange.

    Best for: OAuth 2.0 environments, human-to-agent delegation, existing IdP integration.

    [:octicons-arrow-right-24: Learn more](idjag/protocol-overview.md)

-   :material-shield-account:{ .lg .middle } **AIMS**

    ---

    Agent Identity Management System using SPIFFE and WIMSE standards.

    Best for: Kubernetes/cloud-native, mTLS environments, workload identity.

    [:octicons-arrow-right-24: Learn more](aims/overview.md)

</div>

## Choosing a Protocol

| Aspect | ID-JAG | AIMS |
|--------|--------|------|
| **Type** | Protocol (specific flow) | Framework (composable standards) |
| **Identity Model** | OAuth JWT assertions | SPIFFE IDs |
| **Credential Format** | Signed JWT assertions | X.509 SVIDs, JWT-SVIDs, WITs |
| **Authentication** | Token exchange (RFC 8693) | mTLS or WIT/WPT |
| **Delegation** | `act` claim for human-to-agent | SPIFFE path conventions |
| **Best For** | OAuth 2.0 environments | Kubernetes/cloud-native |
| **Standards** | RFC 8693, RFC 7523 | SPIFFE, WIMSE |

## Installation

```bash
go get github.com/grokify/agent-protocols
```

## Quick Examples

=== "ID-JAG"

    ```go
    import "github.com/grokify/agent-protocols/idjag"

    // Agent authenticates as itself
    assertion := idjag.NewAssertion(
        "https://issuer.example.com",
        "agent:calendar-bot",
        []string{"https://auth.example.com"},
        5 * time.Minute,
    )

    // Exchange for access token
    client := idjag.NewTokenExchangeClient("https://auth.example.com/token")
    resp, err := client.ExchangeAssertion(ctx, signedAssertion, "read:data")
    ```

=== "AIMS"

    ```go
    import "github.com/grokify/agent-protocols/aims"

    // Create SPIFFE ID for agent
    spiffeID, _ := aims.NewSPIFFEID("example.com", "/agent/calendar-bot")

    // Create Workload Identity Token
    wit := aims.NewWIT(spiffeID, []string{"https://api.example.com"}, 1*time.Hour)
    signedWIT, _ := wit.Sign(privateKey, "key-1")

    // Create proof token for specific request
    wpt := aims.NewWPTForRequest(spiffeID.String(), "https://api.example.com", req)
    wpt.BindToRequest(req, privateKey, "key-1")
    ```

## Documentation

### ID-JAG

- [Protocol Overview](idjag/protocol-overview.md) - How ID-JAG works
- [Getting Started](idjag/getting-started.md) - Installation and first steps
- [Examples](idjag/examples.md) - Running the demo applications
- [Diagrams](idjag/diagrams.md) - Sequence and architecture diagrams
- [API Reference](idjag/api-reference.md) - Go package documentation

### AIMS

- [Overview](aims/overview.md) - AIMS framework introduction
- [Getting Started](aims/getting-started.md) - Installation and first steps
- [Examples](aims/examples.md) - Running the demo applications
- [Diagrams](aims/diagrams.md) - Sequence and architecture diagrams
- [API Reference](aims/api-reference.md) - Go package documentation

### Releases

- [v0.1.0](releases/v0.1.0.md) - Initial release (2026-04-19)

## Related Specifications

### ID-JAG

- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) - ID-JAG specification
- [RFC 8693](https://tools.ietf.org/html/rfc8693) - OAuth 2.0 Token Exchange
- [RFC 7523](https://tools.ietf.org/html/rfc7523) - JWT Bearer Assertion

### AIMS

- [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00) - AIMS specification
- [draft-ietf-wimse-s2s-protocol](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/) - WIMSE S2S Protocol
- [SPIFFE](https://spiffe.io/) - Secure Production Identity Framework For Everyone
