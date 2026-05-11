# Agent Protocols

Go implementation of agent-to-agent communication protocols.

!!! warning "Experimental"
    This library implements draft specifications that are subject to change.

## Overview

This repository provides Go libraries for emerging AI agent authentication and authorization protocols. As AI agents become more prevalent, standardized approaches to agent identity and authentication are critical for secure multi-agent systems.

## Protocols

<div class="grid cards" markdown>

-   :material-robot:{ .lg .middle } **AAuth**

    ---

    Agent Authentication using HTTP message signatures and token exchange.

    Best for: AI agent identity, cryptographic authentication, human delegation.

    [:octicons-arrow-right-24: Learn more](aauth/overview.md)

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

| Aspect | AAuth | ID-JAG | AIMS |
|--------|-------|--------|------|
| **Type** | Protocol | Protocol | Framework |
| **Identity Model** | AAuth IDs | OAuth JWT assertions | SPIFFE IDs |
| **Credential Format** | aa-agent+jwt, aa-auth+jwt | Signed JWT assertions | X.509 SVIDs, JWT-SVIDs, WITs |
| **Authentication** | HTTP signatures + tokens | Token exchange (RFC 8693) | mTLS or WIT/WPT |
| **Delegation** | Person Server + cnf | `act` claim | SPIFFE path conventions |
| **Best For** | AI agent identity | OAuth 2.0 environments | Kubernetes/cloud-native |
| **Standards** | RFC 9421, RFC 8693 | RFC 8693, RFC 7523 | SPIFFE, WIMSE |

## Installation

```bash
go get github.com/aistandardsio/agent-protocols
```

## Quick Examples

=== "AAuth"

    ```go
    import "github.com/aistandardsio/agent-protocols/aauth"

    // Create agent with cryptographic identity
    agentID, _ := aauth.NewAAuthID("calendar-bot", "example.com")
    agent, _ := aauth.NewAgent(agentID, privateKey,
        aauth.WithAgentProviderURL("https://agents.example.com"))

    // Create signed HTTP request
    req, _ := agent.SignedRequest(ctx, "GET", "https://api.example.com/events", nil)

    // Or use automatic signing transport
    client := &http.Client{Transport: agent.Transport(nil)}
    resp, _ := client.Get("https://api.example.com/events")
    ```

=== "ID-JAG"

    ```go
    import "github.com/aistandardsio/agent-protocols/idjag"

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
    import "github.com/aistandardsio/agent-protocols/aims"

    // Create SPIFFE ID for agent
    spiffeID, _ := aims.NewSPIFFEID("example.com", "/agent/calendar-bot")

    // Create Workload Identity Token
    wit := aims.NewWIT(spiffeID, []string{"https://api.example.com"}, 1*time.Hour)
    signedWIT, _ := wit.Sign(privateKey, "key-1")

    // Create proof token for specific request
    wpt := aims.NewWPTForRequest(spiffeID.String(), "https://api.example.com", req)
    wpt.BindToRequest(req, privateKey, "key-1")
    ```

## Adapters

Production-ready integrations with identity infrastructure.

<div class="grid cards" markdown>

-   :material-server:{ .lg .middle } **Zitadel**

    ---

    Integration with Zitadel OIDC infrastructure for all three protocols.

    [:octicons-arrow-right-24: Learn more](adapters/zitadel/overview.md)

</div>

## Documentation

### AAuth

- [Overview](aauth/overview.md) - AAuth protocol introduction
- [Getting Started](aauth/getting-started.md) - Installation and first steps
- [Examples](aauth/examples.md) - Running the demo applications
- [Diagrams](aauth/diagrams.md) - Sequence and architecture diagrams
- [API Reference](aauth/api-reference.md) - Go package documentation

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

### Adapters

- [Zitadel](adapters/zitadel/overview.md) - Integration with Zitadel OIDC infrastructure

### Releases

- [v0.2.0](releases/v0.2.0.md) - Zitadel adapter (2026-05-10)
- [v0.1.0](releases/v0.1.0.md) - Initial release (2026-04-19)

## Related Specifications

### AAuth

- [draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) - AAuth Protocol specification
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) - HTTP Message Signatures
- [RFC 8693](https://tools.ietf.org/html/rfc8693) - OAuth 2.0 Token Exchange
- [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800) - Proof-of-Possession Key Semantics

### ID-JAG

- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) - ID-JAG specification
- [RFC 8693](https://tools.ietf.org/html/rfc8693) - OAuth 2.0 Token Exchange
- [RFC 7523](https://tools.ietf.org/html/rfc7523) - JWT Bearer Assertion

### AIMS

- [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00) - AIMS specification
- [draft-ietf-wimse-s2s-protocol](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/) - WIMSE S2S Protocol
- [SPIFFE](https://spiffe.io/) - Secure Production Identity Framework For Everyone
