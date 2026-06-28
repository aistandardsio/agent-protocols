# Agent Protocols

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Docs][docs-mkdoc-svg]][docs-mkdoc-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/aistandardsio/agent-protocols/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/aistandardsio/agent-protocols/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/aistandardsio/agent-protocols/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/aistandardsio/agent-protocols/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/aistandardsio/agent-protocols/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/aistandardsio/agent-protocols/actions/workflows/go-sast-codeql.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/aistandardsio/agent-protocols
 [goreport-url]: https://goreportcard.com/report/github.com/aistandardsio/agent-protocols
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/aistandardsio/agent-protocols
 [docs-godoc-url]: https://pkg.go.dev/github.com/aistandardsio/agent-protocols
 [docs-mkdoc-svg]: https://img.shields.io/badge/Go-dev%20guide-blue.svg
 [docs-mkdoc-url]: https://aistandards.io/agent-protocols
 [viz-svg]: https://img.shields.io/badge/visualizaton-Go-blue.svg
 [viz-url]: https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=aistandardsio%2Fagent-protocols
 [loc-svg]: https://tokei.rs/b1/github/grokify/agent-protocols
 [repo-url]: https://github.com/aistandardsio/agent-protocols
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/aistandardsio/agent-protocols/blob/main/LICENSE

Go implementation of agent-to-agent communication protocols for AI agent authentication and authorization.

> **EXPERIMENTAL**: This library implements draft specifications that are subject to change.

## Overview

This repository provides Go libraries for emerging agent-to-agent protocols:

- **[aauth](./aauth/)** - Agent Authentication using HTTP message signatures (RFC 9421) based on [draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
  - [Examples](./aauth/examples/) - Working demos (simple, delegation, token exchange)
  - [PIDL Definitions](./aauth/pidl/) - Protocol diagrams

- **[idjag](./idjag/)** - Identity Assertion JWT Authorization Grant based on [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
  - [Examples](./idjag/examples/) - Working demos
  - [PIDL Definitions](./idjag/pidl/) - Protocol diagrams

- **[aims](./aims/)** - Agent Identity Management System (AIMS) based on [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00)
  - [Examples](./aims/examples/) - Working demos (simple WIT/WPT, mTLS)
  - [PIDL Definitions](./aims/pidl/) - Protocol diagrams

- **[a2a](./a2a/)** - Agent-to-Agent Protocol for agent discovery and task delegation based on [Google A2A](https://google.github.io/A2A/)
  - Discovery client for fetching Agent Cards
  - Task invocation with async polling support

- **[authzen](./authzen/)** - AuthZEN PDP client for authorization decisions based on [OpenID AuthZEN](https://openid.github.io/authzen/)
  - PEP-to-PDP communication API
  - Agent-aware subject helpers with SPIFFE/delegation support

### Server Implementations

Interface-based authorization servers (bring your own storage):

- **[aauth/personserver](./aauth/personserver/)** - AAuth Person Server with pluggable store interface
- **[idjag/authzserver](./idjag/authzserver/)** - ID-JAG Authorization Server with pluggable store interface

For multi-protocol orchestration and production deployments, see [plexusone/agentauth](https://github.com/plexusone/agentauth).

### Cross-Protocol Bridge

- **[bridge](./bridge/)** - Cross-protocol interoperability with unified identity representation
  - Multi-protocol HTTP middleware accepting ID-JAG, AIMS, and AAuth
  - Canonical `Identity` type for protocol-agnostic code
  - Protocol detection and token parsing
- **[bridge/observe](./bridge/observe/)** - Observability integration via [OmniObserve](https://github.com/plexusone/omniobserve)
  - Distributed tracing with auth spans
  - Metrics: `auth.requests`, `auth.success`, `auth.failure`, `auth.duration`
  - Structured logging with identity context

### Adapters

Production-ready integrations with identity infrastructure:

- **[adapters/zitadel](./adapters/zitadel/)** - Integration with [Zitadel](https://zitadel.com/) OIDC for all three protocols
- **[adapters/sharkauth](./adapters/sharkauth/)** - Integration with [SharkAuth](https://github.com/shark-auth/shark) for agent delegation with DPoP
- **[adapters/ory](./adapters/ory/)** - Integration with [Ory Fosite](https://github.com/ory/fosite) and [Hydra](https://github.com/ory/hydra)

## Installation

```bash
go get github.com/aistandardsio/agent-protocols
```

## Quick Start

### AAuth - HTTP Message Signatures

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

### ID-JAG - Token Exchange

```go
import "github.com/aistandardsio/agent-protocols/idjag"

// Create assertion for token exchange
assertion := idjag.NewAssertion(
    "https://issuer.example.com",
    "agent:calendar-bot",
    []string{"https://auth.example.com"},
    5 * time.Minute,
)

// Exchange for access token
client := idjag.NewTokenExchangeClient("https://auth.example.com/token")
resp, _ := client.ExchangeAssertion(ctx, signedAssertion, "read:data")
```

### AIMS - Workload Identity

```go
import "github.com/aistandardsio/agent-protocols/aims"

// Create SPIFFE ID for agent
spiffeID, _ := aims.NewSPIFFEID("example.com", "/agent/calendar-bot")

// Create Workload Identity Token
wit := aims.NewWIT(spiffeID, []string{"https://api.example.com"}, 1*time.Hour)
signedWIT, _ := wit.Sign(privateKey, "key-1")
```

### A2A - Agent Discovery & Task Delegation

```go
import "github.com/aistandardsio/agent-protocols/a2a"

// Discover agent capabilities
discovery := a2a.NewDiscoveryClient()
card, _ := discovery.DiscoverAgent(ctx, "https://agent.example.com")

// Create client and invoke capability
client, _ := a2a.NewClient(card, a2a.WithClientBearerToken("token"))
resp, _ := client.Invoke(ctx, &a2a.TaskRequest{
    CapabilityID: "security-scan",
    Input:        json.RawMessage(`{"repo": "acme/backend"}`),
})
```

### AuthZEN - Authorization Decisions

```go
import "github.com/aistandardsio/agent-protocols/authzen"

// Create PDP client
client := authzen.NewClient("https://pdp.example.com")

// Check if agent is allowed to perform action
subject := authzen.AgentSubject("code-review-agent",
    authzen.WithWorkloadID("spiffe://example.com/agent/review"),
    authzen.WithDelegator("user:alice"),
)
allowed, _ := client.IsAllowed(ctx, subject,
    authzen.NewResource("repository", "acme/backend", nil),
    authzen.NewAction("read", nil))
```

## Examples

Each protocol includes working demos:

**AAuth:**
```bash
go run ./aauth/examples/simple      # Agent authentication
go run ./aauth/examples/delegation  # Human-to-agent delegation
```

**ID-JAG:**
```bash
go run ./idjag/examples/simple      # Agent-only flow
go run ./idjag/examples/delegation  # Human-to-agent delegation
```

**AIMS:**
```bash
go run ./aims/examples/simple       # WIT/WPT authentication
go run ./aims/examples/mtls         # mTLS with X.509 SVID
```

**Zitadel Adapter:**
```bash
go run ./adapters/zitadel/examples/idjag  # ID-JAG token exchange
go run ./adapters/zitadel/examples/aims   # AIMS WIT verification
go run ./adapters/zitadel/examples/aauth  # AAuth agent authentication
```

**SharkAuth Adapter:**
```bash
go run ./adapters/sharkauth/examples/aauth  # AAuth with delegation grants
```

**Ory Adapter:**
```bash
go run ./adapters/ory/examples/idjag  # ID-JAG with Hydra
```

**Cross-Protocol Bridge:**
```bash
go run ./demos/protocol-bridge  # Multi-protocol authentication demo
```

## Documentation

- **AAuth**: [Overview](./docs/aauth/overview.md) | [Getting Started](./docs/aauth/getting-started.md) | [Examples](./docs/aauth/examples.md)
- **ID-JAG**: [Protocol Overview](./docs/idjag/protocol-overview.md) | [Getting Started](./docs/idjag/getting-started.md)
- **AIMS**: [Overview](./docs/aims/overview.md) | [Getting Started](./docs/aims/getting-started.md)
- **A2A**: [Overview](./docs/a2a/overview.md) | [Getting Started](./docs/a2a/getting-started.md)
- **AuthZEN**: [Overview](./docs/authzen/overview.md) | [Getting Started](./docs/authzen/getting-started.md)
- **AgentAuth**: See [plexusone/agentauth](https://github.com/plexusone/agentauth) for unified deployment
- **Zitadel Adapter**: [Overview](./docs/adapters/zitadel/overview.md) | [Getting Started](./docs/adapters/zitadel/getting-started.md)
- **SharkAuth Adapter**: [Overview](./docs/adapters/sharkauth/overview.md) | [Getting Started](./docs/adapters/sharkauth/getting-started.md)
- **Ory Adapter**: [Overview](./docs/adapters/ory/overview.md) | [Getting Started](./docs/adapters/ory/getting-started.md)
- [API Reference](https://pkg.go.dev/github.com/aistandardsio/agent-protocols)
- [Changelog](./CHANGELOG.md)
- [Full Documentation](https://aistandards.io/agent-protocols/)

## Development

```bash
# Run unit tests
go test ./...

# Run linter
golangci-lint run

# Run integration tests (all protocol examples)
./scripts/integration-test.sh

# Run integration tests (quick mode - core protocols only)
./scripts/integration-test.sh --quick
```

## Related Specifications

- [draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) - AAuth Protocol specification
- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) - ID-JAG specification
- [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00) - AIMS specification
- [draft-ietf-wimse-s2s-protocol](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/) - WIMSE S2S Protocol (WIT/WPT)
- [Google A2A](https://google.github.io/A2A/) - Agent-to-Agent Protocol specification
- [OpenID AuthZEN](https://openid.github.io/authzen/) - Authorization API specification
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) - HTTP Message Signatures
- [RFC 8693](https://tools.ietf.org/html/rfc8693) - OAuth 2.0 Token Exchange
- [SPIFFE](https://spiffe.io/) - Secure Production Identity Framework For Everyone

## License

MIT License - see [LICENSE](LICENSE) for details.
