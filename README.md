# Agent Protocols

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/grokify/agent-protocols/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/grokify/agent-protocols/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/grokify/agent-protocols/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/grokify/agent-protocols/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/grokify/agent-protocols/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/grokify/agent-protocols/actions/workflows/go-sast-codeql.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/grokify/agent-protocols
 [goreport-url]: https://goreportcard.com/report/github.com/grokify/agent-protocols
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/grokify/agent-protocols
 [docs-godoc-url]: https://pkg.go.dev/github.com/grokify/agent-protocols
 [viz-svg]: https://img.shields.io/badge/visualizaton-Go-blue.svg
 [viz-url]: https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=grokify%2Fagent-protocols
 [loc-svg]: https://tokei.rs/b1/github/grokify/agent-protocols
 [repo-url]: https://github.com/grokify/agent-protocols
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/agent-protocols/blob/master/LICENSE

Go implementation of agent-to-agent communication protocols, starting with ID-JAG (Identity Assertion JWT Authorization Grant).

> **EXPERIMENTAL**: This library implements draft specifications that are subject to change.

## Overview

This repository provides Go libraries for emerging agent-to-agent protocols:

- **[idjag](./idjag/)** - Identity Assertion JWT Authorization Grant based on [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
  - [Examples](./idjag/examples/) - Working demos
  - [PIDL Definitions](./idjag/pidl/) - Protocol diagrams

- **[aims](./aims/)** - Agent Identity Management System (AIMS) based on [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00)
  - [Examples](./aims/examples/) - Working demos (simple WIT/WPT, mTLS)
  - [PIDL Definitions](./aims/pidl/) - Protocol diagrams

## Installation

```bash
go get github.com/grokify/agent-protocols
```

## Quick Start

### ID-JAG Token Exchange

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/grokify/agent-protocols/idjag"
)

func main() {
    // Create an assertion for token exchange
    assertion := &idjag.Assertion{
        Issuer:    "https://issuer.example.com",
        Subject:   "agent:my-agent",
        Audience:  []string{"https://auth.example.com"},
        IssuedAt:  time.Now(),
        ExpiresAt: time.Now().Add(5 * time.Minute),
    }

    // Exchange assertion for access token
    client := &idjag.TokenExchangeClient{
        TokenURL: "https://auth.example.com/token",
    }

    resp, err := client.Exchange(context.Background(), signedAssertion)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Access Token: %s\n", resp.AccessToken)
}
```

### Human-to-Agent Delegation

```go
// Create assertion with delegation chain
assertion := &idjag.Assertion{
    Issuer:    "https://issuer.example.com",
    Subject:   "user:alice",  // Human identity
    Audience:  []string{"https://auth.example.com"},
    IssuedAt:  time.Now(),
    ExpiresAt: time.Now().Add(5 * time.Minute),
    Actor: &idjag.Actor{
        Subject: "agent:calendar-bot",  // Acting agent
    },
}
```

## Examples

See the [idjag/examples](./idjag/examples/) directory for complete working demos:

- **[simple](./idjag/examples/simple/)** - Agent-only flow without human delegation
- **[delegation](./idjag/examples/delegation/)** - Human-to-agent delegation flow

Run an example:

```bash
go run ./idjag/examples/simple
```

## Documentation

- **ID-JAG**: [Getting Started](./docs/idjag/getting-started.md) | [Protocol Overview](./docs/idjag/protocol-overview.md)
- **AIMS**: [Getting Started](./docs/aims/getting-started.md) | [Overview](./docs/aims/overview.md)
- [API Reference](https://pkg.go.dev/github.com/grokify/agent-protocols)
- [Changelog](./CHANGELOG.md)

## Related Specifications

- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) - ID-JAG specification
- [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00) - AIMS specification
- [draft-ietf-wimse-s2s-protocol](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/) - WIMSE S2S Protocol (WIT/WPT)
- [SPIFFE](https://spiffe.io/) - Secure Production Identity Framework For Everyone
- [RFC 8693](https://tools.ietf.org/html/rfc8693) - OAuth 2.0 Token Exchange

## License

MIT License - see [LICENSE](LICENSE) for details.
