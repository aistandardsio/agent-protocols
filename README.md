# agent-protocols

[![Go Reference](https://pkg.go.dev/badge/github.com/grokify/agent-protocols.svg)](https://pkg.go.dev/github.com/grokify/agent-protocols)
[![Build Status](https://github.com/grokify/agent-protocols/workflows/test/badge.svg)](https://github.com/grokify/agent-protocols/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/grokify/agent-protocols)](https://goreportcard.com/report/github.com/grokify/agent-protocols)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Go implementation of agent-to-agent communication protocols, starting with ID-JAG (Identity Assertion JWT Authorization Grant).

> **EXPERIMENTAL**: This library implements draft specifications that are subject to change.

## Overview

This repository provides Go libraries for emerging agent-to-agent protocols:

- **[idjag](./idjag/)** - Identity Assertion JWT Authorization Grant based on [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)

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

See the [examples](./examples/) directory for complete working demos:

- **[simple](./examples/simple/)** - Agent-only flow without human delegation
- **[delegation](./examples/delegation/)** - Human-to-agent delegation flow

Run an example:

```bash
go run ./examples/simple
```

## Documentation

- [Getting Started](./docs/getting-started.md)
- [Protocol Overview](./docs/protocol-overview.md)
- [API Reference](https://pkg.go.dev/github.com/grokify/agent-protocols)

## Related Specifications

- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) - ID-JAG specification
- [RFC 8693](https://tools.ietf.org/html/rfc8693) - OAuth 2.0 Token Exchange

## License

MIT License - see [LICENSE](LICENSE) for details.
