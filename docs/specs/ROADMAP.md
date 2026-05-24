# Agent Protocols Roadmap

Go implementation of emerging AI agent-to-agent communication protocols for authentication and authorization.

## Release History

| Version | Date | Highlights |
|---------|------|------------|
| v0.3.0 | 2025-05-11 | SharkAuth adapter, Ory adapter |
| v0.2.0 | 2025-05-11 | AAuth protocol, Zitadel adapter |
| v0.1.0 | 2025-04-19 | ID-JAG and AIMS protocols |

---

## Architecture Overview

Three-tier architecture across three protocols:

| Tier | Description | Status |
|------|-------------|--------|
| **Tier 1: Core Packages** | Protocol implementations | ✅ Complete |
| **Tier 2: Adapters** | Identity ecosystem integrations | ✅ Complete |
| **Tier 3: Production Demos** | Docker Compose + observability | Planned |

### Protocol Comparison

| Aspect | ID-JAG | AIMS | AAuth |
|--------|--------|------|-------|
| **Focus** | Token exchange | Workload identity | Agent delegation |
| **Identity** | OAuth JWT assertions | SPIFFE IDs | Agent URIs |
| **Standards** | RFC 8693, RFC 7523 | SPIFFE, WIMSE | RFC 9421, RFC 8693 |
| **Best For** | OAuth environments | Kubernetes/mTLS | Agent-to-agent |

---

## Completed Phases

### Phase 1: Core Protocols ✅ (v0.1.0)

| Package | Protocol | Status |
|---------|----------|--------|
| `idjag/` | ID-JAG | ✅ Complete |
| `aims/` | AIMS | ✅ Complete |
| `aauth/` | AAuth | ✅ Complete (v0.2.0) |

### Phase 2: Protocol Examples ✅ (v0.2.0)

| Example | Location | Status |
|---------|----------|--------|
| ID-JAG simple | `idjag/examples/simple/` | ✅ |
| ID-JAG delegation | `idjag/examples/delegation/` | ✅ |
| AIMS simple | `aims/examples/simple/` | ✅ |
| AIMS mTLS | `aims/examples/mtls/` | ✅ |
| AAuth simple | `aauth/examples/simple/` | ✅ |
| AAuth resource-managed | `aauth/examples/resource-managed/` | ✅ |
| AAuth delegation | `aauth/examples/delegation/` | ✅ |
| Multi-protocol | `demos/multi-protocol/` | ✅ |

### Phase 3: Zitadel Adapter ✅ (v0.2.0)

| Component | Status |
|-----------|--------|
| `adapters/zitadel/token_exchange.go` | ✅ |
| `adapters/zitadel/jwt_profile.go` | ✅ |
| `adapters/zitadel/verifier.go` | ✅ |
| `adapters/zitadel/middleware.go` | ✅ |
| Examples for ID-JAG, AIMS, AAuth | ✅ |

### Phase 4: SharkAuth Adapter ✅ (v0.3.0)

| Component | Status |
|-----------|--------|
| `adapters/sharkauth/client.go` | ✅ |
| `adapters/sharkauth/delegation.go` | ✅ |
| `adapters/sharkauth/dpop.go` | ✅ |
| AAuth examples | ✅ |

### Phase 5: Ory Adapter ✅ (v0.3.0)

| Component | Status |
|-----------|--------|
| `adapters/ory/fosite/handler.go` | ✅ |
| `adapters/ory/fosite/storage.go` | ✅ |
| `adapters/ory/hydra/client.go` | ✅ |
| ID-JAG examples | ✅ |

### Phase 5.5: Code Quality & Test Coverage ✅ (v0.3.1)

Improvements to core packages identified during verification review.

#### AIMS Package Enhancements

| Component | Status | Description |
|-----------|--------|-------------|
| `ParseWIT` function | ✅ | Parse WIT JWT strings for inspection |
| `ParseWPT` function | ✅ | Parse WPT JWT strings for inspection |
| `WITVerifier` | ✅ | Verify WIT signatures with public key |
| `WPTVerifier` | ✅ | Verify WPT signatures with public key |
| `signingMethodForKey` fix | ✅ | Proper RSA/EC/Ed25519 detection |
| `typ` header for WIT | ✅ | Added `wimse-id+jwt` type header |
| Tests for new functions | ✅ | Unit tests for parse/verify |

#### AAuth Package Fixes

| Component | Status | Description |
|-----------|--------|-------------|
| Request body size limit | ✅ | Prevent memory exhaustion |
| Context propagation | ✅ | Pass request context to verifiers |
| ResourceServer context | ✅ | Context parameter on verify methods |
| Token type validation | ✅ | Validate `typ` header in Parse functions |
| Tests for changes | ✅ | Unit tests for new functionality |
| Lint warning fix | ✅ | Suppress gosec false positive |

#### SharkAuth Adapter Fixes

| Component | Status | Description |
|-----------|--------|-------------|
| DPoP JWK parsing | ✅ | Proper RSA/EC/Ed25519 key parsing |
| DPoP verification tests | ✅ | End-to-end proof verification |

#### Documentation Updates

| Component | Status | Description |
|-----------|--------|-------------|
| AIMS verifier docs | ✅ | Document WITVerifier/WPTVerifier |
| AAuth context docs | ✅ | Document context propagation |

#### CI/Testing Improvements

| Component | Status | Description |
|-----------|--------|-------------|
| Integration test script | ✅ | `scripts/integration-test.sh` runs all examples |

---

## Current Phase

### Phase 6: Production Demos (v0.4.0)

Full infrastructure with Docker Compose, observability, and scenario testing.

#### Docker Compose Setup

| Component | Status | Description |
|-----------|--------|-------------|
| Base infrastructure | Planned | Docker Compose orchestration |
| Zitadel setup | Planned | IdP configuration and init scripts |
| Agent services | Planned | Example agent A, agent B |
| Resource API | Planned | Protected resource server |

#### Scenarios

| Scenario | Status | Description |
|----------|--------|-------------|
| ID-JAG token exchange | Planned | End-to-end token exchange flow |
| AIMS K8s workload | Planned | Kubernetes workload identity |
| AAuth multi-agent | Planned | Delegation chain demonstration |
| Cross-protocol bridge | Planned | Protocol interoperability |

#### Observability

| Component | Status | Description |
|-----------|--------|-------------|
| Jaeger | Planned | Distributed tracing |
| Prometheus | Planned | Metrics collection |
| Grafana | Planned | Dashboards and visualization |

#### Kubernetes Integration

| Component | Status | Description |
|-----------|--------|-------------|
| AIMS workload identity | Planned | Native K8s integration |
| SPIRE integration | Planned | SPIFFE runtime patterns |
| Service mesh examples | Planned | Istio/Linkerd integration |

---

## Future Phases

### Phase 7: Enhanced Documentation

- [ ] Interactive API documentation
- [ ] Protocol comparison guides
- [ ] Migration guides between protocols
- [ ] Security best practices

### Phase 8: Additional Adapters

- [ ] Keycloak adapter
- [ ] Auth0 adapter
- [ ] AWS Cognito adapter
- [ ] Azure AD adapter

### Phase 9: SDK Extensions

- [ ] Python SDK
- [ ] TypeScript/JavaScript SDK
- [ ] Rust SDK

---

## Protocol Specifications

| Protocol | Specification | Status |
|----------|---------------|--------|
| ID-JAG | [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) | Draft |
| AIMS | [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00) | Draft |
| AAuth | [draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) | Draft |

---

## Dependencies

### Tier 1: Core (Minimal)

```go
require (
    github.com/golang-jwt/jwt/v5 v5.3.1
    golang.org/x/oauth2 v0.36.0
)
```

### Tier 2: Adapters

```go
require (
    github.com/zitadel/oidc/v3  // Zitadel
    github.com/ory/fosite       // Ory
)
```

### Tier 3: Demos

```go
require (
    go.opentelemetry.io/otel                    // Observability
    go.opentelemetry.io/otel/exporters/jaeger   // Tracing
)
```

---

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## References

- [Zitadel](https://github.com/zitadel/zitadel) - Cloud-native IdP
- [SharkAuth](https://github.com/shark-auth/shark) - Agent-focused auth
- [Ory Hydra](https://github.com/ory/hydra) - OAuth 2.0 server
- [SPIFFE](https://spiffe.io/) - Workload identity standard
