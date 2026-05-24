# Agent Protocols Roadmap

Go implementation of emerging AI agent-to-agent communication protocols for authentication and authorization.

## Release History

| Version | Date | Highlights |
|---------|------|------------|
| v0.4.0 | 2026-05-24 | Token parsing/verification, IETF compliance, breaking API changes |
| v0.3.0 | 2026-05-11 | SharkAuth adapter, Ory adapter |
| v0.2.0 | 2026-05-11 | AAuth protocol, Zitadel adapter |
| v0.1.0 | 2026-04-19 | ID-JAG and AIMS protocols |

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

### Phase 5.5: Code Quality & Test Coverage ✅ (v0.4.0)

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

### Phase 6: Production Infrastructure (v0.5.0)

Full infrastructure with Docker Compose, configuration management, and multi-service demos.

#### Docker Compose Setup

| Component | Status | Description |
|-----------|--------|-------------|
| `docker-compose.yml` | Planned | Multi-service orchestration |
| Zitadel container | Planned | Pre-configured IdP with init scripts |
| Agent A service | Planned | Example requesting agent |
| Agent B service | Planned | Example delegated agent |
| Resource API service | Planned | Protected resource server |
| Person Server | Planned | AAuth token exchange server |
| Network configuration | Planned | Service discovery and DNS |

#### Production Configuration

| Component | Status | Description |
|-----------|--------|-------------|
| Environment variables | Planned | `.env.example` with all config options |
| Config file templates | Planned | YAML/JSON configuration examples |
| 12-factor app guide | Planned | Best practices for cloud deployment |
| Secrets management | Planned | Integration with Vault/K8s secrets |
| Multi-environment setup | Planned | Dev/staging/prod configuration |

#### End-to-End Scenarios

| Scenario | Status | Description |
|----------|--------|-------------|
| ID-JAG token exchange | Planned | Agent → IdP → Resource with real Zitadel |
| AAuth multi-agent | Planned | Delegation chain: Human → Agent A → Agent B |
| AAuth resource-managed | Planned | Resource issues token, PS exchanges |
| AIMS workload auth | Planned | WIT/WPT flow with mTLS |
| Mixed protocol gateway | Planned | Single service accepting multiple protocols |

---

### Phase 7: Cross-Protocol Bridging (v0.6.0)

Enable interoperability between protocols for mixed environments.

#### Token Conversion

| Component | Status | Description |
|-----------|--------|-------------|
| ID-JAG → AAuth bridge | ✅ | `bridge.FromIDJAG()` + `identity.ToAAuth()` |
| AIMS → ID-JAG bridge | ✅ | `bridge.FromWIT()` + `identity.ToIDJAG()` |
| AAuth → AIMS bridge | ✅ | `bridge.FromAAuth()` + `identity.ToWIT()` |
| Bidirectional adapters | ✅ | Full two-way protocol translation via `bridge/` package |

#### Gateway Patterns

| Component | Status | Description |
|-----------|--------|-------------|
| Multi-protocol middleware | ✅ | `bridge.MultiProtocolMiddleware()` HTTP handler |
| Protocol detection | ✅ | `bridge.DetectProtocol()` from JWT typ header |
| Unified identity context | ✅ | `bridge.Identity` canonical representation |
| Token normalization | ✅ | `bridge.Parse()` extracts to canonical format |

#### Bridge Examples

| Example | Status | Description |
|---------|--------|-------------|
| `demos/protocol-bridge/` | ✅ | Working cross-protocol demo |
| OAuth → Agent migration | ✅ | `docs/guides/oauth-to-agent-migration.md` |
| Hybrid authentication | ✅ | `docs/guides/hybrid-authentication.md` |

---

### Phase 8: Observability & Operations (v0.7.0)

Production monitoring, debugging, and operational tooling.

#### Distributed Tracing

| Component | Status | Description |
|-----------|--------|-------------|
| OpenTelemetry SDK | Planned | Instrumentation for all packages |
| Jaeger integration | Planned | Trace visualization |
| Trace context propagation | Planned | Cross-service correlation |
| Token flow tracing | Planned | Track tokens through exchanges |

#### Metrics & Monitoring

| Component | Status | Description |
|-----------|--------|-------------|
| Prometheus metrics | Planned | Token counts, latencies, errors |
| Grafana dashboards | Planned | Pre-built visualization |
| Alert rules | Planned | Common failure detection |
| Health endpoints | Planned | `/health`, `/ready` for all services |

#### Debugging Tools

| Component | Status | Description |
|-----------|--------|-------------|
| Token inspector CLI | Planned | Decode and validate tokens |
| Request debugger | Planned | Trace HTTP signature verification |
| Log correlation | Planned | Structured logging with trace IDs |
| Troubleshooting guide | Planned | Common issues and solutions |

---

### Phase 9: Kubernetes & Cloud Native (v0.8.0)

Native Kubernetes integration and cloud provider support.

#### Kubernetes Integration

| Component | Status | Description |
|-----------|--------|-------------|
| K8s manifests | Planned | Deployment, Service, ConfigMap |
| Helm charts | Planned | Parameterized deployment |
| AIMS workload identity | Planned | Pod identity with WIT/WPT |
| Service account tokens | Planned | K8s SA → protocol token bridge |

#### SPIFFE/SPIRE Integration

| Component | Status | Description |
|-----------|--------|-------------|
| SPIRE agent sidecar | Planned | Automatic SVID rotation |
| Workload attestation | Planned | K8s, Docker, process attestors |
| Federation examples | Planned | Cross-cluster identity |
| SPIFFE ID patterns | Planned | Best practices for agent IDs |

#### Service Mesh

| Component | Status | Description |
|-----------|--------|-------------|
| Istio integration | Planned | mTLS with AIMS |
| Linkerd integration | Planned | Lightweight service mesh |
| Envoy filters | Planned | Protocol-aware proxying |
| Traffic policies | Planned | Authorization based on agent identity |

#### Cloud Providers

| Component | Status | Description |
|-----------|--------|-------------|
| AWS IAM integration | Planned | AssumeRole with agent tokens |
| GCP Workload Identity | Planned | GKE service account binding |
| Azure Managed Identity | Planned | AKS pod identity |

---

### Phase 10: Security Hardening (v0.9.0)

Security best practices, compliance, and hardening guides.

#### Security Documentation

| Component | Status | Description |
|-----------|--------|-------------|
| Security best practices | Planned | Comprehensive security guide |
| Threat model | Planned | Attack vectors and mitigations |
| Token security | Planned | Lifetime, rotation, revocation |
| Key management | Planned | HSM, KMS integration patterns |

#### TLS & Certificates

| Component | Status | Description |
|-----------|--------|-------------|
| TLS configuration guide | Planned | Cipher suites, versions |
| Certificate rotation | Planned | Automated cert renewal |
| mTLS examples | Planned | Client certificate authentication |
| CA integration | Planned | Let's Encrypt, internal CA |

#### Compliance

| Component | Status | Description |
|-----------|--------|-------------|
| Audit logging | Planned | Token issuance/usage logs |
| Token revocation | Planned | Revocation list/endpoint |
| Compliance checklist | Planned | SOC2, GDPR considerations |
| Penetration testing | Planned | Security assessment guide |

---

### Phase 11: Enhanced Documentation (v1.0.0)

Comprehensive documentation for production readiness.

#### User Documentation

| Component | Status | Description |
|-----------|--------|-------------|
| Interactive tutorials | Planned | Step-by-step learning paths |
| Protocol comparison guide | Planned | When to use which protocol |
| Migration guides | Planned | OAuth → ID-JAG, etc. |
| FAQ and troubleshooting | Planned | Common questions answered |

#### Developer Documentation

| Component | Status | Description |
|-----------|--------|-------------|
| Architecture deep-dive | Planned | Internal design documentation |
| Extension guide | Planned | How to add custom adapters |
| Contributing guide | Planned | Code style, PR process |
| API versioning policy | Planned | Stability guarantees |

#### Operations Documentation

| Component | Status | Description |
|-----------|--------|-------------|
| Deployment guide | Planned | Step-by-step production setup |
| Upgrade procedures | Planned | Version migration paths |
| Rollback procedures | Planned | Recovery from failed upgrades |
| Disaster recovery | Planned | Backup and restore |

---

## Future Phases

### Phase 12: Integration Patterns

| Component | Status | Description |
|-----------|--------|-------------|
| gRPC support | Planned | Protocol Buffers + gRPC transport |
| Message queue auth | Planned | Kafka, RabbitMQ, NATS patterns |
| API gateway integration | Planned | Kong, Ambassador, Traefik |
| GraphQL authentication | Planned | Agent auth for GraphQL APIs |
| WebSocket support | Planned | Long-lived connection auth |

### Phase 13: Additional Adapters

| Adapter | Status | Description |
|---------|--------|-------------|
| Keycloak | Planned | Red Hat SSO integration |
| Auth0 | Planned | Auth0 tenant integration |
| AWS Cognito | Planned | AWS identity pools |
| Azure AD | Planned | Microsoft Entra ID |
| Okta | Planned | Workforce/customer identity |
| PingIdentity | Planned | Enterprise IAM |

### Phase 14: SDK Extensions

| SDK | Status | Description |
|-----|--------|-------------|
| Python SDK | Planned | Native Python implementation |
| TypeScript SDK | Planned | Browser and Node.js support |
| Rust SDK | Planned | High-performance implementation |
| Java SDK | Planned | JVM ecosystem support |
| .NET SDK | Planned | C# implementation |

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
