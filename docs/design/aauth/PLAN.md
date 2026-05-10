# AAuth Protocol Implementation Plan

**Status**: Draft
**Created**: 2026-05-10
**Protocol**: [draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol)

## Overview

This plan describes the implementation of the AAuth protocol as a Go package (`aauth/`) in the agent-protocols repository. AAuth enables agents to prove identity cryptographically without pre-registration, using HTTP Message Signatures (RFC 9421) and key-bound tokens.

## Protocol Summary

### What AAuth Solves

Traditional OAuth 2.0 requires pre-registration and shared secrets (client_id/client_secret). AAuth provides:

- **Self-published agent identities**: `aauth:local@domain` URIs
- **Cryptographic proof-of-possession**: Every token bound via `cnf.jwk`
- **HTTP request signing**: RFC 9421 signatures on all requests
- **Delegation chains**: `act` claim for human-to-agent authorization
- **No pre-registration**: Agents prove identity via signatures

### Token Types

| Type | Purpose | Issued By |
|------|---------|-----------|
| `aa-agent+jwt` | Agent identity | Agent Provider |
| `aa-auth+jwt` | Authorization grant | Person Server / Access Server |
| `aa-resource+jwt` | Exchange token | Resource (for PS/AS exchange) |

### Authorization Modes

1. **Identity-only**: Agent identity sufficient for access
2. **Resource-managed**: Resource controls access internally
3. **PS-asserted (3-party)**: Person Server provides human authorization
4. **Federated (4-party)**: External Access Server handles authorization

---

## Package Structure

```
aauth/
├── doc.go                     # Package documentation
├── errors.go                  # Error definitions
├── claims.go                  # Constants (token types, claims, URIs)
├── uri.go                     # aauth: URI parsing (aauth:local@domain)
├── uri_test.go
│
├── # Token Types
├── agent_token.go             # aa-agent+jwt token type
├── agent_token_test.go
├── auth_token.go              # aa-auth+jwt token type
├── auth_token_test.go
├── resource_token.go          # aa-resource+jwt token type
├── resource_token_test.go
│
├── # HTTP Signatures (RFC 9421)
├── httpsig/
│   ├── doc.go
│   ├── signer.go              # Request signing
│   ├── signer_test.go
│   ├── verifier.go            # Signature verification
│   ├── verifier_test.go
│   ├── components.go          # @method, @target-uri, etc.
│   └── params.go              # Signature-Input header parsing
│
├── # Key Management
├── key.go                     # Key pair management, CNF binding
├── key_test.go
├── jwk.go                     # JWK operations
├── jwk_test.go
│
├── # Agent-Side
├── agent.go                   # Agent client (identity + signing)
├── agent_test.go
├── agent_options.go           # AgentOption functional options
│
├── # Resource-Side
├── resource.go                # Resource server (challenges, tokens)
├── resource_test.go
├── resource_options.go        # ResourceOption functional options
├── challenge.go               # WWW-Authenticate challenge generation
├── challenge_test.go
│
├── # Auth Server
├── authserver.go              # Authorization/Person Server
├── authserver_test.go
├── authserver_options.go      # AuthServerOption functional options
├── exchange.go                # Token exchange flows
├── exchange_test.go
│
├── # Metadata Discovery
├── metadata.go                # .well-known metadata types
├── metadata_test.go
├── discovery.go               # Discovery client
├── discovery_test.go
│
├── # HTTP Integration
├── transport.go               # http.RoundTripper with auto-signing
├── transport_test.go
├── middleware.go              # Server middleware (verification)
├── middleware_test.go
├── context.go                 # Context utilities
│
├── # Verification
├── verifier.go                # Token verification interface
├── verifier_test.go
│
├── # PIDL Protocol Diagrams
├── pidl/
│   ├── identity_only.json
│   ├── resource_managed.json
│   ├── ps_asserted.json
│   └── federated.json
│
└── examples/
    ├── simple/
    │   ├── README.md
    │   └── main.go            # Identity-only flow demo
    ├── resource-managed/
    │   ├── README.md
    │   └── main.go            # Resource-managed demo
    └── delegation/
        ├── README.md
        └── main.go            # Human-to-agent delegation demo
```

---

## Core Types

### AAuth ID (`uri.go`)

```go
// AAuthID represents an AAuth agent identifier.
// Format: aauth:local@domain
type AAuthID struct {
    Local  string // e.g., "calendar-bot"
    Domain string // e.g., "example.com"
}

func ParseAAuthID(uri string) (*AAuthID, error)
func (id *AAuthID) String() string
```

### Agent Token (`agent_token.go`)

```go
// AgentToken represents an aa-agent+jwt token.
type AgentToken struct {
    Issuer    string    `json:"iss"`  // Agent Provider URL
    Subject   string    `json:"sub"`  // AAuth ID
    Audience  []string  `json:"aud"`
    IssuedAt  time.Time `json:"iat"`
    ExpiresAt time.Time `json:"exp"`
    JWTID     string    `json:"jti,omitempty"`
    CNF       *CNF      `json:"cnf"`           // Key confirmation (required)
    Actor     *Actor    `json:"act,omitempty"` // Delegation chain
}

// CNF contains the confirmation key binding (RFC 7800).
type CNF struct {
    JWK json.RawMessage `json:"jwk,omitempty"` // Embedded public key
    JKU string          `json:"jku,omitempty"` // JWKS URL
    Kid string          `json:"kid,omitempty"` // Key ID reference
}

func NewAgentToken(issuer, subject string, cnf *CNF, ttl time.Duration) *AgentToken
func (t *AgentToken) Sign(method jwt.SigningMethod, key crypto.PrivateKey, keyID string) (string, error)
func (t *AgentToken) Validate() error
```

### Auth Token (`auth_token.go`)

```go
// AuthToken represents an aa-auth+jwt token.
type AuthToken struct {
    Issuer    string    `json:"iss"`
    Subject   string    `json:"sub"`  // AAuth ID of authorized agent
    Audience  []string  `json:"aud"`  // Resource(s) authorized for
    IssuedAt  time.Time `json:"iat"`
    ExpiresAt time.Time `json:"exp"`
    CNF       *CNF      `json:"cnf"`           // Key binding
    Actor     *Actor    `json:"act,omitempty"` // Delegation chain
    Scope     string    `json:"scope,omitempty"`
}
```

### Resource Token (`resource_token.go`)

```go
// ResourceToken represents an aa-resource+jwt token.
type ResourceToken struct {
    Issuer    string    `json:"iss"`  // Resource URL
    Subject   string    `json:"sub"`  // AAuth ID
    Audience  []string  `json:"aud"`  // PS or AS URL
    IssuedAt  time.Time `json:"iat"`
    ExpiresAt time.Time `json:"exp"`
    AgentJKT  string    `json:"agent_jkt"` // JWK thumbprint
    Scope     string    `json:"scope,omitempty"`
}
```

### HTTP Signatures (`httpsig/`)

```go
// Signer signs HTTP requests per RFC 9421.
type Signer interface {
    Sign(req *http.Request) error
}

type SignerOptions struct {
    PrivateKey        crypto.PrivateKey
    KeyID             string
    Algorithm         string   // e.g., "ecdsa-p256-sha256"
    CoveredComponents []string // e.g., ["@method", "@target-uri"]
}

func NewSigner(opts SignerOptions) (Signer, error)

// Verifier verifies HTTP request signatures.
type Verifier interface {
    Verify(req *http.Request) (*VerificationResult, error)
}
```

### Agent Client (`agent.go`)

```go
// Agent represents an AAuth agent with identity and signing capability.
type Agent struct {
    // ... internal fields
}

func NewAgent(id *AAuthID, privateKey crypto.PrivateKey, opts ...AgentOption) (*Agent, error)

// SignedRequest creates a signed HTTP request.
func (a *Agent) SignedRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error)

// Authenticate performs the full authentication flow against a resource.
func (a *Agent) Authenticate(ctx context.Context, resource string) (*AuthToken, error)

// Transport returns an http.RoundTripper that auto-signs requests.
func (a *Agent) Transport() http.RoundTripper
```

### Resource Server (`resource.go`)

```go
// ResourceServer handles AAuth authentication on the resource side.
type ResourceServer struct {
    // ... internal fields
}

func NewResourceServer(url string, key crypto.PrivateKey, opts ...ResourceOption) *ResourceServer

// Middleware returns HTTP middleware that enforces AAuth authentication.
func (rs *ResourceServer) Middleware(next http.Handler) http.Handler

// IssueResourceToken creates a resource token for token exchange.
func (rs *ResourceServer) IssueResourceToken(agentID *AAuthID, audience string) (*ResourceToken, error)
```

### Auth Server (`authserver.go`)

```go
// AuthServer handles authorization token issuance.
type AuthServer struct {
    // ... internal fields
}

func NewAuthServer(issuer string, key crypto.PrivateKey, opts ...AuthServerOption) *AuthServer

// ServeHTTP implements http.Handler for the token endpoint.
func (as *AuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request)

// IssueAuthToken creates an auth token for an authorized agent.
func (as *AuthServer) IssueAuthToken(agent *AAuthID, audience []string, scope string, ttl time.Duration) (*AuthToken, error)
```

---

## Implementation Phases

### Phase 1: Foundation (Week 1)

| File | Description |
|------|-------------|
| `doc.go` | Package documentation |
| `errors.go` | Error definitions |
| `claims.go` | Constants and token types |
| `uri.go` + test | AAuth ID parsing |
| `key.go` + test | Key management, CNF creation |

### Phase 2: HTTP Signatures (Week 2)

| File | Description |
|------|-------------|
| `httpsig/doc.go` | Subpackage documentation |
| `httpsig/components.go` | @method, @target-uri derivation |
| `httpsig/params.go` | Signature-Input header parsing |
| `httpsig/signer.go` + test | Request signing |
| `httpsig/verifier.go` + test | Signature verification |

### Phase 3: Token Types (Week 3)

| File | Description |
|------|-------------|
| `agent_token.go` + test | aa-agent+jwt |
| `auth_token.go` + test | aa-auth+jwt |
| `resource_token.go` + test | aa-resource+jwt |
| `verifier.go` + test | Token verification interface |

### Phase 4: Agent-Side (Week 4)

| File | Description |
|------|-------------|
| `agent_options.go` | AgentOption functions |
| `agent.go` + test | Agent client |
| `transport.go` + test | Auto-signing transport |
| `context.go` | Context utilities |

### Phase 5: Resource-Side (Week 5)

| File | Description |
|------|-------------|
| `challenge.go` + test | WWW-Authenticate generation |
| `resource_options.go` | ResourceOption functions |
| `resource.go` + test | Resource server |
| `middleware.go` + test | Verification middleware |

### Phase 6: Auth Server (Week 6)

| File | Description |
|------|-------------|
| `authserver_options.go` | AuthServerOption functions |
| `exchange.go` + test | Token exchange flows |
| `authserver.go` + test | Authorization server |

### Phase 7: Discovery (Week 7)

| File | Description |
|------|-------------|
| `metadata.go` + test | Metadata types |
| `discovery.go` + test | Discovery client |

### Phase 8: Examples & Docs (Week 8)

| File | Description |
|------|-------------|
| `examples/simple/` | Identity-only flow |
| `examples/resource-managed/` | Resource-managed flow |
| `examples/delegation/` | Delegation chain demo |
| `pidl/*.json` | Protocol diagrams |
| `docs/aauth/` | Documentation |

---

## Dependencies

```go
// go.mod - minimal additions
require (
    github.com/golang-jwt/jwt/v5 v5.3.1  // Already present
)
```

**HTTP Signatures**: Implement internally in `httpsig/` subpackage for full RFC 9421 compliance and minimal external dependencies.

---

## Design Decisions

### 1. CNF Binding

Use embedded JWK in `cnf.jwk` by default (simpler key distribution), with optional `jku` support.

### 2. HTTP Signature Algorithm

Default to ECDSA P-256 (`ecdsa-p256-sha256`) for strong security, compact signatures, and alignment with existing patterns.

### 3. Actor Claim Compatibility

Define compatible `Actor` struct matching idjag pattern for delegation chains.

### 4. Transport Integration

Provide both explicit signing and transparent `http.RoundTripper`:

```go
// Explicit
req, _ := agent.SignedRequest(ctx, "GET", url, nil)

// Transparent
client := &http.Client{Transport: agent.Transport()}
```

### 5. Deferred Authorization

Support 202 responses with polling for async authorization flows.

---

## Security Considerations

1. **Key Management**: Never log private keys; use crypto/rand
2. **Token Validation**: Always verify signatures before trusting claims
3. **CNF Binding**: Validate cnf matches request signer
4. **Replay Protection**: Include nonce; use short token lifetimes
5. **Covered Components**: Sign @method, @target-uri, content-digest, authorization

---

## Testing Strategy

- Unit tests for each file (`*_test.go`)
- Integration tests for complete flows
- Table-driven tests following existing patterns
- Minimum 80% coverage; 90%+ for core types

---

## Verification

After implementation:

```bash
# Build
go build ./aauth/...

# Test
go test -v ./aauth/...

# Lint
golangci-lint run ./aauth/...

# Run examples
go run ./aauth/examples/simple
go run ./aauth/examples/resource-managed
```

---

## References

- [draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol)
- [RFC 9421 - HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421)
- [RFC 7800 - Proof-of-Possession Key (cnf)](https://www.rfc-editor.org/rfc/rfc7800)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [TypeScript SDK](https://github.com/aauth-dev/packages-js)
- [Python Demo](https://github.com/christian-posta/aauth-full-demo)
