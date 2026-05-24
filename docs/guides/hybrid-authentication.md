# Hybrid Authentication Guide

This guide explains how to support multiple authentication protocols simultaneously using the bridge package. This is useful for:

- Organizations with diverse client types (web apps, workloads, AI agents)
- Gradual migration from legacy to modern protocols
- Multi-cloud environments with different identity systems

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    API Gateway / Service                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│   │   ID-JAG    │  │    AIMS     │  │    AAuth    │        │
│   │  Verifier   │  │  Verifier   │  │  Verifier   │        │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
│          │                │                │                │
│          └────────────────┼────────────────┘                │
│                           │                                  │
│              ┌────────────▼────────────┐                    │
│              │  bridge.Identity        │                    │
│              │  (Canonical Format)     │                    │
│              └────────────┬────────────┘                    │
│                           │                                  │
│              ┌────────────▼────────────┐                    │
│              │  Application Handler    │                    │
│              └─────────────────────────┘                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Basic Setup

```go
package main

import (
    "log"
    "net/http"

    "github.com/aistandardsio/agent-protocols/bridge"
)

func main() {
    // Configure verifiers for each protocol you support
    middleware := bridge.MultiProtocolMiddleware(
        bridge.WithIDJAGVerifier(createIDJAGVerifier()),
        bridge.WithWITVerifier(createWITVerifier()),
        bridge.WithAAuthVerifier(createAAuthVerifier()),
    )

    // Your handler receives a unified identity
    handler := middleware(http.HandlerFunc(handleRequest))

    log.Fatal(http.ListenAndServe(":8080", handler))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    identity, ok := bridge.IdentityFromContext(r.Context())
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // Protocol-agnostic business logic
    log.Printf("Request from %s via %s", identity.Subject, identity.Protocol)

    // Optional: protocol-specific handling
    switch identity.Protocol {
    case bridge.ProtocolAAuth:
        if identity.HasDelegation() {
            log.Printf("Acting on behalf of: %s", identity.Actor.Subject)
        }
    case bridge.ProtocolAIMS:
        if identity.HasKeyBinding() {
            log.Printf("Request is key-bound (proof-of-possession)")
        }
    }
}
```

## Client Type Detection

Identify client types based on protocol:

```go
type ClientType string

const (
    ClientTypeWebApp    ClientType = "web_app"
    ClientTypeWorkload  ClientType = "workload"
    ClientTypeAgent     ClientType = "agent"
    ClientTypeUnknown   ClientType = "unknown"
)

func detectClientType(identity *bridge.Identity) ClientType {
    switch identity.Protocol {
    case bridge.ProtocolIDJAG:
        // OAuth clients (web apps, mobile apps, SPAs)
        return ClientTypeWebApp

    case bridge.ProtocolAIMS:
        // Kubernetes workloads, microservices
        return ClientTypeWorkload

    case bridge.ProtocolAAuth:
        // AI agents, automated systems
        return ClientTypeAgent

    default:
        return ClientTypeUnknown
    }
}
```

## Protocol-Specific Requirements

Enforce different requirements per protocol:

```go
func enforceRequirements(identity *bridge.Identity) error {
    switch identity.Protocol {
    case bridge.ProtocolAAuth:
        // Agents must have proof-of-possession
        if !identity.HasKeyBinding() {
            return errors.New("agents require key binding")
        }
        // Agents must have delegation chain
        if !identity.HasDelegation() {
            return errors.New("agents require delegation")
        }

    case bridge.ProtocolAIMS:
        // Workloads must be from trusted domain
        if !strings.HasSuffix(identity.Subject, ".cluster.local") {
            return errors.New("workload not from trusted domain")
        }

    case bridge.ProtocolIDJAG:
        // OAuth tokens must have specific audience
        if !containsAudience(identity.Audience, "https://api.example.com") {
            return errors.New("invalid audience")
        }
    }

    return nil
}
```

## Rate Limiting by Protocol

Apply different rate limits based on client type:

```go
func rateLimitMiddleware(next http.Handler) http.Handler {
    // Different limiters per protocol
    limiters := map[bridge.Protocol]*rate.Limiter{
        bridge.ProtocolIDJAG: rate.NewLimiter(100, 10),  // 100 req/s, burst 10
        bridge.ProtocolAIMS:  rate.NewLimiter(1000, 50), // 1000 req/s, burst 50
        bridge.ProtocolAAuth: rate.NewLimiter(500, 25),  // 500 req/s, burst 25
    }

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        protocol := bridge.ProtocolFromContext(r.Context())
        limiter := limiters[protocol]

        if limiter != nil && !limiter.Allow() {
            http.Error(w, "rate limited", http.StatusTooManyRequests)
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

## Authorization Policies

Implement protocol-aware authorization:

```go
type Permission string

const (
    PermissionRead   Permission = "read"
    PermissionWrite  Permission = "write"
    PermissionAdmin  Permission = "admin"
)

func authorize(identity *bridge.Identity, required Permission) bool {
    switch identity.Protocol {
    case bridge.ProtocolIDJAG:
        // Check OAuth scopes in original claims
        scopes, _ := identity.OriginalClaims["scope"].(string)
        return hasScope(scopes, string(required))

    case bridge.ProtocolAIMS:
        // SPIFFE ID path-based authorization
        // spiffe://domain/ns/namespace/sa/service
        return checkSPIFFEPath(identity.Subject, required)

    case bridge.ProtocolAAuth:
        // Delegation chain authorization
        // Agent inherits permissions from actor
        if identity.HasDelegation() {
            return checkActorPermissions(identity.Actor.Subject, required)
        }
        return false
    }

    return false
}
```

## Audit Logging

Log authentication events with protocol context:

```go
type AuditEvent struct {
    Timestamp   time.Time `json:"timestamp"`
    Protocol    string    `json:"protocol"`
    Subject     string    `json:"subject"`
    Issuer      string    `json:"issuer"`
    ClientType  string    `json:"client_type"`
    Action      string    `json:"action"`
    Resource    string    `json:"resource"`
    Success     bool      `json:"success"`
    Actor       string    `json:"actor,omitempty"`
    KeyBound    bool      `json:"key_bound"`
}

func auditLog(r *http.Request, action string, success bool) {
    identity, _ := bridge.IdentityFromContext(r.Context())

    event := AuditEvent{
        Timestamp:  time.Now(),
        Protocol:   string(identity.Protocol),
        Subject:    identity.Subject,
        Issuer:     identity.Issuer,
        ClientType: string(detectClientType(identity)),
        Action:     action,
        Resource:   r.URL.Path,
        Success:    success,
        KeyBound:   identity.HasKeyBinding(),
    }

    if identity.HasDelegation() {
        event.Actor = identity.Actor.Subject
    }

    logger.Info("audit", slog.Any("event", event))
}
```

## Token Introspection Endpoint

Provide a unified introspection endpoint:

```go
func introspectHandler(w http.ResponseWriter, r *http.Request) {
    token := r.FormValue("token")
    if token == "" {
        http.Error(w, "token required", http.StatusBadRequest)
        return
    }

    // Detect and parse token
    protocol, err := bridge.DetectProtocol(token)
    if err != nil {
        json.NewEncoder(w).Encode(map[string]bool{"active": false})
        return
    }

    // Parse without full verification for introspection
    result, err := bridge.Parse(token)
    if err != nil {
        json.NewEncoder(w).Encode(map[string]bool{"active": false})
        return
    }

    identity := result.Identity

    response := map[string]interface{}{
        "active":     !identity.IsExpired(),
        "protocol":   string(protocol),
        "sub":        identity.Subject,
        "iss":        identity.Issuer,
        "aud":        identity.Audience,
        "iat":        identity.IssuedAt.Unix(),
        "exp":        identity.ExpiresAt.Unix(),
        "key_bound":  identity.HasKeyBinding(),
        "delegated":  identity.HasDelegation(),
    }

    if identity.HasDelegation() {
        response["act"] = map[string]string{
            "sub": identity.Actor.Subject,
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

## Health Check with Protocol Status

Include protocol verifier status in health checks:

```go
type HealthStatus struct {
    Status    string            `json:"status"`
    Protocols map[string]string `json:"protocols"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    status := HealthStatus{
        Status:    "healthy",
        Protocols: make(map[string]string),
    }

    // Check each configured verifier
    if idjagVerifier != nil {
        status.Protocols["id-jag"] = "enabled"
    }
    if witVerifier != nil {
        status.Protocols["aims"] = "enabled"
    }
    if aauthVerifier != nil {
        status.Protocols["aauth"] = "enabled"
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(status)
}
```

## Restricting Protocols

Limit which protocols are accepted for specific endpoints:

```go
// Public API: accept all protocols
publicAPI := bridge.MultiProtocolMiddleware(
    bridge.WithIDJAGVerifier(idjagVerifier),
    bridge.WithWITVerifier(witVerifier),
    bridge.WithAAuthVerifier(aauthVerifier),
)(publicHandler)

// Internal API: workloads only
internalAPI := bridge.MultiProtocolMiddleware(
    bridge.WithWITVerifier(witVerifier),
    bridge.WithAllowedProtocols(bridge.ProtocolAIMS),
)(internalHandler)

// Agent API: agents only with key binding
agentAPI := bridge.MultiProtocolMiddleware(
    bridge.WithAAuthVerifier(aauthVerifier),
    bridge.WithAllowedProtocols(bridge.ProtocolAAuth),
    bridge.WithRequireKeyBinding(),
)(agentHandler)
```

## Best Practices

1. **Use canonical identity** - Write business logic against `bridge.Identity`, not protocol-specific types

2. **Log protocol usage** - Track which protocols are used for migration planning

3. **Apply principle of least privilege** - Different protocols may have different trust levels

4. **Test all paths** - Ensure each protocol path is covered in integration tests

5. **Monitor verifier health** - Alert on verifier failures that would block a protocol

6. **Document protocol requirements** - Make clear which protocols are accepted for each endpoint

## Next Steps

- See [OAuth to Agent Migration](oauth-to-agent-migration.md) for migration strategies
- See [demos/protocol-bridge](../../demos/protocol-bridge/) for working examples
