# OAuth to Agent Protocol Migration Guide

This guide explains how to migrate from traditional OAuth 2.0 authentication to agent-native protocols (ID-JAG, AIMS, AAuth) using the bridge package.

## Why Migrate?

Traditional OAuth 2.0 works well for human-driven applications but has limitations for AI agent scenarios:

| Aspect | OAuth 2.0 | Agent Protocols |
|--------|-----------|-----------------|
| **Identity Model** | User-centric | Agent-centric |
| **Delegation** | Limited (on-behalf-of) | Native delegation chains |
| **Request Binding** | None | Proof-of-possession |
| **Workload Identity** | Bolt-on | Native (AIMS/SPIFFE) |

## Migration Strategies

### Strategy 1: Gradual Migration via Bridge

Use the bridge package to accept both OAuth tokens (via ID-JAG) and agent tokens simultaneously.

```go
package main

import (
    "net/http"

    "github.com/aistandardsio/agent-protocols/bridge"
)

func main() {
    // Create multi-protocol middleware
    // ID-JAG accepts OAuth JWT assertions
    // AAuth accepts native agent tokens
    middleware := bridge.MultiProtocolMiddleware(
        bridge.WithIDJAGVerifier(idjagVerifier),
        bridge.WithAAuthVerifier(aauthVerifier),
    )

    // Protected handler works with canonical identity
    handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        identity, _ := bridge.IdentityFromContext(r.Context())

        // Same code handles both OAuth and agent clients
        log.Printf("Request from: %s (via %s)", identity.Subject, identity.Protocol)
    }))

    http.ListenAndServe(":8080", handler)
}
```

### Strategy 2: Token Exchange at Gateway

Convert OAuth tokens to agent tokens at the API gateway level.

```go
func tokenExchangeHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Verify incoming OAuth token
    oauthToken := extractBearerToken(r)
    claims, err := verifyOAuthToken(oauthToken)
    if err != nil {
        http.Error(w, "invalid token", http.StatusUnauthorized)
        return
    }

    // 2. Convert to canonical identity
    identity := &bridge.Identity{
        Protocol:  bridge.ProtocolIDJAG,
        Issuer:    claims.Issuer,
        Subject:   claims.Subject,
        Audience:  claims.Audience,
        IssuedAt:  claims.IssuedAt,
        ExpiresAt: claims.ExpiresAt,
    }

    // 3. Issue agent token for downstream services
    cnf := &aauth.CNF{Kid: "gateway-key"}
    agentToken, err := identity.SignAAuth(cnf, gatewayKey, "gateway-key-1")
    if err != nil {
        http.Error(w, "token exchange failed", http.StatusInternalServerError)
        return
    }

    // 4. Return agent token to client
    json.NewEncoder(w).Encode(map[string]string{
        "access_token": agentToken,
        "token_type":   "Bearer",
    })
}
```

### Strategy 3: Parallel Systems

Run OAuth and agent authentication in parallel during transition.

```go
// OAuth endpoint (existing)
http.Handle("/oauth/token", oauthTokenHandler)

// Agent endpoint (new)
http.Handle("/agent/token", agentTokenHandler)

// Protected resources accept both
http.Handle("/api/", bridge.MultiProtocolMiddleware(
    bridge.WithIDJAGVerifier(idjagVerifier),  // OAuth via ID-JAG
    bridge.WithAAuthVerifier(aauthVerifier),   // Native agents
)(apiHandler))
```

## Migration Steps

### Phase 1: Add Bridge Layer

1. Add the bridge package to your project:
   ```bash
   go get github.com/aistandardsio/agent-protocols/bridge
   ```

2. Wrap existing handlers with multi-protocol middleware
3. Update handler code to use `bridge.IdentityFromContext()`

### Phase 2: Enable Agent Clients

1. Register agent clients with your identity provider
2. Issue agent credentials (keys, certificates)
3. Update client SDKs to use agent protocols

### Phase 3: Migrate Clients

1. Start with internal/trusted agents
2. Monitor protocol usage via `bridge.ProtocolFromContext()`
3. Gradually migrate external clients

### Phase 4: Deprecate OAuth (Optional)

1. Set deadline for OAuth deprecation
2. Restrict OAuth to legacy clients only:
   ```go
   bridge.WithAllowedProtocols(bridge.ProtocolAAuth, bridge.ProtocolAIMS)
   ```
3. Remove OAuth verifier after migration complete

## Choosing the Right Protocol

| Scenario | Recommended Protocol |
|----------|---------------------|
| Existing OAuth infrastructure | ID-JAG |
| Kubernetes workloads | AIMS |
| AI agent-to-agent | AAuth |
| Mixed environment | Use bridge with all three |

## Identity Mapping

Map OAuth claims to agent identity fields:

```go
func oauthToIdentity(claims *OAuthClaims) *bridge.Identity {
    return &bridge.Identity{
        Protocol:  bridge.ProtocolIDJAG,
        Issuer:    claims.Issuer,
        Subject:   claims.Subject,
        Audience:  claims.Audience,
        IssuedAt:  time.Unix(claims.IssuedAt, 0),
        ExpiresAt: time.Unix(claims.ExpiresAt, 0),
        JWTID:     claims.JWTID,
        OriginalClaims: map[string]any{
            "client_id": claims.ClientID,
            "scope":     claims.Scope,
        },
    }
}
```

## Preserving Delegation

OAuth's `act` claim maps to agent protocol delegation:

```go
// OAuth token with act claim
{
    "sub": "user@example.com",
    "act": {
        "sub": "service-account@example.com"
    }
}

// Converts to bridge.Identity with Actor
identity := &bridge.Identity{
    Subject: "user@example.com",
    Actor: &bridge.Actor{
        Subject: "service-account@example.com",
    },
}
```

## Monitoring Migration Progress

Track protocol usage to monitor migration:

```go
func metricsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        next.ServeHTTP(w, r)

        protocol := bridge.ProtocolFromContext(r.Context())
        protocolCounter.WithLabelValues(string(protocol)).Inc()
    })
}
```

## Rollback Plan

If issues arise, the bridge layer allows instant rollback:

1. Keep OAuth verifier configured
2. Remove agent verifiers to disable agent auth
3. All clients fall back to OAuth

## Next Steps

- See [Hybrid Authentication](hybrid-authentication.md) for running both systems long-term
- See [demos/protocol-bridge](../../demos/protocol-bridge/) for working examples
