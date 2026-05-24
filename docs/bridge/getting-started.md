# Bridge Getting Started

This guide shows how to use the bridge package for cross-protocol authentication.

## Installation

```bash
go get github.com/aistandardsio/agent-protocols/bridge
```

## Quick Start: Multi-Protocol Gateway

Accept any authentication protocol in your HTTP service:

```go
package main

import (
    "encoding/json"
    "log"
    "net/http"

    "github.com/aistandardsio/agent-protocols/bridge"
)

func main() {
    // Create multi-protocol middleware
    auth := bridge.MultiProtocolMiddleware(
        bridge.WithIDJAGVerifier(idjagVerifier),
        bridge.WithWITVerifier(witVerifier),
        bridge.WithAAuthVerifier(aauthVerifier),
    )

    // Wrap your handler
    http.Handle("/api/", auth(http.HandlerFunc(apiHandler)))

    log.Fatal(http.ListenAndServe(":8080", nil))
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
    // Get canonical identity from context
    identity, ok := bridge.IdentityFromContext(r.Context())
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // Use unified identity fields
    json.NewEncoder(w).Encode(map[string]interface{}{
        "subject":  identity.Subject,
        "issuer":   identity.Issuer,
        "protocol": identity.Protocol,
    })
}
```

## Protocol Detection

Detect which protocol a token uses:

```go
import "github.com/aistandardsio/agent-protocols/bridge"

func detectToken(tokenString string) {
    protocol, err := bridge.DetectProtocol(tokenString)
    if err != nil {
        log.Printf("Invalid token: %v", err)
        return
    }

    switch protocol {
    case bridge.ProtocolIDJAG:
        log.Println("Token is ID-JAG assertion")
    case bridge.ProtocolAIMS:
        log.Println("Token is AIMS WIT")
    case bridge.ProtocolAAuth:
        log.Println("Token is AAuth agent token")
    default:
        log.Println("Unknown protocol")
    }
}

// Convenience functions
if bridge.IsIDJAG(token) {
    // Handle ID-JAG token
}
if bridge.IsWIT(token) {
    // Handle AIMS token
}
if bridge.IsAAuth(token) {
    // Handle AAuth token
}
```

## Token Parsing

Parse a token without verification (for inspection):

```go
result, err := bridge.Parse(tokenString)
if err != nil {
    log.Printf("Parse failed: %v", err)
    return
}

log.Printf("Protocol: %s", result.Protocol)
log.Printf("Subject: %s", result.Identity.Subject)

// Access protocol-specific data
switch result.Protocol {
case bridge.ProtocolIDJAG:
    log.Printf("Client ID: %s", result.IDJAGAssertion.ClientID)
case bridge.ProtocolAIMS:
    log.Printf("SPIFFE ID: %s", result.WIT.Subject)
case bridge.ProtocolAAuth:
    if result.AAuthToken.Actor != nil {
        log.Printf("Acting for: %s", result.AAuthToken.Actor.Subject)
    }
}
```

## Identity Conversion

Convert tokens between protocols:

```go
import (
    "github.com/aistandardsio/agent-protocols/aauth"
    "github.com/aistandardsio/agent-protocols/bridge"
    "github.com/aistandardsio/agent-protocols/idjag"
)

// Start with an ID-JAG assertion
assertion := &idjag.Assertion{
    Issuer:   "https://idp.example.com",
    Subject:  "user@example.com",
    ClientID: "web-client",
    // ...
}

// Convert to canonical identity
identity, err := bridge.FromIDJAG(assertion)
if err != nil {
    log.Fatal(err)
}

// Convert to AAuth agent token
cnf := &aauth.CNF{Kid: "agent-key"}
agentToken, err := identity.ToAAuth(cnf)
if err != nil {
    log.Fatal(err)
}

// Or sign directly
signedToken, err := identity.SignAAuth(cnf, privateKey, "key-id")
```

## Identity Properties

Check identity properties:

```go
identity, _ := bridge.IdentityFromContext(ctx)

// Check expiration
if identity.IsExpired() {
    log.Println("Token expired")
}

// Check for proof-of-possession
if identity.HasKeyBinding() {
    log.Printf("Key ID: %s", identity.KeyBinding.Kid)
}

// Check for delegation
if identity.HasDelegation() {
    log.Printf("Acting on behalf of: %s", identity.Actor.Subject)
}
```

## Middleware Options

Configure the middleware behavior:

```go
middleware := bridge.MultiProtocolMiddleware(
    // Add verifiers
    bridge.WithIDJAGVerifier(idjagVerifier),
    bridge.WithWITVerifier(witVerifier),
    bridge.WithAAuthVerifier(aauthVerifier),

    // Restrict allowed protocols
    bridge.WithAllowedProtocols(
        bridge.ProtocolAAuth,
        bridge.ProtocolAIMS,
    ),

    // Require proof-of-possession
    bridge.WithRequireKeyBinding(),

    // Custom error handler
    bridge.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
        log.Printf("Auth failed: %v", err)
        http.Error(w, "authentication required", http.StatusUnauthorized)
    }),
)
```

## Context Helpers

Extract information from request context:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Get identity
    identity, ok := bridge.IdentityFromContext(r.Context())
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // Get protocol
    protocol := bridge.ProtocolFromContext(r.Context())
    log.Printf("Request via %s protocol", protocol)
}
```

## Example: Protocol-Specific Logic

Handle different protocols differently while using unified identity:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    identity, _ := bridge.IdentityFromContext(r.Context())
    protocol := bridge.ProtocolFromContext(r.Context())

    // Unified identity access
    log.Printf("Request from: %s", identity.Subject)

    // Protocol-specific handling
    switch protocol {
    case bridge.ProtocolAAuth:
        // Agents must have delegation
        if !identity.HasDelegation() {
            http.Error(w, "delegation required", http.StatusForbidden)
            return
        }
        log.Printf("Agent acting for: %s", identity.Actor.Subject)

    case bridge.ProtocolAIMS:
        // Workloads must have key binding
        if !identity.HasKeyBinding() {
            http.Error(w, "key binding required", http.StatusForbidden)
            return
        }

    case bridge.ProtocolIDJAG:
        // Check OAuth client ID
        clientID, _ := identity.OriginalClaims["client_id"].(string)
        log.Printf("OAuth client: %s", clientID)
    }

    // Continue with request
    w.WriteHeader(http.StatusOK)
}
```

## Running the Demo

See the protocol-bridge demo for a complete example:

```bash
go run ./demos/protocol-bridge
```

## Next Steps

- [OAuth to Agent Migration](../guides/oauth-to-agent-migration.md)
- [Hybrid Authentication](../guides/hybrid-authentication.md)
- [Bridge Overview](overview.md)
