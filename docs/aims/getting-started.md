# Getting Started with AIMS

This guide walks you through using the AIMS package for AI agent authentication.

## Installation

```bash
go get github.com/grokify/agent-protocols
```

## Creating a SPIFFE ID

SPIFFE IDs are the canonical identifier for workloads in AIMS:

```go
package main

import (
    "fmt"
    "github.com/grokify/agent-protocols/aims"
)

func main() {
    // Create a SPIFFE ID from components
    spiffeID, err := aims.NewSPIFFEID("example.com", "/agent/calendar-bot")
    if err != nil {
        panic(err)
    }

    fmt.Println("SPIFFE ID:", spiffeID.String())
    // Output: spiffe://example.com/agent/calendar-bot

    // Parse an existing SPIFFE ID
    parsed, err := aims.ParseSPIFFEID("spiffe://prod.example.com/workload/api")
    if err != nil {
        panic(err)
    }

    fmt.Println("Trust Domain:", parsed.TrustDomain) // prod.example.com
    fmt.Println("Path:", parsed.Path)                // /workload/api
    fmt.Println("Is Agent:", parsed.IsAgent())      // false
    fmt.Println("Is Workload:", parsed.IsWorkload()) // true
}
```

## Creating a Workload Identity Token (WIT)

WITs are JWTs that represent workload identity:

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "fmt"
    "time"

    "github.com/grokify/agent-protocols/aims"
)

func main() {
    // Create SPIFFE ID
    spiffeID, _ := aims.NewSPIFFEID("example.com", "/agent/calendar-bot")

    // Create WIT
    wit := aims.NewWIT(
        spiffeID,
        []string{"https://api.example.com"},
        1*time.Hour,
        aims.WithWITJTI(aims.GenerateJTI()),
        aims.WithWITCNF(&aims.CNF{Kid: "key-1"}),
    )

    // Generate signing key
    privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

    // Sign the WIT
    signedWIT, err := wit.Sign(privateKey, "key-1")
    if err != nil {
        panic(err)
    }

    fmt.Println("Signed WIT:", signedWIT)
}
```

## Creating a WIMSE Proof Token (WPT)

WPTs bind authentication to specific HTTP requests:

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "net/http"

    "github.com/grokify/agent-protocols/aims"
)

func main() {
    spiffeID, _ := aims.NewSPIFFEID("example.com", "/agent/calendar-bot")

    // Create WPT for a specific request
    req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/events", nil)
    wpt := aims.NewWPTForRequest(
        spiffeID.String(),
        "https://api.example.com",
        req,
    )

    // Sign and bind to request
    privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    err := wpt.BindToRequest(req, privateKey, "key-1")
    if err != nil {
        panic(err)
    }

    // The request now has the WPT in the Workload-Identity-Token header
}
```

## Creating an Agent Identity

Combine SPIFFE ID, credentials, and attestation:

```go
package main

import (
    "fmt"
    "time"

    "github.com/grokify/agent-protocols/aims"
)

func main() {
    spiffeID, _ := aims.NewSPIFFEID("example.com", "/agent/calendar-bot")

    // Create credential (JWT-SVID in this case)
    credential := aims.NewJWTSVID(
        "signed-jwt-token",
        spiffeID,
        time.Now().Add(1*time.Hour),
    )

    // Create attestation
    attestation := aims.NewAttestationWithOptions(
        aims.AttestationKubernetes,
        []byte("attestation-evidence"),
        aims.WithAttribute(aims.AttrNamespace, "production"),
        aims.WithAttribute(aims.AttrServiceAccount, "calendar-bot"),
    )

    // Create agent identity
    identity := aims.NewAgentIdentity(
        spiffeID,
        credential,
        aims.WithAttestation(attestation),
        aims.WithMetadata("version", "1.0.0"),
    )

    fmt.Println("Is Valid:", identity.IsValid())
    fmt.Println("Expires At:", identity.ExpiresAt())
}
```

## Running the Examples

### Simple Example

Demonstrates basic SPIFFE ID, WIT, and WPT creation:

```bash
go run ./aims/examples/simple
```

### mTLS Example

Demonstrates X.509 SVID authentication with mTLS:

```bash
go run ./aims/examples/mtls
```

## Next Steps

- [Examples](examples.md) - Detailed walkthrough of the example applications
- [API Reference](https://pkg.go.dev/github.com/grokify/agent-protocols/aims) - Complete Go package documentation
