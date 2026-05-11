# Zitadel Adapter Examples

The Zitadel adapter includes self-contained examples demonstrating integration with each protocol.

## Running Examples

All examples use embedded mock servers, so no external Zitadel instance is required.

### ID-JAG Example

Demonstrates ID-JAG assertion exchange for access tokens with delegation support.

```bash
go run ./adapters/zitadel/examples/idjag
```

**Output:**

```
=== ID-JAG to Zitadel Token Exchange Demo ===

Step 1: Creating ID-JAG assertion...
  Subject: user:alice@example.com
  Actor: agent:calendar-bot

Step 2: Signing assertion...

Step 3: Exchanging assertion for access token...

Step 4: Verifying access token...
  Verified subject: user:alice@example.com
  Verified actor: agent:calendar-bot

=== Demo completed successfully ===
```

**What it demonstrates:**

- Creating an ID-JAG assertion with actor claim
- Signing the assertion with RSA keys
- Exchanging the assertion via RFC 8693
- Verifying the resulting token

### AIMS Example

Demonstrates AIMS Workload Identity Token verification with HTTP middleware.

```bash
go run ./adapters/zitadel/examples/aims
```

**Output:**

```
=== AIMS WIT Verification with Zitadel Demo ===

Step 1: Creating SPIFFE ID and WIT...
  SPIFFE ID: spiffe://example.com/workload/api-server
  Issuer: https://example.com
  Audiences: [https://api.example.com https://backend.example.com]

Step 2: Signing WIT...

Step 3: Verifying WIT...
  Verified subject: spiffe://example.com/workload/api-server
  Verified audiences: [https://api.example.com https://backend.example.com]

Step 4: Demonstrating middleware usage...
  Response status: 200
  Response body: Authenticated workload: spiffe://example.com/workload/api-server

=== Demo completed successfully ===
```

**What it demonstrates:**

- Creating a SPIFFE ID and WIT
- Signing the WIT with RSA keys
- Verifying WIT using Zitadel's JWKS infrastructure
- Using HTTP middleware for workload authentication

### AAuth Example

Demonstrates AAuth agent authentication with HTTP middleware.

```bash
go run ./adapters/zitadel/examples/aauth
```

**Output:**

```
=== AAuth Agent Authentication with Zitadel Demo ===

Step 1: Creating AAuth agent...
  Agent ID: aauth:calendar-bot@example.com
  Key ID: calendar-bot

Step 2: Generating agent token...

Step 3: Creating Zitadel-style agent token...

Step 4: Verifying agent token...
  Verified subject: aauth:calendar-bot@example.com
  CNF present: yes

Step 5: Demonstrating middleware usage...
  Response status: 200
  Response body: Authenticated agent: aauth:calendar-bot@example.com

=== Demo completed successfully ===
```

**What it demonstrates:**

- Creating an AAuth agent with key pair
- Generating agent tokens with CNF claim
- Verifying agent tokens using Zitadel's JWKS
- Using HTTP middleware for agent authentication

## Example Code Structure

Each example follows a similar structure:

```
adapters/zitadel/examples/
├── idjag/
│   └── main.go      # ID-JAG token exchange demo
├── aims/
│   └── main.go      # AIMS WIT verification demo
└── aauth/
    └── main.go      # AAuth agent authentication demo
```

## Key Patterns

### Mock Server Setup

All examples create a mock Zitadel server for demonstration:

```go
func createMockZitadelServer(privateKey *rsa.PrivateKey, keyID string) *httptest.Server {
    mux := http.NewServeMux()

    // OIDC discovery endpoint
    mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
        config := map[string]string{
            "issuer":         "http://" + r.Host,
            "token_endpoint": "http://" + r.Host + "/oauth/v2/token",
            "jwks_uri":       "http://" + r.Host + "/jwks",
        }
        json.NewEncoder(w).Encode(config)
    })

    // JWKS endpoint
    mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
        // Return JWKS with test public key
    })

    // Token endpoint (for token exchange)
    mux.HandleFunc("/oauth/v2/token", func(w http.ResponseWriter, r *http.Request) {
        // Handle RFC 8693 token exchange
    })

    return httptest.NewServer(mux)
}
```

### Context Extraction

After middleware validation, extract verified tokens from context:

```go
handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // ID-JAG
    assertion, ok := zitadel.IDJAGAssertionFromContext(r.Context())

    // AIMS
    wit, ok := zitadel.AIMSWITFromContext(r.Context())

    // AAuth
    agentToken, ok := zitadel.AAuthTokenFromContext(r.Context())
})
```

## Production Usage

For production deployments:

1. **Replace mock server** with your Zitadel instance URL
2. **Configure client credentials** if required by your Zitadel setup
3. **Set appropriate audiences** for your API endpoints
4. **Use HTTPS** for all endpoints

```go
// Production configuration
exchanger, _ := zitadel.NewTokenExchanger(
    "https://your-instance.zitadel.cloud",
    zitadel.WithClientCredentials(clientID, clientSecret),
)

verifier, _ := zitadel.NewVerifier(
    "https://your-instance.zitadel.cloud",
    zitadel.WithRequiredAudience("https://api.your-domain.com"),
)
```

## Next Steps

- [Getting Started](getting-started.md) - Configuration options
- [API Reference](api-reference.md) - Complete API documentation
