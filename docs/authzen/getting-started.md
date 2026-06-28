# Getting Started with AuthZEN

This guide covers installation and basic usage of the AuthZEN package.

## Installation

```bash
go get github.com/aistandardsio/agent-protocols/authzen
```

## Quick Start

### Creating a Client

```go
package main

import (
    "context"
    "log"

    "github.com/aistandardsio/agent-protocols/authzen"
)

func main() {
    // Create AuthZEN client pointing to your PDP
    client := authzen.NewClient("https://pdp.example.com",
        authzen.WithBearerToken("your-api-token"),
    )

    log.Printf("Connected to PDP: %s", client.BaseURL())
}
```

### Checking Agent Access

```go
func checkAgentAccess(client *authzen.Client) error {
    ctx := context.Background()

    // Create subject for the AI agent
    subject := authzen.AgentSubject("code-review-agent",
        authzen.WithWorkloadID("spiffe://example.com/agent/code-review"),
        authzen.WithDelegator("user:alice"),
    )

    // Define the resource
    resource := authzen.NewResource("repository", "acme/backend", nil)

    // Define the action
    action := authzen.NewAction("read", nil)

    // Check if allowed
    allowed, err := client.IsAllowed(ctx, subject, resource, action)
    if err != nil {
        return err
    }

    if allowed {
        log.Println("Access granted")
    } else {
        log.Println("Access denied")
    }

    return nil
}
```

### Full Evaluation Request

For more control over the request and response:

```go
func evaluateRequest(client *authzen.Client) error {
    ctx := context.Background()

    resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
        Subject: authzen.AgentSubject("deployment-agent",
            authzen.WithWorkloadID("spiffe://prod.example.com/agent/deploy"),
            authzen.WithDelegator("user:bob"),
            authzen.WithCapabilities([]string{"deploy", "rollback"}),
            authzen.WithMission("deploy:prod-v2.1.0"),
        ),
        Resource: authzen.NewResource("environment", "production", map[string]any{
            "region": "us-west-2",
            "tier":   "critical",
        }),
        Action: authzen.NewAction("deploy", map[string]any{
            "version":  "2.1.0",
            "strategy": "blue-green",
        }),
        Context: authzen.NewContext().
            WithContextValue("request_id", "req-12345").
            WithContextValue("source_ip", "10.0.0.50"),
    })
    if err != nil {
        return err
    }

    log.Printf("Decision: %s", resp.Decision)
    if resp.Decision.IsAllowed() {
        log.Println("Deployment authorized")
    }

    return nil
}
```

### Batch Evaluation

For evaluating multiple requests efficiently:

```go
func batchEvaluate(client *authzen.Client) error {
    ctx := context.Background()

    subject := authzen.AgentSubject("data-agent")

    resp, err := client.EvaluateBatch(ctx, &authzen.BatchEvaluationRequest{
        Evaluations: []authzen.EvaluationRequest{
            {
                Subject:  subject,
                Resource: authzen.NewResource("table", "users", nil),
                Action:   authzen.NewAction("read", nil),
            },
            {
                Subject:  subject,
                Resource: authzen.NewResource("table", "audit_logs", nil),
                Action:   authzen.NewAction("read", nil),
            },
            {
                Subject:  subject,
                Resource: authzen.NewResource("table", "secrets", nil),
                Action:   authzen.NewAction("read", nil),
            },
        },
    })
    if err != nil {
        return err
    }

    for i, eval := range resp.Evaluations {
        log.Printf("Request %d: %s", i+1, eval.Decision)
    }

    return nil
}
```

## Client Options

### Bearer Token Authentication

```go
client := authzen.NewClient("https://pdp.example.com",
    authzen.WithBearerToken("your-api-token"),
)
```

### Custom HTTP Client

```go
import "net/http"

httpClient := &http.Client{
    Timeout: 10 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns: 100,
    },
}

client := authzen.NewClient("https://pdp.example.com",
    authzen.WithHTTPClient(httpClient),
)
```

### Custom Headers

```go
client := authzen.NewClient("https://pdp.example.com",
    authzen.WithHeader("X-Tenant-ID", "acme-corp"),
    authzen.WithHeader("X-Request-Source", "agent-gateway"),
)
```

### Custom Evaluation Path

```go
client := authzen.NewClient("https://pdp.example.com",
    authzen.WithEvaluationPath("/v2/authorize"),
)
```

## Subject Helpers

### Agent Subject with Full Context

```go
subject := authzen.AgentSubject("my-agent",
    // SPIFFE workload identity
    authzen.WithWorkloadID("spiffe://example.com/ns/prod/agent/my-agent"),

    // Human who delegated authority
    authzen.WithDelegator("user:alice@example.com"),

    // Agent's declared capabilities
    authzen.WithCapabilities([]string{"read", "write", "analyze"}),

    // Current mission/task scope
    authzen.WithMission("data-analysis:report-q4-2024"),
)
```

### Manual Subject Creation

```go
subject := authzen.Subject{
    Type: "service",
    ID:   "backend-api",
    Properties: map[string]any{
        "environment": "production",
        "version":     "3.2.1",
    },
}
```

## Error Handling

```go
import "errors"

resp, err := client.Evaluate(ctx, req)
if err != nil {
    // Check for AuthZEN-specific errors
    var authzErr *authzen.ErrorResponse
    if errors.As(err, &authzErr) {
        switch authzErr.Code {
        case "invalid_request":
            log.Printf("Bad request: %s", authzErr.Description)
        case "unauthorized":
            log.Println("Authentication required")
        case "forbidden":
            log.Println("Insufficient permissions to query PDP")
        default:
            log.Printf("PDP error: %s", authzErr.Error())
        }
        return err
    }

    // Network or other errors
    return fmt.Errorf("evaluation failed: %w", err)
}
```

## Integration with HTTP Middleware

```go
import "net/http"

func AuthZENMiddleware(client *authzen.Client) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()

            // Extract agent identity from request (e.g., from AAuth or ID-JAG)
            agentID := r.Header.Get("X-Agent-ID")
            delegator := r.Header.Get("X-Delegator")

            subject := authzen.AgentSubject(agentID,
                authzen.WithDelegator(delegator),
            )

            resource := authzen.NewResource("api", r.URL.Path, nil)
            action := authzen.NewAction(strings.ToLower(r.Method), nil)

            allowed, err := client.IsAllowed(ctx, subject, resource, action)
            if err != nil {
                http.Error(w, "Authorization check failed", http.StatusInternalServerError)
                return
            }

            if !allowed {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

## Next Steps

- [Overview](overview.md) - Learn about AuthZEN concepts
- [API Reference](https://pkg.go.dev/github.com/aistandardsio/agent-protocols/authzen) - Full Go package documentation
