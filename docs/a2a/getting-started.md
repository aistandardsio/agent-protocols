# Getting Started with A2A

This guide covers installation and basic usage of the A2A package.

## Installation

```bash
go get github.com/aistandardsio/agent-protocols/a2a
```

## Quick Start

### Discovering an Agent

```go
package main

import (
    "context"
    "log"

    "github.com/aistandardsio/agent-protocols/a2a"
)

func main() {
    ctx := context.Background()

    // Create discovery client
    discovery := a2a.NewDiscoveryClient()

    // Discover agent from base URL
    card, err := discovery.DiscoverAgent(ctx, "https://agent.example.com")
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Found agent: %s", card.Name)
    log.Printf("Description: %s", card.Description)
    log.Printf("Capabilities: %d", len(card.Capabilities))

    for _, cap := range card.Capabilities {
        log.Printf("  - %s: %s", cap.ID, cap.Description)
    }
}
```

### Invoking a Capability

```go
import (
    "context"
    "encoding/json"

    "github.com/aistandardsio/agent-protocols/a2a"
)

func invokeCapability(card *a2a.AgentCard) error {
    ctx := context.Background()

    // Create client for the agent
    client, err := a2a.NewClient(card,
        a2a.WithClientBearerToken("your-access-token"),
    )
    if err != nil {
        return err
    }

    // Invoke a capability
    resp, err := client.Invoke(ctx, &a2a.TaskRequest{
        CapabilityID: "security-scan",
        Input: json.RawMessage(`{
            "repository": "acme/backend",
            "branch": "main"
        }`),
    })
    if err != nil {
        return err
    }

    log.Printf("Task ID: %s", resp.TaskID)
    log.Printf("Status: %s", resp.Status)

    if resp.Status == a2a.TaskStatusCompleted {
        log.Printf("Output: %s", string(resp.Output))
    }

    return nil
}
```

### Waiting for Task Completion

For long-running tasks, use `InvokeAndWait`:

```go
import "time"

func invokeAndWait(client *a2a.Client) error {
    ctx := context.Background()

    // Invoke and poll until completion
    resp, err := client.InvokeAndWait(ctx, &a2a.TaskRequest{
        CapabilityID: "data-analysis",
        Input: json.RawMessage(`{"dataset": "sales-2024"}`),
    }, 5*time.Second) // Poll every 5 seconds
    if err != nil {
        return err
    }

    switch resp.Status {
    case a2a.TaskStatusCompleted:
        log.Printf("Success: %s", string(resp.Output))
    case a2a.TaskStatusFailed:
        log.Printf("Failed: %s", resp.Error)
    case a2a.TaskStatusCanceled:
        log.Println("Task was canceled")
    }

    return nil
}
```

### Polling Task Status Manually

```go
func pollTaskStatus(client *a2a.Client, taskID string) error {
    ctx := context.Background()

    for {
        status, err := client.GetStatus(ctx, taskID)
        if err != nil {
            return err
        }

        log.Printf("Status: %s", status.Status)

        if status.Progress != nil {
            log.Printf("Progress: %d%%", *status.Progress)
        }

        if status.Status.IsTerminal() {
            if status.Status == a2a.TaskStatusCompleted {
                log.Printf("Result: %s", string(status.Output))
            }
            break
        }

        time.Sleep(2 * time.Second)
    }

    return nil
}
```

### Canceling a Task

```go
func cancelTask(client *a2a.Client, taskID string) error {
    ctx := context.Background()

    if err := client.Cancel(ctx, taskID); err != nil {
        return err
    }

    log.Println("Task canceled")
    return nil
}
```

## Client Options

### Bearer Token Authentication

```go
client, _ := a2a.NewClient(card,
    a2a.WithClientBearerToken("your-access-token"),
)
```

### Delegation Token

For agent-to-agent calls with human delegation:

```go
delegationToken := &a2a.DelegationToken{
    Token:     "eyJhbGciOiJSUzI1NiIs...",
    TokenType: "Bearer",
    ExpiresIn: 3600,
    Scope:     "security-scan code-review",
}

client, _ := a2a.NewClient(card,
    a2a.WithDelegationToken(delegationToken),
)
```

### Custom Headers

```go
client, _ := a2a.NewClient(card,
    a2a.WithClientHeader("X-Request-ID", "req-12345"),
    a2a.WithClientHeader("X-Correlation-ID", "corr-67890"),
)
```

### Custom HTTP Client

```go
import "net/http"

httpClient := &http.Client{
    Timeout: 2 * time.Minute,
}

client, _ := a2a.NewClient(card,
    a2a.WithClientHTTPClient(httpClient),
)
```

## Discovery Options

### Custom HTTP Client

```go
discovery := a2a.NewDiscoveryClient(
    a2a.WithDiscoveryHTTPClient(customHTTPClient),
)
```

### Direct URL Discovery

If you have the full URL to the agent card:

```go
card, err := discovery.DiscoverAgentByURL(ctx,
    "https://cdn.example.com/agents/code-review/agent.json")
```

## Working with Capabilities

### Check Before Invoking

```go
func safeInvoke(client *a2a.Client, capabilityID string, input json.RawMessage) error {
    card := client.AgentCard()

    // Verify capability exists
    if !a2a.HasCapability(card, capabilityID) {
        return fmt.Errorf("agent does not support capability: %s", capabilityID)
    }

    // Get capability details
    cap := a2a.GetCapability(card, capabilityID)
    log.Printf("Invoking: %s - %s", cap.Name, cap.Description)

    return client.Invoke(ctx, &a2a.TaskRequest{
        CapabilityID: capabilityID,
        Input:        input,
    })
}
```

### List All Capabilities

```go
func listCapabilities(card *a2a.AgentCard) {
    fmt.Printf("Agent: %s (v%s)\n", card.Name, card.Version)
    fmt.Printf("Description: %s\n\n", card.Description)
    fmt.Println("Capabilities:")

    for _, cap := range card.Capabilities {
        fmt.Printf("  %s\n", cap.ID)
        fmt.Printf("    Name: %s\n", cap.Name)
        fmt.Printf("    Description: %s\n", cap.Description)
        if cap.InputSchema != nil {
            fmt.Printf("    Input Schema: %s\n", string(cap.InputSchema))
        }
        fmt.Println()
    }
}
```

## Authentication Handling

### Check Authentication Requirements

```go
func connectToAgent(card *a2a.AgentCard, token string) (*a2a.Client, error) {
    var opts []a2a.ClientOption

    if a2a.SupportsAuthentication(card, "bearer") {
        if token == "" {
            return nil, fmt.Errorf("agent requires bearer token authentication")
        }
        opts = append(opts, a2a.WithClientBearerToken(token))
    } else if a2a.SupportsAuthentication(card, "none") {
        // No authentication needed
    } else if card.Authentication != nil {
        return nil, fmt.Errorf("unsupported auth type: %s", card.Authentication.Type)
    }

    return a2a.NewClient(card, opts...)
}
```

## Error Handling

```go
import "errors"

func handleErrors(err error) {
    switch {
    case errors.Is(err, a2a.ErrAgentNotFound):
        log.Println("Agent not found - check the URL")

    case errors.Is(err, a2a.ErrCapabilityNotFound):
        log.Println("Capability not supported by this agent")

    case errors.Is(err, a2a.ErrTaskNotFound):
        log.Println("Task does not exist or has expired")

    case errors.Is(err, a2a.ErrUnauthorized):
        log.Println("Authentication failed - check your token")

    case errors.Is(err, a2a.ErrForbidden):
        log.Println("Access denied - insufficient permissions")

    case errors.Is(err, a2a.ErrRateLimited):
        log.Println("Rate limited - retry after backoff")

    default:
        log.Printf("Error: %v", err)
    }
}
```

## Complete Example

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "os"
    "time"

    "github.com/aistandardsio/agent-protocols/a2a"
)

func main() {
    ctx := context.Background()

    // 1. Discover the agent
    discovery := a2a.NewDiscoveryClient()
    card, err := discovery.DiscoverAgent(ctx, "https://code-review.example.com")
    if err != nil {
        log.Fatalf("Discovery failed: %v", err)
    }

    log.Printf("Discovered: %s v%s", card.Name, card.Version)

    // 2. Check capabilities
    if !a2a.HasCapability(card, "security-scan") {
        log.Fatal("Agent doesn't support security scanning")
    }

    // 3. Create authenticated client
    client, err := a2a.NewClient(card,
        a2a.WithClientBearerToken(os.Getenv("AGENT_TOKEN")),
    )
    if err != nil {
        log.Fatalf("Client creation failed: %v", err)
    }

    // 4. Invoke capability and wait for result
    resp, err := client.InvokeAndWait(ctx, &a2a.TaskRequest{
        CapabilityID: "security-scan",
        Input: json.RawMessage(`{
            "repository": "acme/backend",
            "branch": "feature/auth"
        }`),
    }, 10*time.Second)
    if err != nil {
        log.Fatalf("Invocation failed: %v", err)
    }

    // 5. Handle result
    switch resp.Status {
    case a2a.TaskStatusCompleted:
        log.Printf("Scan complete: %s", string(resp.Output))
    case a2a.TaskStatusFailed:
        log.Printf("Scan failed: %s", resp.Error)
    }
}
```

## Next Steps

- [Overview](overview.md) - Learn about A2A concepts
- [API Reference](https://pkg.go.dev/github.com/aistandardsio/agent-protocols/a2a) - Full Go package documentation
