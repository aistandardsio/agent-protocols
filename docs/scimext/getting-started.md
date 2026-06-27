# Getting Started

This guide walks you through setting up and using the SCIM Agent Extension
client.

!!! tip "More Resources"
    Visit [AIStandards.io](https://aistandards.io/standards/scim-agent-extension)
    for additional resources, related standards, and community implementations.

## Installation

Add the package to your Go project:

```bash
go get github.com/aistandardsio/agent-protocols/scimext
```

## Creating a Client

The client uses functional options for configuration:

```go
package main

import (
    "github.com/aistandardsio/agent-protocols/scimext"
)

func main() {
    client, err := scimext.NewClient(
        scimext.WithBaseURL("https://scim.example.com/v2"),
        scimext.WithBearerToken("your-oauth-token"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Use the client...
}
```

### Configuration Options

| Option | Description |
|--------|-------------|
| `WithBaseURL(url)` | Set the SCIM server base URL |
| `WithBearerToken(token)` | Set the OAuth bearer token for authentication |
| `WithHTTPClient(client)` | Use a custom HTTP client |
| `WithTimeout(duration)` | Set the request timeout |

## Creating an Agent

```go
import (
    "context"
    "github.com/aistandardsio/agent-protocols/scimext"
    "github.com/aistandardsio/agent-protocols/scimext/agents"
)

ctx := context.Background()

agent, err := client.Agents().Create(ctx, &agents.CreateRequest{
    Name:        "my-ai-assistant",
    DisplayName: "My AI Assistant",
    Description: "An AI assistant for customer support",
    AgentType:   "Assistant",
    Active:      true,
    Protocols: []agents.Protocol{
        {
            Type:             "A2A",
            SpecificationURL: "https://example.com/agents/my-assistant/.well-known/agent-card.json",
        },
    },
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Created agent: %s (ID: %s)\n", agent.Name, agent.ID)
```

## Listing Agents

```go
// List all agents
list, err := client.Agents().List(ctx, nil)
if err != nil {
    log.Fatal(err)
}

for _, agent := range list.Resources {
    fmt.Printf("Agent: %s (%s)\n", agent.Name, agent.ID)
}

// List with filtering
list, err := client.Agents().List(ctx, &agents.ListOptions{
    Filter:    "agentType eq 'Assistant'",
    Count:     10,
    SortBy:    "name",
    SortOrder: "ascending",
})
```

## Getting an Agent by ID

```go
agent, err := client.Agents().Get(ctx, "agent-id-here")
if err != nil {
    if scimext.IsNotFound(err) {
        fmt.Println("Agent not found")
        return
    }
    log.Fatal(err)
}

fmt.Printf("Agent: %s\n", agent.Name)
fmt.Printf("Active: %t\n", agent.Active)
fmt.Printf("Protocols: %d\n", len(agent.Protocols))
```

## Updating an Agent

```go
// Replace the entire agent
updated, err := client.Agents().Replace(ctx, agent.ID, &agents.CreateRequest{
    Name:        agent.Name,
    DisplayName: "Updated Display Name",
    Active:      false,
})
if err != nil {
    log.Fatal(err)
}
```

## Deleting an Agent

```go
err := client.Agents().Delete(ctx, "agent-id-here")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Agent deleted")
```

## Working with Agentic Applications

The Applications service works similarly to the Agents service:

```go
import "github.com/aistandardsio/agent-protocols/scimext/applications"

// Create an application
app, err := client.Applications().Create(ctx, &applications.CreateRequest{
    Name:        "ai-platform",
    DisplayName: "AI Platform",
    Active:      true,
    ApplicationURLs: []applications.ApplicationURL{
        {Type: "homepage", Primary: true, Value: "https://ai.example.com"},
        {Type: "api", Value: "https://api.ai.example.com"},
    },
    OAuthConfigurations: []applications.OAuthConfiguration{
        {
            ClientID:     "oauth-client-id",
            AudienceURI:  "https://api.ai.example.com",
            IssuerURI:    "https://idp.example.com",
            RedirectURIs: []string{"https://ai.example.com/callback"},
        },
    },
})

// List applications
apps, err := client.Applications().List(ctx, nil)

// Get by ID
app, err := client.Applications().Get(ctx, "app-id")

// Delete
err := client.Applications().Delete(ctx, "app-id")
```

## Error Handling

The client provides helper functions for common error conditions:

```go
agent, err := client.Agents().Get(ctx, "nonexistent-id")
if err != nil {
    switch {
    case scimext.IsNotFound(err):
        fmt.Println("Agent not found")
    case scimext.IsUnauthorized(err):
        fmt.Println("Authentication required")
    case scimext.IsForbidden(err):
        fmt.Println("Access denied")
    case scimext.IsBadRequest(err):
        fmt.Println("Invalid request")
    default:
        log.Fatal(err)
    }
}
```

## Next Steps

- See the [Examples](examples.md) page for runnable demos
- Check the [API Reference](api-reference.md) for complete documentation
- Review the [Overview](overview.md) for protocol details
