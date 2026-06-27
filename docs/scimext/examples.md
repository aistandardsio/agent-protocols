# Examples

This page describes how to run the SCIM Agent Extension examples.

## Prerequisites

Before running the examples, ensure you have:

1. Go 1.21 or later installed
2. Access to a SCIM server that implements the Agent Extension
3. An OAuth bearer token for authentication

## Simple Example

The simple example demonstrates basic CRUD operations for agents and agentic
applications.

### Running the Example

Set environment variables:

```bash
export SCIM_BASE_URL="https://your-scim-server.com/v2"
export SCIM_TOKEN="your-bearer-token"
```

Run the example:

```bash
cd scimext/examples/simple
go run main.go
```

### What It Does

The simple example:

1. Creates an agent with A2A protocol support
2. Lists all agents
3. Creates an agentic application with OAuth configuration
4. Lists all applications
5. Retrieves the created agent by ID
6. Cleans up by deleting the created resources

### Expected Output

```
Creating agent...
Created agent: example-assistant (ID: abc123)

Listing agents...
Found 1 agents:
  - example-assistant (ID: abc123, Type: Assistant, Active: true)

Creating agentic application...
Created application: example-platform (ID: def456)

Listing agentic applications...
Found 1 applications:
  - example-platform (ID: def456, Active: true)

Getting agent abc123...
Agent details:
  Name: example-assistant
  Display Name: Example AI Assistant
  Type: Assistant
  Active: true
  Protocols: 1

Deleting agent abc123...
Agent deleted successfully

Deleting application def456...
Application deleted successfully

Done!
```

## Example: Filtering Agents

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/aistandardsio/agent-protocols/scimext"
    "github.com/aistandardsio/agent-protocols/scimext/agents"
)

func main() {
    client, _ := scimext.NewClient(
        scimext.WithBaseURL(os.Getenv("SCIM_BASE_URL")),
        scimext.WithBearerToken(os.Getenv("SCIM_TOKEN")),
    )

    ctx := context.Background()

    // Filter by agent type
    assistants, err := client.Agents().List(ctx, &agents.ListOptions{
        Filter: "agentType eq 'Assistant'",
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d assistants\n", assistants.TotalResults)

    // Filter by name
    specific, err := client.Agents().List(ctx, &agents.ListOptions{
        Filter: "name eq 'my-agent'",
    })
    if err != nil {
        log.Fatal(err)
    }

    if len(specific.Resources) > 0 {
        fmt.Printf("Found agent: %s\n", specific.Resources[0].Name)
    }
}
```

## Example: Creating an Agent with Protocols

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/aistandardsio/agent-protocols/scimext"
    "github.com/aistandardsio/agent-protocols/scimext/agents"
)

func main() {
    client, _ := scimext.NewClient(
        scimext.WithBaseURL(os.Getenv("SCIM_BASE_URL")),
        scimext.WithBearerToken(os.Getenv("SCIM_TOKEN")),
    )

    ctx := context.Background()

    agent, err := client.Agents().Create(ctx, &agents.CreateRequest{
        Name:        "multi-protocol-agent",
        DisplayName: "Multi-Protocol Agent",
        AgentType:   "Assistant",
        Active:      true,
        Protocols: []agents.Protocol{
            {
                Type:             "A2A",
                SpecificationURL: "https://example.com/.well-known/agent-card.json",
            },
            {
                Type:             "OpenAPI",
                SpecificationURL: "https://example.com/openapi.yaml",
            },
            {
                Type:             "MCP-Server",
                SpecificationURL: "https://example.com/mcp-manifest.json",
            },
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Created agent with %d protocols", len(agent.Protocols))
}
```

## Example: Application with OAuth Configuration

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/aistandardsio/agent-protocols/scimext"
    "github.com/aistandardsio/agent-protocols/scimext/applications"
)

func main() {
    client, _ := scimext.NewClient(
        scimext.WithBaseURL(os.Getenv("SCIM_BASE_URL")),
        scimext.WithBearerToken(os.Getenv("SCIM_TOKEN")),
    )

    ctx := context.Background()

    app, err := client.Applications().Create(ctx, &applications.CreateRequest{
        Name:        "enterprise-ai-platform",
        DisplayName: "Enterprise AI Platform",
        Description: "Enterprise platform for AI agents",
        Active:      true,
        ApplicationURLs: []applications.ApplicationURL{
            {
                Type:        "homepage",
                Primary:     true,
                Value:       "https://ai.enterprise.com",
                Description: "Main platform website",
            },
            {
                Type:        "api",
                Value:       "https://api.ai.enterprise.com/v1",
                Description: "REST API endpoint",
            },
            {
                Type:        "ssoEndpoint",
                Value:       "https://sso.enterprise.com/saml",
                Description: "SAML SSO endpoint",
            },
        },
        OAuthConfigurations: []applications.OAuthConfiguration{
            {
                ClientID:    "prod-client-id",
                Description: "Production OAuth client",
                AudienceURI: "https://api.ai.enterprise.com",
                IssuerURI:   "https://idp.enterprise.com",
                RedirectURIs: []string{
                    "https://ai.enterprise.com/oauth/callback",
                    "https://ai.enterprise.com/auth/complete",
                },
            },
        },
        ExternalIdentifiers: []applications.ExternalIdentifier{
            {
                Type:   "ssoTenantId",
                Value:  "tenant-12345",
                System: "https://idp.enterprise.com",
            },
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Created application: %s", app.Name)
    log.Printf("OAuth clients: %d", len(app.OAuthConfigurations))
}
```

## Testing Without a Server

For local development and testing without a real SCIM server, you can use
the ogen-generated server handler to create a mock implementation:

```go
import "github.com/aistandardsio/agent-protocols/scimext/internal/api"

// Implement api.Handler interface for testing
type MockHandler struct {
    api.UnimplementedHandler
    agents map[string]*api.Agent
}

func (h *MockHandler) CreateAgent(
    ctx context.Context,
    req *api.AgentCreate,
) (api.CreateAgentRes, error) {
    // Implement mock behavior...
}
```

## Next Steps

- Check the [API Reference](api-reference.md) for complete method documentation
- Review the [Overview](overview.md) for protocol details
- See [Getting Started](getting-started.md) for installation instructions
