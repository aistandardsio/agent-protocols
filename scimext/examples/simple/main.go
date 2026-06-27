// Package main demonstrates basic usage of the SCIM Agent Extension client.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aistandardsio/agent-protocols/scimext"
	"github.com/aistandardsio/agent-protocols/scimext/agents"
	"github.com/aistandardsio/agent-protocols/scimext/applications"
)

func main() {
	// Get configuration from environment
	baseURL := os.Getenv("SCIM_BASE_URL")
	if baseURL == "" {
		baseURL = "https://scim.example.com/v2"
	}
	token := os.Getenv("SCIM_TOKEN")

	// Create the client
	client, err := scimext.NewClient(
		scimext.WithBaseURL(baseURL),
		scimext.WithBearerToken(token),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	// Example: Create an agent
	fmt.Println("Creating agent...")
	agent, err := client.Agents().Create(ctx, &agents.CreateRequest{
		Name:        "example-assistant",
		DisplayName: "Example AI Assistant",
		Description: "An example AI assistant for demonstration",
		AgentType:   "Assistant",
		Active:      true,
		Protocols: []agents.Protocol{
			{
				Type:             "A2A",
				SpecificationURL: "https://example.com/agents/example-assistant/.well-known/agent-card.json",
			},
		},
	})
	if err != nil {
		log.Printf("Failed to create agent: %v", err)
	} else {
		fmt.Printf("Created agent: %s (ID: %s)\n", agent.Name, agent.ID)
	}

	// Example: List agents
	fmt.Println("\nListing agents...")
	agentList, err := client.Agents().List(ctx, &agents.ListOptions{
		Count: 10,
	})
	if err != nil {
		log.Printf("Failed to list agents: %v", err)
	} else {
		fmt.Printf("Found %d agents:\n", agentList.TotalResults)
		for _, a := range agentList.Resources {
			fmt.Printf("  - %s (ID: %s, Type: %s, Active: %t)\n",
				a.Name, a.ID, a.AgentType, a.Active)
		}
	}

	// Example: Create an agentic application
	fmt.Println("\nCreating agentic application...")
	app, err := client.Applications().Create(ctx, &applications.CreateRequest{
		Name:        "example-platform",
		DisplayName: "Example AI Platform",
		Description: "Platform hosting AI assistants",
		Active:      true,
		ApplicationURLs: []applications.ApplicationURL{
			{
				Type:        "homepage",
				Primary:     true,
				Value:       "https://example.com",
				Description: "Main website",
			},
			{
				Type:        "api",
				Value:       "https://api.example.com/v1",
				Description: "API endpoint",
			},
		},
		OAuthConfigurations: []applications.OAuthConfiguration{
			{
				ClientID:    "example-client-id",
				Description: "Production OAuth client",
				AudienceURI: "https://api.example.com",
				IssuerURI:   "https://idp.example.com",
				RedirectURIs: []string{
					"https://example.com/oauth/callback",
				},
			},
		},
	})
	if err != nil {
		log.Printf("Failed to create application: %v", err)
	} else {
		fmt.Printf("Created application: %s (ID: %s)\n", app.Name, app.ID)
	}

	// Example: List agentic applications
	fmt.Println("\nListing agentic applications...")
	appList, err := client.Applications().List(ctx, &applications.ListOptions{
		Count: 10,
	})
	if err != nil {
		log.Printf("Failed to list applications: %v", err)
	} else {
		fmt.Printf("Found %d applications:\n", appList.TotalResults)
		for _, a := range appList.Resources {
			fmt.Printf("  - %s (ID: %s, Active: %t)\n",
				a.Name, a.ID, a.Active)
		}
	}

	// Example: Get a specific agent (if we created one)
	if agent != nil && agent.ID != "" {
		fmt.Printf("\nGetting agent %s...\n", agent.ID)
		fetchedAgent, err := client.Agents().Get(ctx, agent.ID)
		if err != nil {
			log.Printf("Failed to get agent: %v", err)
		} else {
			fmt.Printf("Agent details:\n")
			fmt.Printf("  Name: %s\n", fetchedAgent.Name)
			fmt.Printf("  Display Name: %s\n", fetchedAgent.DisplayName)
			fmt.Printf("  Type: %s\n", fetchedAgent.AgentType)
			fmt.Printf("  Active: %t\n", fetchedAgent.Active)
			fmt.Printf("  Protocols: %d\n", len(fetchedAgent.Protocols))
		}

		// Example: Delete the agent
		fmt.Printf("\nDeleting agent %s...\n", agent.ID)
		if err := client.Agents().Delete(ctx, agent.ID); err != nil {
			log.Printf("Failed to delete agent: %v", err)
		} else {
			fmt.Println("Agent deleted successfully")
		}
	}

	// Example: Delete the application (if we created one)
	if app != nil && app.ID != "" {
		fmt.Printf("\nDeleting application %s...\n", app.ID)
		if err := client.Applications().Delete(ctx, app.ID); err != nil {
			log.Printf("Failed to delete application: %v", err)
		} else {
			fmt.Println("Application deleted successfully")
		}
	}

	fmt.Println("\nDone!")
}
