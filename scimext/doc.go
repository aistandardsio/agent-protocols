// Package scimext provides a Go client for the SCIM Agent Extension API.
//
// EXPERIMENTAL: This package implements draft-abbey-scim-agent-extension-00
// which is still under development. The API may change as the specification evolves.
//
// # Overview
//
// The SCIM Agent Extension adds two new resource types to SCIM 2.0:
//
//   - Agent: Represents AI agents with their own identity, metadata, and privileges
//   - AgenticApplication: Represents applications that host or provide access to agents
//
// This extension enables identity providers and service providers to manage agents
// using the well-established SCIM protocol, rather than requiring adoption of
// entirely new agent discovery and management protocols.
//
// # Key Components
//
//   - Client: Main entry point for interacting with SCIM servers
//   - agents.Service: Operations on Agent resources (/Agents endpoint)
//   - applications.Service: Operations on AgenticApplication resources (/AgenticApplications endpoint)
//
// # Example Usage
//
//	client, err := scimext.NewClient(
//	    scimext.WithBaseURL("https://scim.example.com/v2"),
//	    scimext.WithBearerToken(os.Getenv("SCIM_TOKEN")),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create an agent
//	agent, err := client.Agents().Create(ctx, &agents.CreateRequest{
//	    Name:        "my-ai-assistant",
//	    DisplayName: "My AI Assistant",
//	    AgentType:   "Assistant",
//	    Active:      true,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Created agent: %s\n", agent.ID)
//
//	// List all agents
//	list, err := client.Agents().List(ctx, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, a := range list.Resources {
//	    fmt.Printf("Agent: %s (%s)\n", a.Name, a.ID)
//	}
//
// # References
//
//   - AIStandards.io: https://aistandards.io/standards/scim-agent-extension
//   - IETF Draft: https://datatracker.ietf.org/doc/draft-abbey-scim-agent-extension
//   - RFC 7643: SCIM Core Schema
//   - RFC 7644: SCIM Protocol
package scimext
