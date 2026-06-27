// Package agents provides operations for managing SCIM Agent resources.
//
// An Agent represents an AI agent with its own identifier, metadata, and privileges,
// independent of a particular runtime environment or containing application.
//
// # Example Usage
//
//	// Create an agent
//	agent, err := client.Agents().Create(ctx, &agents.CreateRequest{
//	    Name:        "my-ai-assistant",
//	    DisplayName: "My AI Assistant",
//	    AgentType:   "Assistant",
//	    Active:      true,
//	})
//
//	// Get an agent by ID
//	agent, err := client.Agents().Get(ctx, "agent-id")
//
//	// List all agents
//	list, err := client.Agents().List(ctx, &agents.ListOptions{
//	    Filter: "name eq 'my-ai-assistant'",
//	})
//
//	// Update an agent
//	agent, err := client.Agents().Update(ctx, "agent-id", &agents.UpdateRequest{
//	    Active: false,
//	})
//
//	// Delete an agent
//	err := client.Agents().Delete(ctx, "agent-id")
package agents
