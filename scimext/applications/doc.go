// Package applications provides operations for managing SCIM AgenticApplication resources.
//
// An AgenticApplication represents a software application that hosts or provides
// access to one or more agents. It serves as a container and runtime environment
// for agents, managing their authentication, authorization, and access to resources.
//
// # Example Usage
//
//	// Create an agentic application
//	app, err := client.Applications().Create(ctx, &applications.CreateRequest{
//	    Name:        "ai-assistant-platform",
//	    DisplayName: "AI Assistant Platform",
//	    Description: "Platform hosting customer-facing AI assistants",
//	    Active:      true,
//	})
//
//	// Get an application by ID
//	app, err := client.Applications().Get(ctx, "app-id")
//
//	// List all applications
//	list, err := client.Applications().List(ctx, &applications.ListOptions{
//	    Filter: "name eq 'ai-assistant-platform'",
//	})
//
//	// Delete an application
//	err := client.Applications().Delete(ctx, "app-id")
package applications
