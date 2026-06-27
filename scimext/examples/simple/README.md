# SCIM Agent Extension - Simple Example

This example demonstrates basic usage of the SCIM Agent Extension client for
managing AI agents and agentic applications.

## Overview

The example shows how to:

- Create a SCIM client with bearer token authentication
- Create, list, get, and delete Agent resources
- Create, list, and delete AgenticApplication resources

## Prerequisites

- A SCIM server that implements the Agent Extension (draft-abbey-scim-agent-extension)
- An OAuth/bearer token for authentication

## Running the Example

Set environment variables:

```bash
export SCIM_BASE_URL="https://your-scim-server.com/v2"
export SCIM_TOKEN="your-bearer-token"
```

Run the example:

```bash
go run main.go
```

## Expected Output

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

## References

- [AIStandards.io: SCIM Agent Extension](https://aistandards.io/standards/scim-agent-extension)
- [SCIM Agent Extension Draft](https://datatracker.ietf.org/doc/draft-abbey-scim-agent-extension)
- [RFC 7643 - SCIM Core Schema](https://datatracker.ietf.org/doc/html/rfc7643)
- [RFC 7644 - SCIM Protocol](https://datatracker.ietf.org/doc/html/rfc7644)
