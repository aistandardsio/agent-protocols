# SCIM Agent Extension

!!! warning "EXPERIMENTAL"
    This package implements draft-abbey-scim-agent-extension-00 which is still
    under development. The API may change as the specification evolves.

!!! info "Part of AIStandards.io"
    This implementation is part of the [AIStandards.io](https://aistandards.io)
    initiative tracking emerging AI agent standards. See the
    [SCIM Agent Extension standard page](https://aistandards.io/standards/scim-agent-extension)
    for more information.

## Overview

The SCIM Agent Extension adds two new resource types to SCIM 2.0 for managing
AI agents and agentic applications across organizational domains.

Rather than creating entirely new protocols for agent discovery and management,
this extension leverages the well-established SCIM protocol and existing
implementations to solve agent cross-domain management.

## Resource Types

### Agent

An **Agent** represents an AI agent with its own identifier, metadata, and
privileges, independent of a particular runtime environment or containing
application. Agents are distinct from traditional software workloads due to
varying degrees of unpredictable behavior caused by delegation of control flow
to artificial intelligence models.

**Schema URI**: `urn:ietf:params:scim:schemas:core:2.0:Agent`

**Endpoint**: `/Agents`

Key attributes:

| Attribute | Description |
|-----------|-------------|
| `name` | Unique identifier for the agent (REQUIRED) |
| `displayName` | Human-readable display name |
| `agentType` | Classification type (e.g., "Assistant", "Researcher") |
| `active` | Administrative status |
| `protocols` | Supported communication protocols (A2A, OpenAPI, MCP-Server) |
| `owners` | Users or groups that own this agent |
| `parent` | Parent agent in hierarchy |

### AgenticApplication

An **AgenticApplication** represents a software application that hosts or
provides access to one or more agents. It serves as a container and runtime
environment for agents, managing their authentication, authorization, and
access to resources.

**Schema URI**: `urn:ietf:params:scim:schemas:core:2.0:AgenticApplication`

**Endpoint**: `/AgenticApplications`

Key attributes:

| Attribute | Description |
|-----------|-------------|
| `name` | Unique identifier for the application (REQUIRED) |
| `displayName` | Human-readable display name |
| `applicationUrls` | URLs associated with the application |
| `oAuthConfiguration` | OAuth client configurations |
| `agents` | Agents associated with this application |
| `active` | Administrative status |

## Protocol Communication Types

Agents can declare supported communication protocols via the `protocols` attribute:

| Type | Description |
|------|-------------|
| `A2A` | Agent-to-Agent Protocol |
| `OpenAPI` | OpenAPI/REST specification |
| `MCP-Server` | Model Context Protocol Server |

Each protocol includes a `specificationUrl` pointing to the agent's specific
configuration document for that protocol.

## ServiceProviderConfig Extension

SCIM servers that support the Agent Extension advertise this via the
ServiceProviderConfig endpoint:

```json
{
  "agentExtension": {
    "supported": true,
    "agentsSupported": true,
    "agenticApplicationsSupported": true
  }
}
```

## Relationship to Other Protocols

The SCIM Agent Extension complements authentication protocols like:

- **AAuth**: Agent Authentication using HTTP message signatures
- **ID-JAG**: Identity Assertion JWT Authorization Grant
- **AIMS**: Agent Identity Management System (SPIFFE/WIMSE)

While these protocols handle **authentication** (how agents prove identity),
the SCIM Agent Extension handles **provisioning** (how agents are created,
discovered, and managed in identity systems).

## References

- [AIStandards.io: SCIM Agent Extension](https://aistandards.io/standards/scim-agent-extension)
- [IETF Draft: draft-abbey-scim-agent-extension](https://datatracker.ietf.org/doc/draft-abbey-scim-agent-extension)
- [RFC 7643: SCIM Core Schema](https://datatracker.ietf.org/doc/html/rfc7643)
- [RFC 7644: SCIM Protocol](https://datatracker.ietf.org/doc/html/rfc7644)
