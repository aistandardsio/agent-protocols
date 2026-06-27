# Pull Request: Add OpenAPI 3.0 Specification

## Target Repository

[macyabbey/draft-abbey-scim-agent-extension](https://github.com/macyabbey/draft-abbey-scim-agent-extension)

---

## PR Title

**feat: add OpenAPI 3.0 specification for SCIM Agent Extension**

---

## PR Description

### Summary

This PR adds an OpenAPI 3.0 specification for the SCIM Agents and Agentic
Applications Extension, enabling automated client generation and API
documentation.

### Changes

- Add `openapi/scim-agent-extension.yaml` - Complete OpenAPI 3.0.3 specification

### OpenAPI Spec Details

The specification includes:

**Endpoints:**

- `GET/POST /Agents` - List and create agents
- `GET/PUT/PATCH/DELETE /Agents/{id}` - Agent CRUD operations
- `GET/POST /AgenticApplications` - List and create agentic applications
- `GET/PUT/PATCH/DELETE /AgenticApplications/{id}` - Application CRUD operations
- `GET /ServiceProviderConfig` - Service provider configuration with agent extension support

**Schema Components:**

- `Agent` - Full agent resource with all attributes from the draft
- `AgentCreate` - Request body for creating/replacing agents
- `AgentListResponse` - SCIM list response for agents
- `AgenticApplication` - Full agentic application resource
- `AgenticApplicationCreate` - Request body for creating/replacing applications
- `AgenticApplicationListResponse` - SCIM list response for applications
- `PatchRequest` / `PatchOperation` - SCIM PATCH operations
- `ServiceProviderConfig` - Including `agentExtension` configuration
- `Error` - SCIM error response
- Supporting types: `Meta`, `Reference`, `Protocol`, `ApplicationURL`, `OAuthConfiguration`, etc.

**Features:**

- Full SCIM 2.0 query parameters (filter, startIndex, count, sortBy, sortOrder, attributes, excludedAttributes)
- Bearer token authentication
- Standard SCIM error responses (400, 401, 403, 404, 409, 500)
- Content type: `application/scim+json`

### Motivation

An OpenAPI specification enables:

1. **Client Generation** - Automated SDK generation for Go, Python, TypeScript, etc.
2. **API Documentation** - Interactive API docs via Swagger UI or Redoc
3. **Validation** - Request/response validation against the schema
4. **Testing** - Contract testing and mock server generation
5. **Interoperability** - Standard format for API description

### Derived From

This specification was created based on the schema definitions in
`draft-abbey-scim-agent-extension.md` (lines 698-1479), specifically:

- Agent Schema JSON (lines 698-1177)
- Agentic Application Schema JSON (lines 1183-1479)

### Usage

Generate clients using tools like:

```bash
# Go (using ogen)
ogen --package api --target ./client openapi/scim-agent-extension.yaml

# Python (using openapi-generator)
openapi-generator generate -i openapi/scim-agent-extension.yaml -g python -o ./python-client

# TypeScript (using openapi-typescript)
npx openapi-typescript openapi/scim-agent-extension.yaml -o ./types.ts
```

### Testing

The specification has been validated by:

1. Successfully generating a Go client using [ogen](https://github.com/ogen-go/ogen)
2. Building and testing the generated client against the schema
3. Verifying all operations match the IETF draft definitions

### Related

This OpenAPI spec is used in the [agent-protocols](https://github.com/aistandardsio/agent-protocols)
Go implementation to generate a type-safe SCIM client.

---

## Checklist

- [x] OpenAPI spec follows OpenAPI 3.0.3 format
- [x] All endpoints from the draft are included
- [x] All schema attributes match the draft definitions
- [x] SCIM standard query parameters included
- [x] SCIM standard error responses included
- [x] Authentication scheme defined
- [x] Spec validated with ogen code generation
- [x] Content type is `application/scim+json`

---

## Files to Add

```
openapi/
├── scim-agent-extension.yaml   # OpenAPI 3.0 specification
└── README.md                    # Usage instructions (optional)
```

---

## Notes for Maintainers

1. The spec follows the schema definitions exactly as written in the draft
2. Some fields use `readOnly: true` where the draft specifies read-only attributes
3. Protocol types are defined as enums: `A2A`, `OpenAPI`, `MCP-Server`
4. Application URL types are defined as enums: `ssoEndpoint`, `loginPage`, `api`, `homepage`
5. Agent relationship types are defined as enums: `owned`, `authorized`, `guest`

If you'd like any adjustments to match your preferred style or organization,
I'm happy to update the PR accordingly.
