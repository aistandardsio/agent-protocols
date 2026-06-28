// Package authzen implements the AuthZEN Authorization API
// based on the OpenID AuthZEN specification.
//
// AuthZEN defines a standard API for communication between
// Policy Enforcement Points (PEPs) and Policy Decision Points (PDPs),
// enabling fine-grained authorization decisions.
//
// # EXPERIMENTAL
//
// This package implements a draft specification that is subject to change.
// The API may change in backwards-incompatible ways as the specification evolves.
//
// # Protocol Overview
//
// AuthZEN provides a REST API for authorization decisions:
//   - Evaluation API: Single access decision requests
//   - Batch Evaluation: Multiple decisions in one request
//   - Subject/Resource/Action model with extensible properties
//
// Basic flow:
//  1. PEP constructs evaluation request with subject, resource, action, context
//  2. PEP sends request to PDP via AuthZEN API
//  3. PDP evaluates policies (Cedar, OpenFGA, OPA, etc.)
//  4. PDP returns decision (PERMIT, DENY, INDETERMINATE)
//  5. PEP enforces the decision
//
// # Agent Integration
//
// For AI agents, the subject typically includes:
//   - Agent identity (SPIFFE ID, agent ID)
//   - Delegating user (from ID-JAG "act" claim)
//   - Mission scope (from AAuth)
//
// Example evaluation request for an agent:
//
//	{
//	  "subject": {
//	    "type": "agent",
//	    "id": "code-review-agent",
//	    "properties": {
//	      "workload_id": "spiffe://example.com/agent/code-review",
//	      "delegator": "user:alice",
//	      "capabilities": ["code-review", "security-scan"]
//	    }
//	  },
//	  "resource": {
//	    "type": "repository",
//	    "id": "acme/backend",
//	    "properties": {
//	      "visibility": "private"
//	    }
//	  },
//	  "action": {
//	    "name": "comment",
//	    "properties": {
//	      "pr_number": 123
//	    }
//	  },
//	  "context": {
//	    "time": "2024-01-15T10:30:00Z",
//	    "mission": "code-review:pr-123"
//	  }
//	}
//
// # References
//
//   - OpenID AuthZEN: https://openid.net/specs/openid-authzen-authorization-api-1_0.html
//   - Cedar: https://www.cedarpolicy.com/
//   - OpenFGA: https://openfga.dev/
package authzen
