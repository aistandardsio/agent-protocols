// Package a2a implements the Agent-to-Agent (A2A) Protocol
// for agent discovery, authentication, and task delegation.
//
// A2A enables AI agents to discover other agents, negotiate capabilities,
// and delegate tasks while maintaining accountability through delegation chains.
//
// # EXPERIMENTAL
//
// This package implements a draft specification that is subject to change.
// The API may change in backwards-incompatible ways as the specification evolves.
//
// # Protocol Overview
//
// A2A provides three main capabilities:
//   - Discovery: Agents publish Agent Cards at well-known endpoints
//   - Authentication: Agents authenticate using existing OAuth/SPIFFE infrastructure
//   - Delegation: Agents can delegate tasks with constrained scopes
//
// # Agent Cards
//
// Agents publish their capabilities via Agent Cards at /.well-known/agent.json:
//
//	{
//	  "id": "code-review-agent",
//	  "name": "Code Review Agent",
//	  "version": "1.0.0",
//	  "capabilities": [
//	    {
//	      "id": "review-pr",
//	      "description": "Review pull request for issues",
//	      "input_schema": {...},
//	      "output_schema": {...}
//	    }
//	  ],
//	  "authentication": {
//	    "type": "bearer",
//	    "token_endpoint": "https://auth.example.com/token"
//	  },
//	  "endpoints": {
//	    "invoke": "https://agent.example.com/invoke",
//	    "status": "https://agent.example.com/status/{task_id}"
//	  }
//	}
//
// # Task Delegation
//
// When an orchestrator delegates to a specialist:
//  1. Orchestrator discovers specialist via Agent Card
//  2. Orchestrator requests delegation token from auth server
//  3. Delegation token contains full actor chain: user -> orchestrator -> specialist
//  4. Specialist uses delegation token to access resources
//  5. Resource server logs complete delegation chain for audit
//
// # References
//
//   - A2A Protocol: https://github.com/a2a-protocol/a2a
//   - Linux Foundation AI: https://lfaidata.foundation/
package a2a
