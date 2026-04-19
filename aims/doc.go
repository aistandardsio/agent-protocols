// Package aims implements the Agent Identity Management System (AIMS) framework
// based on draft-klrc-aiagent-auth-00.
//
// AIMS provides a comprehensive framework for AI agent authentication by composing
// multiple identity and security standards:
//   - SPIFFE (Secure Production Identity Framework For Everyone) for workload identity
//   - WIMSE (Workload Identity in Multi-System Environments) for token-based auth
//   - OAuth 2.0 for authorization delegation
//
// # EXPERIMENTAL
//
// This package implements a draft specification that is subject to change.
// The API may change in backwards-incompatible ways as the specification evolves.
//
// # Framework Overview
//
// Unlike specific protocols (like ID-JAG), AIMS is a layered framework that defines
// nine architectural layers for agent identity management:
//
//  1. Identifiers - SPIFFE IDs as canonical workload identifiers
//  2. Credentials - X.509 SVIDs, JWT-SVIDs, WITs
//  3. Attestation - TPM, SGX, SEV-SNP, cloud attestation
//  4. Provisioning - SPIRE, cloud-native credential issuance
//  5. Authentication - mTLS, WIT/WPT token flows
//  6. Authorization - Policy-based access control
//  7. Monitoring - Audit logging and telemetry
//  8. Policy - Centralized policy management
//  9. Compliance - Regulatory and audit requirements
//
// # Key Components
//
// SPIFFE ID is the canonical identifier format:
//
//	spiffe://trust-domain/path
//
// Workload Identity Token (WIT) is a JWT representing workload identity:
//
//	{
//	  "iss": "https://spire.example.com",
//	  "sub": "spiffe://example.com/agent/calendar-bot",
//	  "aud": ["https://api.example.com"],
//	  "exp": 1234567890,
//	  "cnf": { "jwk": {...} }
//	}
//
// WIMSE Proof Token (WPT) binds authentication to specific requests:
//
//	{
//	  "iss": "spiffe://example.com/agent/calendar-bot",
//	  "aud": "https://api.example.com",
//	  "htm": "POST",
//	  "htu": "/api/v1/events"
//	}
//
// # References
//
//   - IETF Draft: https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00
//   - SPIFFE: https://spiffe.io/
//   - WIMSE: https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/
//   - RFC 8693 (Token Exchange): https://tools.ietf.org/html/rfc8693
package aims
