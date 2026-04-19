package aims

import (
	"time"
)

// Layer represents one of the 9 AIMS architectural layers.
// Each layer addresses a specific aspect of agent identity management.
type Layer int

const (
	// LayerIdentifiers defines canonical workload identifiers (SPIFFE IDs).
	LayerIdentifiers Layer = iota + 1
	// LayerCredentials defines credential formats (X.509 SVIDs, JWT-SVIDs, WITs).
	LayerCredentials
	// LayerAttestation defines attestation mechanisms (TPM, SGX, cloud).
	LayerAttestation
	// LayerProvisioning defines credential issuance (SPIRE, cloud-native).
	LayerProvisioning
	// LayerAuthentication defines authentication methods (mTLS, WIT/WPT).
	LayerAuthentication
	// LayerAuthorization defines access control policies.
	LayerAuthorization
	// LayerMonitoring defines audit logging and telemetry.
	LayerMonitoring
	// LayerPolicy defines centralized policy management.
	LayerPolicy
	// LayerCompliance defines regulatory and audit requirements.
	LayerCompliance
)

// String returns the human-readable name of the layer.
func (l Layer) String() string {
	switch l {
	case LayerIdentifiers:
		return "Identifiers"
	case LayerCredentials:
		return "Credentials"
	case LayerAttestation:
		return "Attestation"
	case LayerProvisioning:
		return "Provisioning"
	case LayerAuthentication:
		return "Authentication"
	case LayerAuthorization:
		return "Authorization"
	case LayerMonitoring:
		return "Monitoring"
	case LayerPolicy:
		return "Policy"
	case LayerCompliance:
		return "Compliance"
	default:
		return "Unknown"
	}
}

// Description returns a brief description of the layer's purpose.
func (l Layer) Description() string {
	switch l {
	case LayerIdentifiers:
		return "Canonical workload identifiers using SPIFFE IDs"
	case LayerCredentials:
		return "Credential formats: X.509 SVIDs, JWT-SVIDs, WITs"
	case LayerAttestation:
		return "Attestation mechanisms: TPM, SGX, SEV-SNP, cloud attestation"
	case LayerProvisioning:
		return "Credential issuance via SPIRE or cloud-native systems"
	case LayerAuthentication:
		return "Authentication methods: mTLS, WIT/WPT token flows"
	case LayerAuthorization:
		return "Policy-based access control"
	case LayerMonitoring:
		return "Audit logging and telemetry"
	case LayerPolicy:
		return "Centralized policy management"
	case LayerCompliance:
		return "Regulatory and audit requirements"
	default:
		return "Unknown layer"
	}
}

// AllLayers returns all 9 AIMS layers in order.
func AllLayers() []Layer {
	return []Layer{
		LayerIdentifiers,
		LayerCredentials,
		LayerAttestation,
		LayerProvisioning,
		LayerAuthentication,
		LayerAuthorization,
		LayerMonitoring,
		LayerPolicy,
		LayerCompliance,
	}
}

// AgentIdentity represents a fully-attested agent identity.
// It combines a SPIFFE ID, credentials, attestation evidence, and metadata.
type AgentIdentity struct {
	// SPIFFEID is the canonical identifier for this agent.
	SPIFFEID *SPIFFEID

	// Credential is the authentication credential (X.509 SVID, JWT-SVID, or WIT).
	Credential Credential

	// Attestation contains attestation evidence for the agent's runtime environment.
	Attestation *Attestation

	// Metadata contains additional key-value pairs about the agent.
	Metadata map[string]string

	// CreatedAt is when this identity was created.
	CreatedAt time.Time
}

// IdentityOption configures an AgentIdentity.
type IdentityOption func(*AgentIdentity)

// WithAttestation adds attestation evidence to the identity.
func WithAttestation(att *Attestation) IdentityOption {
	return func(ai *AgentIdentity) {
		ai.Attestation = att
	}
}

// WithMetadata adds metadata to the identity.
func WithMetadata(key, value string) IdentityOption {
	return func(ai *AgentIdentity) {
		if ai.Metadata == nil {
			ai.Metadata = make(map[string]string)
		}
		ai.Metadata[key] = value
	}
}

// NewAgentIdentity creates an agent identity from a SPIFFE ID and credential.
func NewAgentIdentity(spiffeID *SPIFFEID, cred Credential, opts ...IdentityOption) *AgentIdentity {
	ai := &AgentIdentity{
		SPIFFEID:   spiffeID,
		Credential: cred,
		CreatedAt:  time.Now(),
	}
	for _, opt := range opts {
		opt(ai)
	}
	return ai
}

// IsValid checks if the identity is currently valid.
// An identity is valid if:
//   - It has a SPIFFE ID
//   - It has a credential that is not expired
func (ai *AgentIdentity) IsValid() bool {
	if ai.SPIFFEID == nil {
		return false
	}
	if ai.Credential == nil {
		return false
	}
	return !ai.Credential.IsExpired()
}

// ExpiresAt returns when this identity expires.
// Returns the credential's expiration time if available.
func (ai *AgentIdentity) ExpiresAt() time.Time {
	if ai.Credential == nil {
		return time.Time{}
	}
	return ai.Credential.ExpiresAt()
}

// TimeToExpiry returns the duration until this identity expires.
// Returns 0 if already expired.
func (ai *AgentIdentity) TimeToExpiry() time.Duration {
	if ai.Credential == nil {
		return 0
	}
	ttl := ai.Credential.ExpiresAt().Sub(time.Now())
	if ttl < 0 {
		return 0
	}
	return ttl
}
