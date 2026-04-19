package aims

import (
	"time"
)

// AttestationType identifies the attestation mechanism used.
type AttestationType string

const (
	// AttestationTPM uses TPM-based hardware attestation.
	AttestationTPM AttestationType = "tpm"

	// AttestationSGX uses Intel SGX enclave attestation.
	AttestationSGX AttestationType = "sgx"

	// AttestationSEVSNP uses AMD SEV-SNP attestation.
	AttestationSEVSNP AttestationType = "sev-snp"

	// AttestationTDX uses Intel TDX attestation.
	AttestationTDX AttestationType = "tdx"

	// AttestationKubernetes uses Kubernetes service account attestation.
	AttestationKubernetes AttestationType = "kubernetes"

	// AttestationAWS uses AWS instance identity document attestation.
	AttestationAWS AttestationType = "aws"

	// AttestationGCP uses GCP instance identity token attestation.
	AttestationGCP AttestationType = "gcp"

	// AttestationAzure uses Azure managed identity attestation.
	AttestationAzure AttestationType = "azure"

	// AttestationGitHub uses GitHub Actions OIDC token attestation.
	AttestationGitHub AttestationType = "github"

	// AttestationUnix uses Unix domain socket attestation (PID, UID, GID).
	AttestationUnix AttestationType = "unix"

	// AttestationDocker uses Docker container attestation.
	AttestationDocker AttestationType = "docker"
)

// String returns the attestation type as a string.
func (at AttestationType) String() string {
	return string(at)
}

// Description returns a human-readable description of the attestation type.
func (at AttestationType) Description() string {
	switch at {
	case AttestationTPM:
		return "TPM-based hardware attestation"
	case AttestationSGX:
		return "Intel SGX enclave attestation"
	case AttestationSEVSNP:
		return "AMD SEV-SNP confidential VM attestation"
	case AttestationTDX:
		return "Intel TDX trusted domain attestation"
	case AttestationKubernetes:
		return "Kubernetes service account attestation"
	case AttestationAWS:
		return "AWS instance identity document attestation"
	case AttestationGCP:
		return "GCP instance identity token attestation"
	case AttestationAzure:
		return "Azure managed identity attestation"
	case AttestationGitHub:
		return "GitHub Actions OIDC token attestation"
	case AttestationUnix:
		return "Unix domain socket attestation"
	case AttestationDocker:
		return "Docker container attestation"
	default:
		return "Unknown attestation type"
	}
}

// IsHardware returns true if this is a hardware-based attestation type.
func (at AttestationType) IsHardware() bool {
	switch at {
	case AttestationTPM, AttestationSGX, AttestationSEVSNP, AttestationTDX:
		return true
	default:
		return false
	}
}

// IsCloud returns true if this is a cloud provider attestation type.
func (at AttestationType) IsCloud() bool {
	switch at {
	case AttestationAWS, AttestationGCP, AttestationAzure:
		return true
	default:
		return false
	}
}

// Attestation represents attestation evidence for an agent's runtime environment.
// Attestation proves the agent is running in a trusted context.
type Attestation struct {
	// Type identifies the attestation mechanism.
	Type AttestationType

	// Evidence is the raw attestation evidence (format depends on Type).
	// For TPM: TPM quote and PCR values
	// For SGX: SGX report/quote
	// For cloud: signed instance identity document
	Evidence []byte

	// Timestamp is when the attestation was generated.
	Timestamp time.Time

	// Attributes contains parsed attestation attributes.
	// Keys and values depend on the attestation type.
	Attributes map[string]string
}

// NewAttestation creates a new attestation with the given type and evidence.
func NewAttestation(attestType AttestationType, evidence []byte) *Attestation {
	return &Attestation{
		Type:      attestType,
		Evidence:  evidence,
		Timestamp: time.Now(),
	}
}

// AttestationOption configures an Attestation.
type AttestationOption func(*Attestation)

// WithAttestationTimestamp sets a custom timestamp for the attestation.
func WithAttestationTimestamp(t time.Time) AttestationOption {
	return func(a *Attestation) {
		a.Timestamp = t
	}
}

// WithAttribute adds an attribute to the attestation.
func WithAttribute(key, value string) AttestationOption {
	return func(a *Attestation) {
		if a.Attributes == nil {
			a.Attributes = make(map[string]string)
		}
		a.Attributes[key] = value
	}
}

// NewAttestationWithOptions creates an attestation with options.
func NewAttestationWithOptions(attestType AttestationType, evidence []byte, opts ...AttestationOption) *Attestation {
	a := &Attestation{
		Type:      attestType,
		Evidence:  evidence,
		Timestamp: time.Now(),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Age returns how old the attestation is.
func (a *Attestation) Age() time.Duration {
	return time.Since(a.Timestamp)
}

// IsFresh returns true if the attestation is younger than the given duration.
func (a *Attestation) IsFresh(maxAge time.Duration) bool {
	return a.Age() < maxAge
}

// GetAttribute returns an attestation attribute value.
func (a *Attestation) GetAttribute(key string) (string, bool) {
	if a.Attributes == nil {
		return "", false
	}
	v, ok := a.Attributes[key]
	return v, ok
}

// Common attestation attribute keys.
const (
	// AttrInstanceID is the cloud instance ID.
	AttrInstanceID = "instance-id"

	// AttrRegion is the cloud region.
	AttrRegion = "region"

	// AttrAccountID is the cloud account/project ID.
	AttrAccountID = "account-id"

	// AttrNamespace is the Kubernetes namespace.
	AttrNamespace = "namespace"

	// AttrServiceAccount is the Kubernetes service account name.
	AttrServiceAccount = "service-account"

	// AttrPodName is the Kubernetes pod name.
	AttrPodName = "pod-name"

	// AttrContainerID is the container ID (Docker, containerd).
	AttrContainerID = "container-id"

	// AttrImageDigest is the container image digest.
	AttrImageDigest = "image-digest"

	// AttrPCR0 is the TPM PCR[0] value (BIOS/firmware).
	AttrPCR0 = "pcr0"

	// AttrMRENCLAVE is the SGX enclave measurement.
	AttrMRENCLAVE = "mrenclave"

	// AttrMRSIGNER is the SGX signer measurement.
	AttrMRSIGNER = "mrsigner"
)
