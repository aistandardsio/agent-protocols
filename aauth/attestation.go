package aauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Attestation errors.
var (
	// ErrAttestationFailed indicates attestation verification failed.
	ErrAttestationFailed = errors.New("attestation verification failed")

	// ErrUnsupportedAttestationType indicates an unsupported attestation type.
	ErrUnsupportedAttestationType = errors.New("unsupported attestation type")

	// ErrAttestationExpired indicates the attestation evidence has expired.
	ErrAttestationExpired = errors.New("attestation evidence expired")

	// ErrInvalidAttestationChain indicates the certificate chain is invalid.
	ErrInvalidAttestationChain = errors.New("invalid attestation certificate chain")

	// ErrPlatformNotSupported indicates the platform doesn't support attestation.
	ErrPlatformNotSupported = errors.New("platform attestation not supported")
)

// AttestationType identifies the type of platform attestation.
type AttestationType string

// Supported attestation types.
const (
	// AttestationTypeTPM is TPM 2.0 attestation.
	AttestationTypeTPM AttestationType = "tpm"

	// AttestationTypeAppleSecureEnclave is Apple Secure Enclave attestation.
	AttestationTypeAppleSecureEnclave AttestationType = "apple-secure-enclave"

	// AttestationTypeAndroidKeystore is Android Keystore attestation.
	AttestationTypeAndroidKeystore AttestationType = "android-keystore"

	// AttestationTypeAzureSGX is Azure SGX enclave attestation.
	AttestationTypeAzureSGX AttestationType = "azure-sgx"

	// AttestationTypeAWSNitro is AWS Nitro Enclave attestation.
	AttestationTypeAWSNitro AttestationType = "aws-nitro"

	// AttestationTypeSoftware is software-based attestation (for testing).
	AttestationTypeSoftware AttestationType = "software"
)

// AttestationEvidence contains proof of platform integrity.
type AttestationEvidence struct {
	// Type identifies the attestation mechanism.
	Type AttestationType `json:"type"`

	// Timestamp is when the attestation was created.
	Timestamp time.Time `json:"timestamp"`

	// Nonce is a challenge nonce to prevent replay attacks.
	Nonce []byte `json:"nonce,omitempty"`

	// Quote is the signed attestation quote (TPM) or attestation statement.
	Quote []byte `json:"quote,omitempty"`

	// Signature is the signature over the attestation data.
	Signature []byte `json:"signature,omitempty"`

	// PublicKey is the attested public key in DER format.
	PublicKey []byte `json:"public_key,omitempty"`

	// CertificateChain is the certificate chain for verification.
	// The first certificate is the leaf (attestation key), followed by intermediates.
	CertificateChain [][]byte `json:"certificate_chain,omitempty"`

	// PlatformData contains platform-specific attestation data.
	PlatformData map[string]any `json:"platform_data,omitempty"`

	// PCRs are Platform Configuration Register values (TPM-specific).
	PCRs map[int][]byte `json:"pcrs,omitempty"`
}

// Verify checks the attestation evidence integrity (not trust).
func (e *AttestationEvidence) Verify() error {
	if e.Type == "" {
		return fmt.Errorf("%w: missing attestation type", ErrAttestationFailed)
	}

	if e.Timestamp.IsZero() {
		return fmt.Errorf("%w: missing timestamp", ErrAttestationFailed)
	}

	if len(e.Quote) == 0 && len(e.Signature) == 0 {
		return fmt.Errorf("%w: missing quote or signature", ErrAttestationFailed)
	}

	return nil
}

// IsExpired checks if the attestation evidence has expired.
func (e *AttestationEvidence) IsExpired(maxAge time.Duration) bool {
	return time.Since(e.Timestamp) > maxAge
}

// Hash returns a SHA-256 hash of the attestation evidence.
func (e *AttestationEvidence) Hash() ([]byte, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation: %w", err)
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

// PlatformAttestor generates attestation evidence for a platform.
type PlatformAttestor interface {
	// Type returns the attestation type.
	Type() AttestationType

	// Attest generates attestation evidence for the given public key.
	// The nonce should be included in the attestation to prevent replay attacks.
	Attest(ctx context.Context, publicKey crypto.PublicKey, nonce []byte) (*AttestationEvidence, error)

	// Available returns true if this attestation mechanism is available on the current platform.
	Available() bool
}

// AttestationVerifier verifies attestation evidence.
type AttestationVerifier interface {
	// Verify verifies the attestation evidence.
	// It checks the signature, certificate chain, and platform-specific validation.
	Verify(ctx context.Context, evidence *AttestationEvidence, expectedNonce []byte) error

	// SupportedTypes returns the attestation types this verifier supports.
	SupportedTypes() []AttestationType
}

// TPMAttestationData contains TPM-specific attestation information.
type TPMAttestationData struct {
	// TPMVersion is the TPM version (e.g., "2.0").
	TPMVersion string `json:"tpm_version"`

	// Manufacturer is the TPM manufacturer ID.
	Manufacturer string `json:"manufacturer,omitempty"`

	// FirmwareVersion is the TPM firmware version.
	FirmwareVersion string `json:"firmware_version,omitempty"`

	// AttestationKeyHandle is the handle of the attestation key.
	AttestationKeyHandle uint32 `json:"ak_handle,omitempty"`

	// SigningKeyHandle is the handle of the signing key.
	SigningKeyHandle uint32 `json:"sk_handle,omitempty"`

	// PCRSelection specifies which PCRs were included in the quote.
	PCRSelection []int `json:"pcr_selection,omitempty"`

	// ClockInfo contains TPM clock information.
	ClockInfo *TPMClockInfo `json:"clock_info,omitempty"`
}

// TPMClockInfo contains TPM clock information for freshness verification.
type TPMClockInfo struct {
	// Clock is the TPM clock value.
	Clock uint64 `json:"clock"`

	// ResetCount is the number of TPM resets.
	ResetCount uint32 `json:"reset_count"`

	// RestartCount is the number of TPM restarts.
	RestartCount uint32 `json:"restart_count"`

	// Safe indicates if the clock is safe (no power loss).
	Safe bool `json:"safe"`
}

// TPMAttestor provides TPM 2.0 attestation.
type TPMAttestor struct {
	// tpmDevice is the TPM device path (e.g., "/dev/tpm0" or "simulator").
	tpmDevice string

	// akHandle is the attestation key handle.
	akHandle uint32

	// ekCert is the endorsement key certificate.
	ekCert *x509.Certificate

	// akCert is the attestation key certificate.
	akCert *x509.Certificate

	// signer is the TPM-backed signer.
	signer crypto.Signer
}

// TPMAttestorOption configures a TPMAttestor.
type TPMAttestorOption func(*TPMAttestor)

// WithTPMDevice sets the TPM device path.
func WithTPMDevice(device string) TPMAttestorOption {
	return func(a *TPMAttestor) {
		a.tpmDevice = device
	}
}

// WithTPMAKHandle sets the attestation key handle.
func WithTPMAKHandle(handle uint32) TPMAttestorOption {
	return func(a *TPMAttestor) {
		a.akHandle = handle
	}
}

// WithTPMEKCert sets the endorsement key certificate.
func WithTPMEKCert(cert *x509.Certificate) TPMAttestorOption {
	return func(a *TPMAttestor) {
		a.ekCert = cert
	}
}

// WithTPMAKCert sets the attestation key certificate.
func WithTPMAKCert(cert *x509.Certificate) TPMAttestorOption {
	return func(a *TPMAttestor) {
		a.akCert = cert
	}
}

// WithTPMSigner sets the TPM-backed signer.
func WithTPMSigner(signer crypto.Signer) TPMAttestorOption {
	return func(a *TPMAttestor) {
		a.signer = signer
	}
}

// NewTPMAttestor creates a new TPM attestor.
func NewTPMAttestor(opts ...TPMAttestorOption) *TPMAttestor {
	a := &TPMAttestor{
		tpmDevice: "/dev/tpm0",
		akHandle:  0x81000001, // Default persistent handle
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Type returns AttestationTypeTPM.
func (a *TPMAttestor) Type() AttestationType {
	return AttestationTypeTPM
}

// Available checks if TPM is available on this platform.
func (a *TPMAttestor) Available() bool {
	// In a real implementation, this would check for TPM device availability
	// For now, we check if a signer was provided
	return a.signer != nil
}

// Attest generates TPM attestation evidence.
func (a *TPMAttestor) Attest(ctx context.Context, publicKey crypto.PublicKey, nonce []byte) (*AttestationEvidence, error) {
	if !a.Available() {
		return nil, ErrPlatformNotSupported
	}

	if a.signer == nil {
		return nil, fmt.Errorf("%w: TPM signer not configured", ErrAttestationFailed)
	}

	// Marshal the public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create quote data: hash of public key + nonce
	quoteData := sha256.Sum256(append(pubKeyBytes, nonce...))

	// Sign the quote with the TPM attestation key
	signature, err := a.signer.Sign(nil, quoteData[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to sign quote: %w", err)
	}

	// Build certificate chain
	var certChain [][]byte
	if a.akCert != nil {
		certChain = append(certChain, a.akCert.Raw)
	}
	if a.ekCert != nil {
		certChain = append(certChain, a.ekCert.Raw)
	}

	// Build platform data
	platformData := map[string]any{
		"tpm_version": "2.0",
		"ak_handle":   a.akHandle,
	}

	return &AttestationEvidence{
		Type:             AttestationTypeTPM,
		Timestamp:        time.Now().UTC(),
		Nonce:            nonce,
		Quote:            quoteData[:],
		Signature:        signature,
		PublicKey:        pubKeyBytes,
		CertificateChain: certChain,
		PlatformData:     platformData,
	}, nil
}

// SoftwareAttestor provides software-based attestation for testing.
type SoftwareAttestor struct {
	signer    crypto.Signer
	issuer    string
	notBefore time.Time
	notAfter  time.Time
}

// SoftwareAttestorOption configures a SoftwareAttestor.
type SoftwareAttestorOption func(*SoftwareAttestor)

// WithSoftwareAttestorIssuer sets the issuer for software attestation.
func WithSoftwareAttestorIssuer(issuer string) SoftwareAttestorOption {
	return func(a *SoftwareAttestor) {
		a.issuer = issuer
	}
}

// WithSoftwareAttestorValidity sets the validity period.
func WithSoftwareAttestorValidity(notBefore, notAfter time.Time) SoftwareAttestorOption {
	return func(a *SoftwareAttestor) {
		a.notBefore = notBefore
		a.notAfter = notAfter
	}
}

// NewSoftwareAttestor creates a software attestor for testing.
func NewSoftwareAttestor(signer crypto.Signer, opts ...SoftwareAttestorOption) *SoftwareAttestor {
	a := &SoftwareAttestor{
		signer:    signer,
		issuer:    "software-attestor",
		notBefore: time.Now(),
		notAfter:  time.Now().Add(24 * time.Hour),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Type returns AttestationTypeSoftware.
func (a *SoftwareAttestor) Type() AttestationType {
	return AttestationTypeSoftware
}

// Available always returns true for software attestation.
func (a *SoftwareAttestor) Available() bool {
	return a.signer != nil
}

// Attest generates software attestation evidence.
func (a *SoftwareAttestor) Attest(ctx context.Context, publicKey crypto.PublicKey, nonce []byte) (*AttestationEvidence, error) {
	if a.signer == nil {
		return nil, fmt.Errorf("%w: signer not configured", ErrAttestationFailed)
	}

	// Marshal the public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create attestation data
	attestData := struct {
		PublicKey string    `json:"public_key"`
		Nonce     string    `json:"nonce"`
		Timestamp time.Time `json:"timestamp"`
		Issuer    string    `json:"issuer"`
	}{
		PublicKey: base64.StdEncoding.EncodeToString(pubKeyBytes),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Timestamp: time.Now().UTC(),
		Issuer:    a.issuer,
	}

	attestDataBytes, err := json.Marshal(attestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation data: %w", err)
	}

	// Sign the attestation data
	hash := sha256.Sum256(attestDataBytes)
	signature, err := a.signer.Sign(nil, hash[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation: %w", err)
	}

	return &AttestationEvidence{
		Type:      AttestationTypeSoftware,
		Timestamp: time.Now().UTC(),
		Nonce:     nonce,
		Quote:     attestDataBytes,
		Signature: signature,
		PublicKey: pubKeyBytes,
		PlatformData: map[string]any{
			"issuer":     a.issuer,
			"not_before": a.notBefore.Unix(),
			"not_after":  a.notAfter.Unix(),
		},
	}, nil
}

// BasicAttestationVerifier provides basic attestation verification.
type BasicAttestationVerifier struct {
	// trustedRoots are trusted root certificates for chain verification.
	trustedRoots *x509.CertPool

	// maxAge is the maximum age of attestation evidence.
	maxAge time.Duration

	// supportedTypes are the attestation types this verifier supports.
	supportedTypes []AttestationType
}

// BasicAttestationVerifierOption configures a BasicAttestationVerifier.
type BasicAttestationVerifierOption func(*BasicAttestationVerifier)

// WithTrustedRoots sets the trusted root certificates.
func WithTrustedRoots(roots *x509.CertPool) BasicAttestationVerifierOption {
	return func(v *BasicAttestationVerifier) {
		v.trustedRoots = roots
	}
}

// WithAttestationMaxAge sets the maximum age of attestation evidence.
func WithAttestationMaxAge(maxAge time.Duration) BasicAttestationVerifierOption {
	return func(v *BasicAttestationVerifier) {
		v.maxAge = maxAge
	}
}

// WithSupportedAttestationTypes sets the supported attestation types.
func WithSupportedAttestationTypes(types ...AttestationType) BasicAttestationVerifierOption {
	return func(v *BasicAttestationVerifier) {
		v.supportedTypes = types
	}
}

// NewBasicAttestationVerifier creates a basic attestation verifier.
func NewBasicAttestationVerifier(opts ...BasicAttestationVerifierOption) *BasicAttestationVerifier {
	v := &BasicAttestationVerifier{
		trustedRoots: x509.NewCertPool(),
		maxAge:       5 * time.Minute,
		supportedTypes: []AttestationType{
			AttestationTypeTPM,
			AttestationTypeSoftware,
		},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// SupportedTypes returns the supported attestation types.
func (v *BasicAttestationVerifier) SupportedTypes() []AttestationType {
	return v.supportedTypes
}

// Verify verifies attestation evidence.
func (v *BasicAttestationVerifier) Verify(ctx context.Context, evidence *AttestationEvidence, expectedNonce []byte) error {
	if evidence == nil {
		return fmt.Errorf("%w: nil evidence", ErrAttestationFailed)
	}

	// Check attestation type is supported
	supported := false
	for _, t := range v.supportedTypes {
		if t == evidence.Type {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("%w: %s", ErrUnsupportedAttestationType, evidence.Type)
	}

	// Verify basic structure
	if err := evidence.Verify(); err != nil {
		return err
	}

	// Check expiration
	if evidence.IsExpired(v.maxAge) {
		return fmt.Errorf("%w: evidence age %v exceeds max %v",
			ErrAttestationExpired, time.Since(evidence.Timestamp), v.maxAge)
	}

	// Verify nonce matches
	if expectedNonce != nil && len(evidence.Nonce) > 0 {
		if !bytesEqual(evidence.Nonce, expectedNonce) {
			return fmt.Errorf("%w: nonce mismatch", ErrAttestationFailed)
		}
	}

	// Verify certificate chain if present
	if len(evidence.CertificateChain) > 0 {
		if err := v.verifyCertificateChain(evidence.CertificateChain); err != nil {
			return err
		}
	}

	// Type-specific verification
	switch evidence.Type {
	case AttestationTypeTPM:
		return v.verifyTPMEvidence(ctx, evidence)
	case AttestationTypeSoftware:
		return v.verifySoftwareEvidence(ctx, evidence)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAttestationType, evidence.Type)
	}
}

// verifyCertificateChain verifies the certificate chain.
func (v *BasicAttestationVerifier) verifyCertificateChain(chain [][]byte) error {
	if len(chain) == 0 {
		return nil
	}

	certs := make([]*x509.Certificate, len(chain))
	for i, certBytes := range chain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("%w: failed to parse certificate %d: %v",
				ErrInvalidAttestationChain, i, err)
		}
		certs[i] = cert
	}

	// Build intermediate pool
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// Verify the leaf certificate
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         v.trustedRoots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		// If no trusted roots configured, skip chain verification
		if v.trustedRoots == nil {
			return nil
		}
		return fmt.Errorf("%w: %v", ErrInvalidAttestationChain, err)
	}

	return nil
}

// verifyTPMEvidence verifies TPM-specific attestation evidence.
func (v *BasicAttestationVerifier) verifyTPMEvidence(_ context.Context, evidence *AttestationEvidence) error {
	if len(evidence.Quote) == 0 {
		return fmt.Errorf("%w: missing TPM quote", ErrAttestationFailed)
	}

	if len(evidence.Signature) == 0 {
		return fmt.Errorf("%w: missing TPM signature", ErrAttestationFailed)
	}

	// If we have a certificate chain, verify the signature using the leaf cert
	if len(evidence.CertificateChain) > 0 {
		leafCert, err := x509.ParseCertificate(evidence.CertificateChain[0])
		if err != nil {
			return fmt.Errorf("%w: failed to parse leaf certificate: %v",
				ErrAttestationFailed, err)
		}

		if err := verifySignature(leafCert.PublicKey, evidence.Quote, evidence.Signature); err != nil {
			return fmt.Errorf("%w: signature verification failed: %v",
				ErrAttestationFailed, err)
		}
	}

	return nil
}

// verifySoftwareEvidence verifies software attestation evidence.
func (v *BasicAttestationVerifier) verifySoftwareEvidence(_ context.Context, evidence *AttestationEvidence) error {
	// Software attestation is mainly for testing, so we just verify basic structure
	if len(evidence.Quote) == 0 {
		return fmt.Errorf("%w: missing attestation data", ErrAttestationFailed)
	}

	if len(evidence.Signature) == 0 {
		return fmt.Errorf("%w: missing signature", ErrAttestationFailed)
	}

	return nil
}

// verifySignature verifies a signature over data.
func verifySignature(publicKey crypto.PublicKey, data, signature []byte) error {
	hash := sha256.Sum256(data)

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, hash[:], signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// bytesEqual compares two byte slices in constant time.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// AttestationCNF extends the CNF claim with attestation evidence.
type AttestationCNF struct {
	*CNF

	// Attestation is the platform attestation evidence.
	Attestation *AttestationEvidence `json:"attestation,omitempty"`
}

// NewAttestationCNF creates a CNF with attestation evidence.
func NewAttestationCNF(cnf *CNF, evidence *AttestationEvidence) *AttestationCNF {
	return &AttestationCNF{
		CNF:         cnf,
		Attestation: evidence,
	}
}

// AttestedKeyProvider wraps a SignatureKeyProvider with attestation.
type AttestedKeyProvider struct {
	SignatureKeyProvider

	attestor PlatformAttestor
	evidence *AttestationEvidence
}

// AttestedKeyProviderOption configures an AttestedKeyProvider.
type AttestedKeyProviderOption func(*AttestedKeyProvider)

// WithAttestedEvidence sets pre-computed attestation evidence.
func WithAttestedEvidence(evidence *AttestationEvidence) AttestedKeyProviderOption {
	return func(p *AttestedKeyProvider) {
		p.evidence = evidence
	}
}

// NewAttestedKeyProvider wraps a key provider with platform attestation.
func NewAttestedKeyProvider(
	provider SignatureKeyProvider,
	attestor PlatformAttestor,
	opts ...AttestedKeyProviderOption,
) *AttestedKeyProvider {
	p := &AttestedKeyProvider{
		SignatureKeyProvider: provider,
		attestor:             attestor,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Attest generates attestation evidence for this key provider.
func (p *AttestedKeyProvider) Attest(ctx context.Context, nonce []byte) (*AttestationEvidence, error) {
	// Return cached evidence if available and not expired
	if p.evidence != nil && !p.evidence.IsExpired(5*time.Minute) {
		return p.evidence, nil
	}

	publicKey, err := p.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	evidence, err := p.attestor.Attest(ctx, publicKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("attestation failed: %w", err)
	}

	p.evidence = evidence
	return evidence, nil
}

// CNFWithAttestation returns a CNF with attestation evidence.
func (p *AttestedKeyProvider) CNFWithAttestation(ctx context.Context, nonce []byte) (*AttestationCNF, error) {
	cnf, err := p.CNF(ctx)
	if err != nil {
		return nil, err
	}

	evidence, err := p.Attest(ctx, nonce)
	if err != nil {
		return nil, err
	}

	return NewAttestationCNF(cnf, evidence), nil
}

// AttestationType returns the type of attestation.
func (p *AttestedKeyProvider) AttestationType() AttestationType {
	if p.attestor == nil {
		return ""
	}
	return p.attestor.Type()
}

// Evidence returns the current attestation evidence.
func (p *AttestedKeyProvider) Evidence() *AttestationEvidence {
	return p.evidence
}
