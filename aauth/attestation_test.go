package aauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestAttestationEvidence(t *testing.T) {
	t.Run("Verify valid evidence", func(t *testing.T) {
		evidence := &AttestationEvidence{
			Type:      AttestationTypeTPM,
			Timestamp: time.Now(),
			Quote:     []byte("test-quote"),
			Signature: []byte("test-signature"),
		}

		err := evidence.Verify()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Verify missing type", func(t *testing.T) {
		evidence := &AttestationEvidence{
			Timestamp: time.Now(),
			Quote:     []byte("test-quote"),
		}

		err := evidence.Verify()
		if err == nil {
			t.Error("expected error for missing type")
		}
	})

	t.Run("Verify missing timestamp", func(t *testing.T) {
		evidence := &AttestationEvidence{
			Type:  AttestationTypeTPM,
			Quote: []byte("test-quote"),
		}

		err := evidence.Verify()
		if err == nil {
			t.Error("expected error for missing timestamp")
		}
	})

	t.Run("Verify missing quote and signature", func(t *testing.T) {
		evidence := &AttestationEvidence{
			Type:      AttestationTypeTPM,
			Timestamp: time.Now(),
		}

		err := evidence.Verify()
		if err == nil {
			t.Error("expected error for missing quote/signature")
		}
	})

	t.Run("IsExpired", func(t *testing.T) {
		evidence := &AttestationEvidence{
			Type:      AttestationTypeTPM,
			Timestamp: time.Now().Add(-10 * time.Minute),
		}

		if !evidence.IsExpired(5 * time.Minute) {
			t.Error("expected evidence to be expired")
		}

		if evidence.IsExpired(15 * time.Minute) {
			t.Error("expected evidence to not be expired")
		}
	})

	t.Run("Hash", func(t *testing.T) {
		evidence := &AttestationEvidence{
			Type:      AttestationTypeTPM,
			Timestamp: time.Now(),
			Quote:     []byte("test-quote"),
		}

		hash, err := evidence.Hash()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(hash) != 32 {
			t.Errorf("expected 32-byte hash, got %d bytes", len(hash))
		}
	})
}

func TestSoftwareAttestor(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Run("Available", func(t *testing.T) {
		attestor := NewSoftwareAttestor(privateKey)
		if !attestor.Available() {
			t.Error("expected attestor to be available")
		}

		attestor2 := NewSoftwareAttestor(nil)
		if attestor2.Available() {
			t.Error("expected attestor to not be available without signer")
		}
	})

	t.Run("Type", func(t *testing.T) {
		attestor := NewSoftwareAttestor(privateKey)
		if attestor.Type() != AttestationTypeSoftware {
			t.Errorf("unexpected type: %v", attestor.Type())
		}
	})

	t.Run("Attest", func(t *testing.T) {
		attestor := NewSoftwareAttestor(privateKey,
			WithSoftwareAttestorIssuer("test-issuer"),
		)

		ctx := context.Background()
		nonce := []byte("test-nonce-12345")

		evidence, err := attestor.Attest(ctx, &privateKey.PublicKey, nonce)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if evidence.Type != AttestationTypeSoftware {
			t.Errorf("unexpected type: %v", evidence.Type)
		}

		if string(evidence.Nonce) != string(nonce) {
			t.Error("nonce mismatch")
		}

		if len(evidence.Quote) == 0 {
			t.Error("missing quote")
		}

		if len(evidence.Signature) == 0 {
			t.Error("missing signature")
		}

		if len(evidence.PublicKey) == 0 {
			t.Error("missing public key")
		}

		if evidence.PlatformData["issuer"] != "test-issuer" {
			t.Error("missing issuer in platform data")
		}
	})

	t.Run("Attest without signer", func(t *testing.T) {
		attestor := NewSoftwareAttestor(nil)

		ctx := context.Background()
		_, err := attestor.Attest(ctx, &privateKey.PublicKey, []byte("nonce"))
		if err == nil {
			t.Error("expected error without signer")
		}
	})
}

func TestTPMAttestor(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Run("Available without signer", func(t *testing.T) {
		attestor := NewTPMAttestor()
		if attestor.Available() {
			t.Error("expected attestor to not be available without signer")
		}
	})

	t.Run("Available with signer", func(t *testing.T) {
		attestor := NewTPMAttestor(
			WithTPMSigner(privateKey),
		)
		if !attestor.Available() {
			t.Error("expected attestor to be available with signer")
		}
	})

	t.Run("Type", func(t *testing.T) {
		attestor := NewTPMAttestor()
		if attestor.Type() != AttestationTypeTPM {
			t.Errorf("unexpected type: %v", attestor.Type())
		}
	})

	t.Run("Attest", func(t *testing.T) {
		// Create a mock AK certificate
		akTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "Test AK",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(24 * time.Hour),
		}
		akCertBytes, err := x509.CreateCertificate(rand.Reader, akTemplate, akTemplate, &privateKey.PublicKey, privateKey)
		if err != nil {
			t.Fatalf("failed to create AK cert: %v", err)
		}
		akCert, err := x509.ParseCertificate(akCertBytes)
		if err != nil {
			t.Fatalf("failed to parse AK cert: %v", err)
		}

		attestor := NewTPMAttestor(
			WithTPMSigner(privateKey),
			WithTPMAKCert(akCert),
			WithTPMAKHandle(0x81000001),
		)

		ctx := context.Background()
		nonce := []byte("test-nonce-12345")

		evidence, err := attestor.Attest(ctx, &privateKey.PublicKey, nonce)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if evidence.Type != AttestationTypeTPM {
			t.Errorf("unexpected type: %v", evidence.Type)
		}

		if string(evidence.Nonce) != string(nonce) {
			t.Error("nonce mismatch")
		}

		if len(evidence.Quote) == 0 {
			t.Error("missing quote")
		}

		if len(evidence.Signature) == 0 {
			t.Error("missing signature")
		}

		if len(evidence.CertificateChain) != 1 {
			t.Errorf("expected 1 certificate, got %d", len(evidence.CertificateChain))
		}

		if evidence.PlatformData["tpm_version"] != "2.0" {
			t.Error("missing TPM version in platform data")
		}
	})

	t.Run("Attest without signer", func(t *testing.T) {
		attestor := NewTPMAttestor()

		ctx := context.Background()
		_, err := attestor.Attest(ctx, &privateKey.PublicKey, []byte("nonce"))
		if err == nil {
			t.Error("expected error without signer")
		}
	})
}

func TestBasicAttestationVerifier(t *testing.T) {
	t.Run("SupportedTypes", func(t *testing.T) {
		verifier := NewBasicAttestationVerifier()
		types := verifier.SupportedTypes()

		if len(types) != 2 {
			t.Errorf("expected 2 supported types, got %d", len(types))
		}
	})

	t.Run("Verify nil evidence", func(t *testing.T) {
		verifier := NewBasicAttestationVerifier()

		ctx := context.Background()
		err := verifier.Verify(ctx, nil, nil)
		if err == nil {
			t.Error("expected error for nil evidence")
		}
	})

	t.Run("Verify unsupported type", func(t *testing.T) {
		verifier := NewBasicAttestationVerifier(
			WithSupportedAttestationTypes(AttestationTypeTPM),
		)

		evidence := &AttestationEvidence{
			Type:      AttestationTypeSoftware,
			Timestamp: time.Now(),
			Quote:     []byte("test"),
		}

		ctx := context.Background()
		err := verifier.Verify(ctx, evidence, nil)
		if err == nil {
			t.Error("expected error for unsupported type")
		}
	})

	t.Run("Verify expired evidence", func(t *testing.T) {
		verifier := NewBasicAttestationVerifier(
			WithAttestationMaxAge(1 * time.Minute),
		)

		evidence := &AttestationEvidence{
			Type:      AttestationTypeSoftware,
			Timestamp: time.Now().Add(-5 * time.Minute),
			Quote:     []byte("test"),
			Signature: []byte("sig"),
		}

		ctx := context.Background()
		err := verifier.Verify(ctx, evidence, nil)
		if err == nil {
			t.Error("expected error for expired evidence")
		}
	})

	t.Run("Verify nonce mismatch", func(t *testing.T) {
		verifier := NewBasicAttestationVerifier()

		evidence := &AttestationEvidence{
			Type:      AttestationTypeSoftware,
			Timestamp: time.Now(),
			Nonce:     []byte("nonce1"),
			Quote:     []byte("test"),
			Signature: []byte("sig"),
		}

		ctx := context.Background()
		err := verifier.Verify(ctx, evidence, []byte("nonce2"))
		if err == nil {
			t.Error("expected error for nonce mismatch")
		}
	})

	t.Run("Verify valid software evidence", func(t *testing.T) {
		verifier := NewBasicAttestationVerifier()

		evidence := &AttestationEvidence{
			Type:      AttestationTypeSoftware,
			Timestamp: time.Now(),
			Nonce:     []byte("nonce"),
			Quote:     []byte("test"),
			Signature: []byte("sig"),
		}

		ctx := context.Background()
		err := verifier.Verify(ctx, evidence, []byte("nonce"))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Verify TPM evidence with certificate", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		// Create attestor and generate evidence
		attestor := NewTPMAttestor(WithTPMSigner(privateKey))
		ctx := context.Background()
		nonce := []byte("test-nonce")

		evidence, err := attestor.Attest(ctx, &privateKey.PublicKey, nonce)
		if err != nil {
			t.Fatalf("failed to attest: %v", err)
		}

		verifier := NewBasicAttestationVerifier()
		err = verifier.Verify(ctx, evidence, nonce)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestAttestedKeyProvider(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	baseProvider := NewJWTKeyProvider(keyPair)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate signer key: %v", err)
	}

	attestor := NewSoftwareAttestor(privateKey)

	t.Run("Basic operations", func(t *testing.T) {
		provider := NewAttestedKeyProvider(baseProvider, attestor)

		if provider.Mode() != SigningModeJWT {
			t.Errorf("unexpected mode: %v", provider.Mode())
		}

		if provider.KeyID() != keyPair.KeyID {
			t.Errorf("unexpected key ID: %s", provider.KeyID())
		}

		if provider.Algorithm() != AlgorithmES256 {
			t.Errorf("unexpected algorithm: %s", provider.Algorithm())
		}

		if provider.AttestationType() != AttestationTypeSoftware {
			t.Errorf("unexpected attestation type: %v", provider.AttestationType())
		}
	})

	t.Run("Sign", func(t *testing.T) {
		provider := NewAttestedKeyProvider(baseProvider, attestor)
		ctx := context.Background()

		signature, err := provider.Sign(ctx, []byte("test data"))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(signature) == 0 {
			t.Error("empty signature")
		}
	})

	t.Run("Attest", func(t *testing.T) {
		provider := NewAttestedKeyProvider(baseProvider, attestor)
		ctx := context.Background()

		nonce := []byte("test-nonce")
		evidence, err := provider.Attest(ctx, nonce)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if evidence.Type != AttestationTypeSoftware {
			t.Errorf("unexpected type: %v", evidence.Type)
		}

		// Evidence should be cached
		evidence2, err := provider.Attest(ctx, []byte("different-nonce"))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Should return cached evidence (same nonce)
		if string(evidence2.Nonce) != string(evidence.Nonce) {
			t.Error("expected cached evidence")
		}
	})

	t.Run("CNFWithAttestation", func(t *testing.T) {
		provider := NewAttestedKeyProvider(baseProvider, attestor)
		ctx := context.Background()

		nonce := []byte("test-nonce")
		attestCNF, err := provider.CNFWithAttestation(ctx, nonce)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if attestCNF.CNF == nil {
			t.Error("missing CNF")
		}

		if attestCNF.Attestation == nil {
			t.Error("missing attestation")
		}
	})

	t.Run("Pre-computed evidence", func(t *testing.T) {
		preEvidence := &AttestationEvidence{
			Type:      AttestationTypeSoftware,
			Timestamp: time.Now(),
			Nonce:     []byte("pre-computed"),
			Quote:     []byte("quote"),
			Signature: []byte("sig"),
		}

		provider := NewAttestedKeyProvider(
			baseProvider,
			attestor,
			WithAttestedEvidence(preEvidence),
		)

		if provider.Evidence() != preEvidence {
			t.Error("expected pre-computed evidence")
		}
	})
}

func TestAttestationCNF(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	cnf, err := keyPair.ToCNF()
	if err != nil {
		t.Fatalf("failed to create CNF: %v", err)
	}

	evidence := &AttestationEvidence{
		Type:      AttestationTypeTPM,
		Timestamp: time.Now(),
		Quote:     []byte("quote"),
		Signature: []byte("sig"),
	}

	attestCNF := NewAttestationCNF(cnf, evidence)

	if attestCNF.CNF != cnf {
		t.Error("CNF mismatch")
	}

	if attestCNF.Attestation != evidence {
		t.Error("attestation mismatch")
	}
}

func TestAttestationTypes(t *testing.T) {
	types := []AttestationType{
		AttestationTypeTPM,
		AttestationTypeAppleSecureEnclave,
		AttestationTypeAndroidKeystore,
		AttestationTypeAzureSGX,
		AttestationTypeAWSNitro,
		AttestationTypeSoftware,
	}

	for _, typ := range types {
		if typ == "" {
			t.Error("empty attestation type")
		}
	}
}

func TestBytesEqual(t *testing.T) {
	tests := []struct {
		a, b   []byte
		expect bool
	}{
		{[]byte("abc"), []byte("abc"), true},
		{[]byte("abc"), []byte("abd"), false},
		{[]byte("abc"), []byte("ab"), false},
		{[]byte{}, []byte{}, true},
		{nil, nil, true},
		{nil, []byte{}, true},
	}

	for _, tt := range tests {
		result := bytesEqual(tt.a, tt.b)
		if result != tt.expect {
			t.Errorf("bytesEqual(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expect)
		}
	}
}
