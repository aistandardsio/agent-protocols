package sharkauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestCreateDPoPProofECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	proof, err := CreateDPoPProof(privateKey, "POST", "https://auth.example.com/token")
	if err != nil {
		t.Fatalf("CreateDPoPProof() error = %v", err)
	}

	if proof.Token == "" {
		t.Error("Expected non-empty token")
	}

	if proof.JTI == "" {
		t.Error("Expected non-empty JTI")
	}

	if proof.IssuedAt.IsZero() {
		t.Error("Expected non-zero IssuedAt")
	}
}

func TestCreateDPoPProofRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	proof, err := CreateDPoPProof(privateKey, "POST", "https://auth.example.com/token")
	if err != nil {
		t.Fatalf("CreateDPoPProof() error = %v", err)
	}

	if proof.Token == "" {
		t.Error("Expected non-empty token")
	}
}

func TestCreateDPoPProofWithOptions(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	proof, err := CreateDPoPProof(privateKey, "GET", "https://api.example.com/resource",
		WithNonce("server-nonce-123"),
		WithAccessTokenBinding("access-token-value"),
		WithJTI("custom-jti-value"),
	)
	if err != nil {
		t.Fatalf("CreateDPoPProof() error = %v", err)
	}

	if proof.JTI != "custom-jti-value" {
		t.Errorf("JTI = %v, want custom-jti-value", proof.JTI)
	}
}

func TestCreateDPoPProofECDSAP384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	proof, err := CreateDPoPProof(privateKey, "POST", "https://auth.example.com/token")
	if err != nil {
		t.Fatalf("CreateDPoPProof() error = %v", err)
	}

	if proof.Token == "" {
		t.Error("Expected non-empty token")
	}
}
