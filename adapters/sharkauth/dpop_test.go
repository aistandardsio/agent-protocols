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

func TestVerifyDPoPProofECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	method := "POST"
	uri := "https://auth.example.com/token"

	proof, err := CreateDPoPProof(privateKey, method, uri)
	if err != nil {
		t.Fatalf("CreateDPoPProof() error = %v", err)
	}

	claims, err := VerifyDPoPProof(proof.Token, method, uri)
	if err != nil {
		t.Fatalf("VerifyDPoPProof() error = %v", err)
	}

	if claims.HTTPMethod != method {
		t.Errorf("HTTPMethod = %v, want %v", claims.HTTPMethod, method)
	}
	if claims.HTTPUri != uri {
		t.Errorf("HTTPUri = %v, want %v", claims.HTTPUri, uri)
	}
	if claims.ID != proof.JTI {
		t.Errorf("JTI = %v, want %v", claims.ID, proof.JTI)
	}
}

func TestVerifyDPoPProofECDSAP384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	method := "GET"
	uri := "https://api.example.com/resource"

	proof, err := CreateDPoPProof(privateKey, method, uri)
	if err != nil {
		t.Fatalf("CreateDPoPProof() error = %v", err)
	}

	claims, err := VerifyDPoPProof(proof.Token, method, uri)
	if err != nil {
		t.Fatalf("VerifyDPoPProof() error = %v", err)
	}

	if claims.HTTPMethod != method {
		t.Errorf("HTTPMethod = %v, want %v", claims.HTTPMethod, method)
	}
}

func TestVerifyDPoPProofRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	method := "POST"
	uri := "https://auth.example.com/token"

	proof, err := CreateDPoPProof(privateKey, method, uri)
	if err != nil {
		t.Fatalf("CreateDPoPProof() error = %v", err)
	}

	claims, err := VerifyDPoPProof(proof.Token, method, uri)
	if err != nil {
		t.Fatalf("VerifyDPoPProof() error = %v", err)
	}

	if claims.HTTPMethod != method {
		t.Errorf("HTTPMethod = %v, want %v", claims.HTTPMethod, method)
	}
}

func TestVerifyDPoPProofMethodMismatch(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	proof, err := CreateDPoPProof(privateKey, "POST", "https://auth.example.com/token")
	if err != nil {
		t.Fatalf("CreateDPoPProof() error = %v", err)
	}

	// Verify with wrong method should fail
	_, err = VerifyDPoPProof(proof.Token, "GET", "https://auth.example.com/token")
	if err == nil {
		t.Error("VerifyDPoPProof() should fail with method mismatch")
	}
}

func TestVerifyDPoPProofURIMismatch(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	proof, err := CreateDPoPProof(privateKey, "POST", "https://auth.example.com/token")
	if err != nil {
		t.Fatalf("CreateDPoPProof() error = %v", err)
	}

	// Verify with wrong URI should fail
	_, err = VerifyDPoPProof(proof.Token, "POST", "https://wrong.example.com/token")
	if err == nil {
		t.Error("VerifyDPoPProof() should fail with URI mismatch")
	}
}
