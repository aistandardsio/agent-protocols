package bridge

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func createTestJWT(header, claims map[string]any) string {
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return headerB64 + "." + claimsB64 + "." + sigB64
}

func TestDetectProtocolFromTyp(t *testing.T) {
	tests := []struct {
		name     string
		typ      string
		expected Protocol
	}{
		{"ID-JAG", TypIDJAG, ProtocolIDJAG},
		{"AIMS WIT", TypWIT, ProtocolAIMS},
		{"AAuth", TypAAuth, ProtocolAAuth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwt := createTestJWT(
				map[string]any{"typ": tt.typ, "alg": "ES256"},
				map[string]any{"sub": "test"},
			)

			protocol, err := DetectProtocol(jwt)
			if err != nil {
				t.Fatalf("DetectProtocol failed: %v", err)
			}
			if protocol != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, protocol)
			}
		})
	}
}

func TestDetectProtocolFromClaims(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]any
		expected Protocol
	}{
		{
			"ID-JAG (client_id)",
			map[string]any{"sub": "user@example.com", "client_id": "client-123"},
			ProtocolIDJAG,
		},
		{
			"AIMS (SPIFFE sub)",
			map[string]any{"sub": "spiffe://example.com/workload"},
			ProtocolAIMS,
		},
		{
			"AAuth (aauth: prefix)",
			map[string]any{"sub": "aauth:agent:123", "cnf": map[string]any{"kid": "key-123"}},
			ProtocolAAuth,
		},
		{
			"AAuth (dwk claim)",
			map[string]any{"sub": "agent", "dwk": "delegated-key"},
			ProtocolAAuth,
		},
		{
			"AAuth (ps claim)",
			map[string]any{"sub": "agent", "ps": "https://person.example.com"},
			ProtocolAAuth,
		},
		{
			"AIMS (cnf without aauth prefix)",
			map[string]any{"sub": "workload", "cnf": map[string]any{"kid": "key-123"}},
			ProtocolAIMS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwt := createTestJWT(
				map[string]any{"typ": "JWT", "alg": "ES256"},
				tt.claims,
			)

			protocol, err := DetectProtocol(jwt)
			if err != nil {
				t.Fatalf("DetectProtocol failed: %v", err)
			}
			if protocol != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, protocol)
			}
		})
	}
}

func TestDetectProtocolUnknown(t *testing.T) {
	jwt := createTestJWT(
		map[string]any{"typ": "JWT", "alg": "ES256"},
		map[string]any{"sub": "generic-subject"},
	)

	protocol, err := DetectProtocol(jwt)
	if err != nil {
		t.Fatalf("DetectProtocol failed: %v", err)
	}
	if protocol != ProtocolUnknown {
		t.Errorf("expected ProtocolUnknown, got %s", protocol)
	}
}

func TestDetectProtocolInvalidJWT(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"one part", "abc"},
		{"two parts", "abc.def"},
		{"invalid base64", "!!!.!!!.!!!"},
		{"invalid JSON header", base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".abc.def"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DetectProtocol(tt.token)
			if err != ErrInvalidJWT {
				t.Errorf("expected ErrInvalidJWT, got %v", err)
			}
		})
	}
}

func TestIsIDJAG(t *testing.T) {
	idjagToken := createTestJWT(
		map[string]any{"typ": TypIDJAG, "alg": "ES256"},
		map[string]any{"sub": "user", "client_id": "client"},
	)

	if !IsIDJAG(idjagToken) {
		t.Error("expected IsIDJAG to return true for ID-JAG token")
	}

	witToken := createTestJWT(
		map[string]any{"typ": TypWIT, "alg": "ES256"},
		map[string]any{"sub": "spiffe://example.com/workload"},
	)

	if IsIDJAG(witToken) {
		t.Error("expected IsIDJAG to return false for WIT token")
	}
}

func TestIsWIT(t *testing.T) {
	witToken := createTestJWT(
		map[string]any{"typ": TypWIT, "alg": "ES256"},
		map[string]any{"sub": "spiffe://example.com/workload"},
	)

	if !IsWIT(witToken) {
		t.Error("expected IsWIT to return true for WIT token")
	}

	idjagToken := createTestJWT(
		map[string]any{"typ": TypIDJAG, "alg": "ES256"},
		map[string]any{"sub": "user", "client_id": "client"},
	)

	if IsWIT(idjagToken) {
		t.Error("expected IsWIT to return false for ID-JAG token")
	}
}

func TestIsAAuth(t *testing.T) {
	aauthToken := createTestJWT(
		map[string]any{"typ": TypAAuth, "alg": "ES256"},
		map[string]any{"sub": "aauth:agent:123"},
	)

	if !IsAAuth(aauthToken) {
		t.Error("expected IsAAuth to return true for AAuth token")
	}

	witToken := createTestJWT(
		map[string]any{"typ": TypWIT, "alg": "ES256"},
		map[string]any{"sub": "spiffe://example.com/workload"},
	)

	if IsAAuth(witToken) {
		t.Error("expected IsAAuth to return false for WIT token")
	}
}

func TestExtractJWTHeader(t *testing.T) {
	// Test with standard padding
	headerWithPadding := base64.URLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claimsB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("sig"))

	token := headerWithPadding + "." + claimsB64 + "." + sigB64

	header, err := extractJWTHeader(token)
	if err != nil {
		t.Fatalf("extractJWTHeader failed: %v", err)
	}

	if header["typ"] != "JWT" {
		t.Errorf("expected typ=JWT, got %v", header["typ"])
	}
	if header["alg"] != "ES256" {
		t.Errorf("expected alg=ES256, got %v", header["alg"])
	}
}

func TestExtractJWTClaims(t *testing.T) {
	jwt := createTestJWT(
		map[string]any{"typ": "JWT", "alg": "ES256"},
		map[string]any{"sub": "user@example.com", "iss": "https://issuer.example.com"},
	)

	claims, err := extractJWTClaims(jwt)
	if err != nil {
		t.Fatalf("extractJWTClaims failed: %v", err)
	}

	if claims["sub"] != "user@example.com" {
		t.Errorf("expected sub=user@example.com, got %v", claims["sub"])
	}
	if claims["iss"] != "https://issuer.example.com" {
		t.Errorf("expected iss=https://issuer.example.com, got %v", claims["iss"])
	}
}
