package aims

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"
)

func TestNewWPT(t *testing.T) {
	wpt := NewWPT(
		"spiffe://example.com/agent/test",
		"https://api.example.com",
		"POST",
		"/api/v1/events",
	)

	if wpt.Issuer != "spiffe://example.com/agent/test" {
		t.Errorf("Issuer = %q, want %q", wpt.Issuer, "spiffe://example.com/agent/test")
	}
	if wpt.Audience != "https://api.example.com" {
		t.Errorf("Audience = %q, want %q", wpt.Audience, "https://api.example.com")
	}
	if wpt.HTM != "POST" {
		t.Errorf("HTM = %q, want %q", wpt.HTM, "POST")
	}
	if wpt.HTU != "/api/v1/events" {
		t.Errorf("HTU = %q, want %q", wpt.HTU, "/api/v1/events")
	}
	if wpt.IssuedAt.IsZero() {
		t.Error("IssuedAt should not be zero")
	}
	if wpt.JWTID == "" {
		t.Error("JWTID should be auto-generated")
	}
}

func TestNewWPT_WithOptions(t *testing.T) {
	expiry := time.Now().Add(10 * time.Minute)
	wpt := NewWPT(
		"spiffe://example.com/agent/test",
		"https://api.example.com",
		"GET",
		"/api/v1/data",
		WithWPTNonce("server-nonce-123"),
		WithWPTJTI("custom-jti"),
		WithWPTExpiry(expiry),
		WithWPTAccessToken("access-token-value"),
	)

	if wpt.Nonce != "server-nonce-123" {
		t.Errorf("Nonce = %q, want %q", wpt.Nonce, "server-nonce-123")
	}
	if wpt.JWTID != "custom-jti" {
		t.Errorf("JWTID = %q, want %q", wpt.JWTID, "custom-jti")
	}
	if !wpt.Expiry.Equal(expiry) {
		t.Errorf("Expiry = %v, want %v", wpt.Expiry, expiry)
	}
	if wpt.ATH == "" {
		t.Error("ATH should be set when access token is bound")
	}
}

func TestNewWPTFromWIT(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")
	wit := NewWIT(spiffeID, []string{"https://api.example.com"}, 1*time.Hour)

	wpt := NewWPTFromWIT(wit, "https://api.example.com", "POST", "/api/v1/action")

	if wpt.Issuer != wit.Subject {
		t.Errorf("Issuer = %q, want %q", wpt.Issuer, wit.Subject)
	}
}

func TestNewWPTForRequest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/api/v1/events?filter=active", nil)

	wpt := NewWPTForRequest("spiffe://example.com/agent/test", "https://api.example.com", req)

	if wpt.HTM != "POST" {
		t.Errorf("HTM = %q, want %q", wpt.HTM, "POST")
	}
	if wpt.HTU != "/api/v1/events?filter=active" {
		t.Errorf("HTU = %q, want %q", wpt.HTU, "/api/v1/events?filter=active")
	}
}

func TestWIMSEProofToken_Validate(t *testing.T) {
	tests := []struct {
		name    string
		wpt     *WIMSEProofToken
		wantErr error
	}{
		{
			name: "valid",
			wpt: &WIMSEProofToken{
				Issuer:   "spiffe://example.com/agent/test",
				Audience: "https://api.example.com",
				HTM:      "POST",
				HTU:      "/api/v1/events",
				Expiry:   time.Now().Add(5 * time.Minute),
			},
			wantErr: nil,
		},
		{
			name: "missing_issuer",
			wpt: &WIMSEProofToken{
				Audience: "https://api.example.com",
				HTM:      "POST",
				HTU:      "/api/v1/events",
			},
			wantErr: ErrWPTMissingIssuer,
		},
		{
			name: "missing_audience",
			wpt: &WIMSEProofToken{
				Issuer: "spiffe://example.com/agent/test",
				HTM:    "POST",
				HTU:    "/api/v1/events",
			},
			wantErr: ErrWPTMissingAudience,
		},
		{
			name: "missing_htm",
			wpt: &WIMSEProofToken{
				Issuer:   "spiffe://example.com/agent/test",
				Audience: "https://api.example.com",
				HTU:      "/api/v1/events",
			},
			wantErr: ErrWPTMissingHTM,
		},
		{
			name: "missing_htu",
			wpt: &WIMSEProofToken{
				Issuer:   "spiffe://example.com/agent/test",
				Audience: "https://api.example.com",
				HTM:      "POST",
			},
			wantErr: ErrWPTMissingHTU,
		},
		{
			name: "expired",
			wpt: &WIMSEProofToken{
				Issuer:   "spiffe://example.com/agent/test",
				Audience: "https://api.example.com",
				HTM:      "POST",
				HTU:      "/api/v1/events",
				Expiry:   time.Now().Add(-1 * time.Minute),
			},
			wantErr: ErrWPTExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.wpt.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWIMSEProofToken_Sign(t *testing.T) {
	wpt := NewWPT(
		"spiffe://example.com/agent/test",
		"https://api.example.com",
		"POST",
		"/api/v1/events",
	)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	signed, err := wpt.Sign(privateKey, "test-key-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if signed == "" {
		t.Error("Sign() returned empty string")
	}

	// JWT should have 3 parts
	parts := 0
	for i := range signed {
		if signed[i] == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("Signed JWT should have 3 parts (2 dots), got %d dots", parts)
	}
}

func TestWIMSEProofToken_BindToRequest(t *testing.T) {
	wpt := NewWPT(
		"spiffe://example.com/agent/test",
		"https://api.example.com",
		"POST",
		"/api/v1/events",
	)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/api/v1/events", nil)
	err = wpt.BindToRequest(req, privateKey, "test-key-1")
	if err != nil {
		t.Fatalf("BindToRequest() error = %v", err)
	}

	header := req.Header.Get(HeaderWPT)
	if header == "" {
		t.Errorf("Request should have %s header", HeaderWPT)
	}
}

func TestWIMSEProofToken_MatchesRequest(t *testing.T) {
	tests := []struct {
		name   string
		wpt    *WIMSEProofToken
		method string
		uri    string
		want   bool
	}{
		{
			name: "exact_match",
			wpt: &WIMSEProofToken{
				HTM: "POST",
				HTU: "/api/v1/events",
			},
			method: "POST",
			uri:    "/api/v1/events",
			want:   true,
		},
		{
			name: "method_case_insensitive",
			wpt: &WIMSEProofToken{
				HTM: "POST",
				HTU: "/api/v1/events",
			},
			method: "post",
			uri:    "/api/v1/events",
			want:   true,
		},
		{
			name: "method_mismatch",
			wpt: &WIMSEProofToken{
				HTM: "POST",
				HTU: "/api/v1/events",
			},
			method: "GET",
			uri:    "/api/v1/events",
			want:   false,
		},
		{
			name: "uri_mismatch",
			wpt: &WIMSEProofToken{
				HTM: "POST",
				HTU: "/api/v1/events",
			},
			method: "POST",
			uri:    "/api/v1/other",
			want:   false,
		},
		{
			name: "with_query_string",
			wpt: &WIMSEProofToken{
				HTM: "GET",
				HTU: "/api/v1/data?filter=active",
			},
			method: "GET",
			uri:    "/api/v1/data?filter=active",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "https://api.example.com"+tt.uri, nil)
			if got := tt.wpt.MatchesRequest(req); got != tt.want {
				t.Errorf("MatchesRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWIMSEProofToken_IsExpired(t *testing.T) {
	tests := []struct {
		name   string
		expiry time.Time
		want   bool
	}{
		{"future", time.Now().Add(5 * time.Minute), false},
		{"past", time.Now().Add(-1 * time.Minute), true},
		{"zero", time.Time{}, false}, // No expiry set
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wpt := &WIMSEProofToken{Expiry: tt.expiry}
			if got := wpt.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWPTFromHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	req.Header.Set(HeaderWPT, "signed-wpt-value")

	got := WPTFromHeader(req)
	if got != "signed-wpt-value" {
		t.Errorf("WPTFromHeader() = %q, want %q", got, "signed-wpt-value")
	}
}

func Test_hashAccessToken(t *testing.T) {
	hash1 := hashAccessToken("access-token-1")
	hash2 := hashAccessToken("access-token-1")
	hash3 := hashAccessToken("access-token-2")

	if hash1 == "" {
		t.Error("hashAccessToken() returned empty string")
	}
	if hash1 != hash2 {
		t.Error("Same token should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("Different tokens should produce different hashes")
	}
}

func TestParseWPT(t *testing.T) {
	// Create and sign a WPT
	originalWPT := NewWPT(
		"spiffe://example.com/agent/test",
		"https://api.example.com",
		"POST",
		"/api/v1/resource",
		WithWPTJTI("test-jti"),
		WithWPTNonce("test-nonce"),
		WithWPTAccessToken("access-token-123"),
	)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	signed, err := originalWPT.Sign(privateKey, "test-key-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Parse the signed WPT
	parsed, err := ParseWPT(signed)
	if err != nil {
		t.Fatalf("ParseWPT() error = %v", err)
	}

	// Verify parsed values match original
	if parsed.Issuer != originalWPT.Issuer {
		t.Errorf("Issuer = %q, want %q", parsed.Issuer, originalWPT.Issuer)
	}
	if parsed.Audience != originalWPT.Audience {
		t.Errorf("Audience = %q, want %q", parsed.Audience, originalWPT.Audience)
	}
	if parsed.HTM != originalWPT.HTM {
		t.Errorf("HTM = %q, want %q", parsed.HTM, originalWPT.HTM)
	}
	if parsed.HTU != originalWPT.HTU {
		t.Errorf("HTU = %q, want %q", parsed.HTU, originalWPT.HTU)
	}
	if parsed.JWTID != originalWPT.JWTID {
		t.Errorf("JWTID = %q, want %q", parsed.JWTID, originalWPT.JWTID)
	}
	if parsed.Nonce != originalWPT.Nonce {
		t.Errorf("Nonce = %q, want %q", parsed.Nonce, originalWPT.Nonce)
	}
	if parsed.ATH != originalWPT.ATH {
		t.Errorf("ATH = %q, want %q", parsed.ATH, originalWPT.ATH)
	}
}

func TestParseWPT_InvalidToken(t *testing.T) {
	_, err := ParseWPT("not-a-valid-jwt")
	if err == nil {
		t.Error("ParseWPT() should return error for invalid token")
	}
}

func TestParseWPT_WrongTypHeader(t *testing.T) {
	// Create a WIT and try to parse it as WPT
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")
	wit := NewWIT(spiffeID, []string{"https://api.example.com"}, 1*time.Hour)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	signed, err := wit.Sign(privateKey, "test-key-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Try to parse WIT as WPT - should fail due to typ mismatch
	_, err = ParseWPT(signed)
	if err == nil {
		t.Error("ParseWPT() should return error for WIT token")
	}
}

func TestWPTVerifier_Verify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	wpt := NewWPT("spiffe://example.com/agent/test", "https://api.example.com", "POST", "/api/v1/resource")
	signed, err := wpt.Sign(privateKey, "test-key-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := NewWPTVerifier(&privateKey.PublicKey)
	verified, err := verifier.Verify(signed)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if verified.Issuer != wpt.Issuer {
		t.Errorf("Issuer = %q, want %q", verified.Issuer, wpt.Issuer)
	}
	if verified.HTM != wpt.HTM {
		t.Errorf("HTM = %q, want %q", verified.HTM, wpt.HTM)
	}
}

func TestWPTVerifier_VerifyWithExpectedIssuer(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	wpt := NewWPT("spiffe://example.com/agent/test", "https://api.example.com", "POST", "/api/v1/resource")
	signed, err := wpt.Sign(privateKey, "test-key-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify with correct issuer
	verifier := NewWPTVerifier(&privateKey.PublicKey).
		WithExpectedIssuer("spiffe://example.com/agent/test")
	_, err = verifier.Verify(signed)
	if err != nil {
		t.Errorf("Verify() with correct issuer error = %v", err)
	}

	// Verify with wrong issuer should fail
	verifier = NewWPTVerifier(&privateKey.PublicKey).
		WithExpectedIssuer("spiffe://wrong.com/agent/other")
	_, err = verifier.Verify(signed)
	if err == nil {
		t.Error("Verify() should fail with wrong issuer")
	}
}

func TestWPTVerifier_VerifyRequest(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	wpt := NewWPT("spiffe://example.com/agent/test", "https://api.example.com", "POST", "/api/v1/resource")
	signed, err := wpt.Sign(privateKey, "test-key-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := NewWPTVerifier(&privateKey.PublicKey)

	// Test matching request
	matchingReq, _ := http.NewRequest("POST", "https://api.example.com/api/v1/resource", nil)
	_, err = verifier.VerifyRequest(signed, matchingReq)
	if err != nil {
		t.Errorf("VerifyRequest() with matching request error = %v", err)
	}

	// Test non-matching request (wrong method)
	wrongMethodReq, _ := http.NewRequest("GET", "https://api.example.com/api/v1/resource", nil)
	_, err = verifier.VerifyRequest(signed, wrongMethodReq)
	if err == nil {
		t.Error("VerifyRequest() should fail with wrong method")
	}

	// Test non-matching request (wrong path)
	wrongPathReq, _ := http.NewRequest("POST", "https://api.example.com/api/v2/different", nil)
	_, err = verifier.VerifyRequest(signed, wrongPathReq)
	if err == nil {
		t.Error("VerifyRequest() should fail with wrong path")
	}
}

func TestWPTVerifier_VerifyExpired(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create expired WPT
	wpt := &WIMSEProofToken{
		Issuer:   "spiffe://example.com/agent/test",
		Audience: "https://api.example.com",
		HTM:      "POST",
		HTU:      "/api/v1/resource",
		IssuedAt: time.Now().Add(-10 * time.Minute),
		Expiry:   time.Now().Add(-5 * time.Minute),
		JWTID:    GenerateJTI(),
	}
	signed, err := wpt.Sign(privateKey, "test-key-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := NewWPTVerifier(&privateKey.PublicKey)
	_, err = verifier.Verify(signed)
	if err != ErrWPTExpired {
		t.Errorf("Verify() error = %v, want ErrWPTExpired", err)
	}
}

func TestWPTVerifier_VerifyWrongKey(t *testing.T) {
	privateKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	wpt := NewWPT("spiffe://example.com/agent/test", "https://api.example.com", "POST", "/api/v1/resource")
	signed, _ := wpt.Sign(privateKey1, "test-key-1")

	// Verify with wrong public key should fail
	verifier := NewWPTVerifier(&privateKey2.PublicKey)
	_, err := verifier.Verify(signed)
	if err == nil {
		t.Error("Verify() should fail with wrong key")
	}
}
