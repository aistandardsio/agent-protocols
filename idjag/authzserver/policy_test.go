package authzserver

import (
	"context"
	"testing"
)

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		scope   string
		pattern string
		want    bool
	}{
		// Exact match
		{"read:email", "read:email", true},
		{"read:email", "read:profile", false},

		// Wildcard
		{"read:email", "read:*", true},
		{"read:profile", "read:*", true},
		{"write:email", "read:*", false},

		// Glob patterns
		{"api:users:read", "api:*:read", true},
		{"api:posts:read", "api:*:read", true},
		{"api:users:write", "api:*:read", false},

		// Edge cases
		{"", "", true},
		{"read", "read", true},
		{"read:email:inbox", "read:*", true}, // * matches any non-slash sequence (path.Match uses / as separator)
	}

	for _, tt := range tests {
		t.Run(tt.scope+"_"+tt.pattern, func(t *testing.T) {
			if got := matchesPattern(tt.scope, tt.pattern); got != tt.want {
				t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.scope, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestDefaultPolicyEvaluator_Evaluate(t *testing.T) {
	ctx := context.Background()
	store := NewMockStore()

	// Create policies
	_ = store.CreateScopePolicy(ctx, &ScopePolicy{
		ID:       "policy-1",
		Pattern:  "read:*",
		Protocol: "idjag",
		Priority: 100,
	})
	_ = store.CreateScopePolicy(ctx, &ScopePolicy{
		ID:              "policy-2",
		Pattern:         "write:*",
		Protocol:        "aauth",
		InteractionType: "supervised",
		Priority:        100,
	})

	evaluator := NewDefaultPolicyEvaluator(store)

	tests := []struct {
		name         string
		scopes       []string
		wantProtocol string
		wantAllowed  int
		wantConsent  int
	}{
		{
			name:         "all idjag scopes",
			scopes:       []string{"read:email", "read:profile"},
			wantProtocol: "idjag",
			wantAllowed:  2,
			wantConsent:  0,
		},
		{
			name:         "all aauth scopes",
			scopes:       []string{"write:email", "write:profile"},
			wantProtocol: "aauth",
			wantAllowed:  0,
			wantConsent:  2,
		},
		{
			name:         "mixed scopes - aauth wins",
			scopes:       []string{"read:email", "write:profile"},
			wantProtocol: "aauth",
			wantAllowed:  1,
			wantConsent:  1,
		},
		{
			name:         "unknown scope defaults to aauth",
			scopes:       []string{"admin:users"},
			wantProtocol: "aauth",
			wantAllowed:  0,
			wantConsent:  1,
		},
		{
			name:         "empty scopes",
			scopes:       []string{},
			wantProtocol: "aauth", // default
			wantAllowed:  0,
			wantConsent:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := evaluator.Evaluate(ctx, "agent-1", tt.scopes)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}
			if decision.Protocol != tt.wantProtocol {
				t.Errorf("Protocol = %v, want %v", decision.Protocol, tt.wantProtocol)
			}
			if len(decision.AllowedScopes) != tt.wantAllowed {
				t.Errorf("AllowedScopes count = %d, want %d", len(decision.AllowedScopes), tt.wantAllowed)
			}
			if len(decision.RequiredConsentScopes) != tt.wantConsent {
				t.Errorf("RequiredConsentScopes count = %d, want %d", len(decision.RequiredConsentScopes), tt.wantConsent)
			}
		})
	}
}

func TestStaticPolicyEvaluator_Evaluate(t *testing.T) {
	ctx := context.Background()

	evaluator := NewStaticPolicyEvaluator().
		WithIDJAGScopes("read:*", "chat:*").
		WithAAuthScopes("write:*", "admin:*")

	tests := []struct {
		name         string
		scopes       []string
		wantProtocol string
		wantAllowed  int
		wantConsent  int
	}{
		{
			name:         "idjag scopes",
			scopes:       []string{"read:email", "chat:message"},
			wantProtocol: "idjag",
			wantAllowed:  2,
			wantConsent:  0,
		},
		{
			name:         "aauth scopes",
			scopes:       []string{"write:profile", "admin:users"},
			wantProtocol: "aauth",
			wantAllowed:  0,
			wantConsent:  2,
		},
		{
			name:         "mixed scopes",
			scopes:       []string{"read:email", "write:profile"},
			wantProtocol: "aauth",
			wantAllowed:  1,
			wantConsent:  1,
		},
		{
			name:         "unknown scope uses default (aauth)",
			scopes:       []string{"custom:scope"},
			wantProtocol: "aauth",
			wantAllowed:  0,
			wantConsent:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := evaluator.Evaluate(ctx, "agent-1", tt.scopes)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}
			if decision.Protocol != tt.wantProtocol {
				t.Errorf("Protocol = %v, want %v", decision.Protocol, tt.wantProtocol)
			}
			if len(decision.AllowedScopes) != tt.wantAllowed {
				t.Errorf("AllowedScopes count = %d, want %d", len(decision.AllowedScopes), tt.wantAllowed)
			}
			if len(decision.RequiredConsentScopes) != tt.wantConsent {
				t.Errorf("RequiredConsentScopes count = %d, want %d", len(decision.RequiredConsentScopes), tt.wantConsent)
			}
		})
	}
}

func TestStaticPolicyEvaluator_WithDefaultProtocol(t *testing.T) {
	ctx := context.Background()

	// Test with idjag as default
	evaluator := NewStaticPolicyEvaluator().
		WithDefaultProtocol("idjag")

	decision, err := evaluator.Evaluate(ctx, "agent-1", []string{"unknown:scope"})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if decision.Protocol != "idjag" {
		t.Errorf("Protocol = %v, want idjag", decision.Protocol)
	}
	if len(decision.AllowedScopes) != 1 {
		t.Errorf("Expected 1 allowed scope, got %d", len(decision.AllowedScopes))
	}
}
