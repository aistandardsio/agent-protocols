package aauth

import (
	"context"
	"testing"
)

func TestDelegationChain(t *testing.T) {
	t.Run("ParseDelegationChain", func(t *testing.T) {
		// Create a nested delegation: human -> agent1 -> agent2
		act := &Actor{
			Subject: "aauth:agent2@example.com",
			Issuer:  "https://example.com",
			Actor: &Actor{
				Subject: "aauth:agent1@example.com",
				Issuer:  "https://example.com",
				Actor: &Actor{
					Subject: "user@example.com",
					Issuer:  "https://idp.example.com",
				},
			},
		}

		chain := ParseDelegationChain(act)
		if chain == nil {
			t.Fatal("expected chain, got nil")
		}

		if chain.Original.Subject != "user@example.com" {
			t.Errorf("unexpected original: %s", chain.Original.Subject)
		}

		if chain.Depth() != 2 {
			t.Errorf("unexpected depth: %d, want 2", chain.Depth())
		}

		if chain.CurrentActor().Subject != "aauth:agent2@example.com" {
			t.Errorf("unexpected current actor: %s", chain.CurrentActor().Subject)
		}

		actors := chain.AllActors()
		if len(actors) != 3 {
			t.Errorf("unexpected actor count: %d, want 3", len(actors))
		}
	})

	t.Run("ParseDelegationChain single actor", func(t *testing.T) {
		act := &Actor{
			Subject: "aauth:agent@example.com",
			Issuer:  "https://example.com",
		}

		chain := ParseDelegationChain(act)
		if chain == nil {
			t.Fatal("expected chain, got nil")
		}

		if chain.Depth() != 0 {
			t.Errorf("unexpected depth: %d, want 0", chain.Depth())
		}

		if chain.Original.Subject != "aauth:agent@example.com" {
			t.Errorf("unexpected original: %s", chain.Original.Subject)
		}
	})

	t.Run("ParseDelegationChain nil", func(t *testing.T) {
		chain := ParseDelegationChain(nil)
		if chain != nil {
			t.Error("expected nil chain")
		}
	})
}

func TestValidateDelegationChain(t *testing.T) {
	t.Run("Valid chain", func(t *testing.T) {
		chain := &DelegationChain{
			Original: &Actor{Subject: "user@example.com"},
			Chain: []*Actor{
				{Subject: "aauth:agent1@example.com"},
				{Subject: "aauth:agent2@example.com"},
			},
		}

		err := ValidateDelegationChain(chain, 5)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Chain too deep", func(t *testing.T) {
		chain := &DelegationChain{
			Original: &Actor{Subject: "user@example.com"},
			Chain: []*Actor{
				{Subject: "agent1"},
				{Subject: "agent2"},
				{Subject: "agent3"},
			},
		}

		err := ValidateDelegationChain(chain, 2)
		if err == nil {
			t.Error("expected error for chain too deep")
		}
		if err != nil && !containsError(err, ErrDelegationChainTooDeep) {
			t.Errorf("unexpected error type: %v", err)
		}
	})

	t.Run("Missing subject", func(t *testing.T) {
		chain := &DelegationChain{
			Original: &Actor{Subject: "user@example.com"},
			Chain: []*Actor{
				{Subject: ""}, // Missing subject
			},
		}

		err := ValidateDelegationChain(chain, 5)
		if err == nil {
			t.Error("expected error for missing subject")
		}
	})

	t.Run("Nil chain", func(t *testing.T) {
		err := ValidateDelegationChain(nil, 5)
		if err != nil {
			t.Errorf("unexpected error for nil chain: %v", err)
		}
	})
}

func TestExtendChain(t *testing.T) {
	original := &Actor{
		Subject: "aauth:agent1@example.com",
		Issuer:  "https://example.com",
	}

	extended := ExtendChain(original, "aauth:agent2@example.com", "https://example.com")

	if extended.Subject != "aauth:agent2@example.com" {
		t.Errorf("unexpected subject: %s", extended.Subject)
	}
	if extended.Actor != original {
		t.Error("expected nested actor to be original")
	}
}

func TestFlattenChain(t *testing.T) {
	act := &Actor{
		Subject: "agent3",
		Actor: &Actor{
			Subject: "agent2",
			Actor: &Actor{
				Subject: "agent1",
			},
		},
	}

	subjects := FlattenChain(act)
	if len(subjects) != 3 {
		t.Errorf("unexpected length: %d", len(subjects))
	}

	expected := []string{"agent1", "agent2", "agent3"}
	for i, s := range subjects {
		if s != expected[i] {
			t.Errorf("unexpected subject at %d: %s, want %s", i, s, expected[i])
		}
	}
}

func TestDelegationRouter(t *testing.T) {
	t.Run("AddRoute and GetRoute", func(t *testing.T) {
		router := NewDelegationRouter()

		route := &DelegationRoute{
			Pattern:     "/api/*",
			TargetAgent: "aauth:api-agent@example.com",
			TargetURL:   "https://api-agent.example.com",
			Scopes:      []string{"read", "write"},
		}

		router.AddRoute("api", route)

		retrieved := router.GetRoute("api")
		if retrieved == nil {
			t.Fatal("expected route, got nil")
		}
		if retrieved.TargetAgent != route.TargetAgent {
			t.Errorf("unexpected target agent: %s", retrieved.TargetAgent)
		}
	})

	t.Run("FindRoute", func(t *testing.T) {
		router := NewDelegationRouter()

		router.AddRoute("api", &DelegationRoute{
			Pattern:     "/api/*",
			TargetAgent: "api-agent",
		})
		router.AddRoute("data", &DelegationRoute{
			Pattern:     "/data/**",
			TargetAgent: "data-agent",
		})

		// Test wildcard match
		route := router.FindRoute("/api/users")
		if route == nil || route.TargetAgent != "api-agent" {
			t.Error("expected api route match")
		}

		// Test exact match
		router.AddRoute("exact", &DelegationRoute{
			Pattern:     "/exact/path",
			TargetAgent: "exact-agent",
		})
		route = router.FindRoute("/exact/path")
		if route == nil || route.TargetAgent != "exact-agent" {
			t.Error("expected exact route match")
		}

		// Test no match
		route = router.FindRoute("/nomatch/path")
		if route != nil {
			t.Error("expected no match")
		}
	})

	t.Run("RemoveRoute", func(t *testing.T) {
		router := NewDelegationRouter()
		router.AddRoute("test", &DelegationRoute{Pattern: "/test"})

		router.RemoveRoute("test")

		if router.GetRoute("test") != nil {
			t.Error("expected route to be removed")
		}
	})
}

func TestDelegationValidator(t *testing.T) {
	t.Run("Validate with allowed delegates", func(t *testing.T) {
		validator := NewDelegationValidator(5)
		validator.AllowDelegate("user@example.com", "agent1@example.com")
		validator.AllowDelegate("agent1@example.com", "agent2@example.com")

		chain := &DelegationChain{
			Original: &Actor{Subject: "user@example.com"},
			Chain: []*Actor{
				{Subject: "agent1@example.com"},
				{Subject: "agent2@example.com"},
			},
		}

		ctx := context.Background()
		err := validator.Validate(ctx, chain)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Validate with unauthorized delegate", func(t *testing.T) {
		validator := NewDelegationValidator(5)
		validator.AllowDelegate("user@example.com", "agent1@example.com")
		// agent2 is not allowed

		chain := &DelegationChain{
			Original: &Actor{Subject: "user@example.com"},
			Chain: []*Actor{
				{Subject: "agent1@example.com"},
				{Subject: "agent2@example.com"},
			},
		}

		ctx := context.Background()
		err := validator.Validate(ctx, chain)
		if err == nil {
			t.Error("expected error for unauthorized delegate")
		}
	})

	t.Run("AllowAllDelegates", func(t *testing.T) {
		validator := NewDelegationValidator(5)
		validator.AllowAllDelegates("user@example.com")

		chain := &DelegationChain{
			Original: &Actor{Subject: "user@example.com"},
			Chain: []*Actor{
				{Subject: "any-agent@example.com"},
			},
		}

		ctx := context.Background()
		err := validator.Validate(ctx, chain)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func containsError(err, target error) bool {
	if err == nil {
		return target == nil
	}
	return err.Error() == target.Error() || (err != nil && target != nil && err.Error()[:len(target.Error())] == target.Error())
}
