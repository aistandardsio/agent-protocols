package sharkauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateDelegationGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if r.URL.Path != "/grants/delegation" {
			t.Errorf("Expected /grants/delegation, got %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}

		if req["actor_subject"] != "agent:calendar-bot" {
			t.Errorf("actor_subject = %v, want agent:calendar-bot", req["actor_subject"])
		}

		grant := DelegationGrant{
			GrantID:      "grant-456",
			ActorSubject: "agent:calendar-bot",
			UserSubject:  "user:alice",
			Scopes:       []string{"calendar:read"},
			CreatedAt:    time.Now(),
			Active:       true,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(grant); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	grant, err := client.CreateDelegationGrant(context.Background(), DelegationGrantRequest{
		ActorSubject: "agent:calendar-bot",
		UserSubject:  "user:alice",
		Scopes:       []string{"calendar:read"},
		TTL:          24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateDelegationGrant() error = %v", err)
	}

	if grant.GrantID != "grant-456" {
		t.Errorf("GrantID = %v, want grant-456", grant.GrantID)
	}

	if !grant.Active {
		t.Error("Expected grant to be active")
	}
}

func TestGetDelegationGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET, got %s", r.Method)
		}

		if r.URL.Path != "/grants/delegation/grant-123" {
			t.Errorf("Expected /grants/delegation/grant-123, got %s", r.URL.Path)
		}

		grant := DelegationGrant{
			GrantID:      "grant-123",
			ActorSubject: "agent:bot",
			UserSubject:  "user:bob",
			Scopes:       []string{"read"},
			Active:       true,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(grant); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	grant, err := client.GetDelegationGrant(context.Background(), "grant-123")
	if err != nil {
		t.Fatalf("GetDelegationGrant() error = %v", err)
	}

	if grant.GrantID != "grant-123" {
		t.Errorf("GrantID = %v, want grant-123", grant.GrantID)
	}
}

func TestGetDelegationGrantNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	_, err := client.GetDelegationGrant(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("Expected error for nonexistent grant")
	}
}

func TestRevokeDelegationGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("Expected DELETE, got %s", r.Method)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	err := client.RevokeDelegationGrant(context.Background(), "grant-123")
	if err != nil {
		t.Fatalf("RevokeDelegationGrant() error = %v", err)
	}
}

func TestListDelegationGrants(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET, got %s", r.Method)
		}

		// Verify query parameters
		if r.URL.Query().Get("user_subject") != "user:alice" {
			t.Errorf("user_subject = %v, want user:alice", r.URL.Query().Get("user_subject"))
		}

		if r.URL.Query().Get("active") != "true" {
			t.Errorf("active = %v, want true", r.URL.Query().Get("active"))
		}

		grants := []*DelegationGrant{
			{GrantID: "grant-1", Active: true},
			{GrantID: "grant-2", Active: true},
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(grants); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)

	grants, err := client.ListDelegationGrants(context.Background(),
		WithUserSubject("user:alice"),
		WithActiveOnly(),
	)
	if err != nil {
		t.Fatalf("ListDelegationGrants() error = %v", err)
	}

	if len(grants) != 2 {
		t.Errorf("len(grants) = %v, want 2", len(grants))
	}
}
