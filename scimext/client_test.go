package scimext

import (
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "default options",
			opts:    nil,
			wantErr: false,
		},
		{
			name: "with base URL",
			opts: []Option{
				WithBaseURL("https://scim.example.com/v2"),
			},
			wantErr: false,
		},
		{
			name: "with bearer token",
			opts: []Option{
				WithBearerToken("test-token"),
			},
			wantErr: false,
		},
		{
			name: "with timeout",
			opts: []Option{
				WithTimeout(60 * time.Second),
			},
			wantErr: false,
		},
		{
			name: "with all options",
			opts: []Option{
				WithBaseURL("https://scim.example.com/v2"),
				WithBearerToken("test-token"),
				WithTimeout(60 * time.Second),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

func TestClientServices(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	t.Run("Agents service", func(t *testing.T) {
		if client.Agents() == nil {
			t.Error("Agents() returned nil")
		}
	})

	t.Run("Applications service", func(t *testing.T) {
		if client.Applications() == nil {
			t.Error("Applications() returned nil")
		}
	})

	t.Run("API client", func(t *testing.T) {
		if client.API() == nil {
			t.Error("API() returned nil")
		}
	})
}
