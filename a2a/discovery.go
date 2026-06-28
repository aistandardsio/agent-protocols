package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DiscoveryClient discovers agents via their Agent Cards.
type DiscoveryClient struct {
	httpClient *http.Client
	headers    http.Header
}

// DiscoveryOption configures the DiscoveryClient.
type DiscoveryOption func(*DiscoveryClient)

// NewDiscoveryClient creates a new agent discovery client.
func NewDiscoveryClient(opts ...DiscoveryOption) *DiscoveryClient {
	c := &DiscoveryClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		headers:    make(http.Header),
	}

	c.headers.Set("Accept", "application/json")

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithDiscoveryHTTPClient sets a custom HTTP client.
func WithDiscoveryHTTPClient(client *http.Client) DiscoveryOption {
	return func(c *DiscoveryClient) {
		c.httpClient = client
	}
}

// DiscoverAgent fetches an Agent Card from the given base URL.
// The URL should be the agent's base URL (e.g., "https://agent.example.com").
// The client will fetch /.well-known/agent.json from this URL.
func (c *DiscoveryClient) DiscoverAgent(ctx context.Context, baseURL string) (*AgentCard, error) {
	url := strings.TrimSuffix(baseURL, "/") + WellKnownPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	for key, values := range c.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch agent card: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrAgentNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var card AgentCard
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		return nil, fmt.Errorf("decode agent card: %w", err)
	}

	return &card, nil
}

// DiscoverAgentByURL fetches an Agent Card from a full URL.
// Use this when you have the complete URL to the agent card.
func (c *DiscoveryClient) DiscoverAgentByURL(ctx context.Context, url string) (*AgentCard, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	for key, values := range c.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch agent card: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrAgentNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var card AgentCard
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		return nil, fmt.Errorf("decode agent card: %w", err)
	}

	return &card, nil
}

// HasCapability checks if an agent card has a specific capability.
func HasCapability(card *AgentCard, capabilityID string) bool {
	for _, cap := range card.Capabilities {
		if cap.ID == capabilityID {
			return true
		}
	}
	return false
}

// GetCapability returns a capability by ID, or nil if not found.
func GetCapability(card *AgentCard, capabilityID string) *Capability {
	for i := range card.Capabilities {
		if card.Capabilities[i].ID == capabilityID {
			return &card.Capabilities[i]
		}
	}
	return nil
}

// SupportsAuthentication checks if the agent supports a specific auth type.
func SupportsAuthentication(card *AgentCard, authType string) bool {
	if card.Authentication == nil {
		return authType == "none"
	}
	return card.Authentication.Type == authType
}
