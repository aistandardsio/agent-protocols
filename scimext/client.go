package scimext

import (
	"context"
	"net/http"
	"time"

	"github.com/aistandardsio/agent-protocols/scimext/agents"
	"github.com/aistandardsio/agent-protocols/scimext/applications"
	"github.com/aistandardsio/agent-protocols/scimext/internal/api"
)

// Version is the SDK version.
const Version = "0.1.0"

// Client provides access to the SCIM Agent Extension API.
type Client struct {
	apiClient *api.Client
	baseURL   string

	// Domain services
	agentsSvc       *agents.Service
	applicationsSvc *applications.Service
}

// clientOptions holds configuration for the client.
type clientOptions struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
	token      string
}

// Option is a functional option for configuring the client.
type Option func(*clientOptions)

// WithBaseURL sets the base URL for the SCIM server.
func WithBaseURL(url string) Option {
	return func(o *clientOptions) {
		o.baseURL = url
	}
}

// WithHTTPClient sets the HTTP client to use for requests.
func WithHTTPClient(client *http.Client) Option {
	return func(o *clientOptions) {
		o.httpClient = client
	}
}

// WithTimeout sets the timeout for HTTP requests.
func WithTimeout(timeout time.Duration) Option {
	return func(o *clientOptions) {
		o.timeout = timeout
	}
}

// WithBearerToken sets the bearer token for authentication.
func WithBearerToken(token string) Option {
	return func(o *clientOptions) {
		o.token = token
	}
}

// NewClient creates a new SCIM Agent Extension client.
func NewClient(opts ...Option) (*Client, error) {
	options := &clientOptions{
		baseURL: "https://scim.example.com/v2",
		timeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(options)
	}

	httpClient := options.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: options.timeout,
		}
	}

	// Wrap HTTP client with auth headers
	authClient := &authHTTPClient{
		client: httpClient,
		token:  options.token,
	}

	// Create the security source
	secSource := &bearerTokenSource{token: options.token}

	// Create ogen client
	apiClient, err := api.NewClient(
		options.baseURL,
		secSource,
		api.WithClient(authClient),
	)
	if err != nil {
		return nil, err
	}

	c := &Client{
		apiClient: apiClient,
		baseURL:   options.baseURL,
	}

	// Initialize domain services
	c.agentsSvc = agents.New(apiClient)
	c.applicationsSvc = applications.New(apiClient)

	return c, nil
}

// Agents returns the agents service for managing Agent resources.
func (c *Client) Agents() *agents.Service {
	return c.agentsSvc
}

// Applications returns the applications service for managing AgenticApplication resources.
func (c *Client) Applications() *applications.Service {
	return c.applicationsSvc
}

// API returns the underlying ogen API client for advanced use cases.
func (c *Client) API() *api.Client {
	return c.apiClient
}

// authHTTPClient wraps an HTTP client to add authentication headers.
type authHTTPClient struct {
	client *http.Client
	token  string
}

// Do executes an HTTP request with authentication headers.
func (c *authHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("X-SCIM-SDK-Version", Version)
	req.Header.Set("X-SCIM-SDK-Lang", "go")
	return c.client.Do(req) //nolint:gosec // SSRF not applicable - client library
}

// bearerTokenSource implements api.SecuritySource for bearer token auth.
type bearerTokenSource struct {
	token string
}

// BearerAuth returns the bearer token.
func (s *bearerTokenSource) BearerAuth(_ context.Context, _ api.OperationName) (api.BearerAuth, error) {
	return api.BearerAuth{Token: s.token}, nil
}
