package authzen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is an AuthZEN PDP client.
type Client struct {
	// BaseURL is the PDP base URL (e.g., "https://pdp.example.com").
	baseURL string

	// httpClient is the HTTP client used for requests.
	httpClient *http.Client

	// headers contains default headers for all requests.
	headers http.Header

	// evaluationPath is the path to the evaluation endpoint.
	evaluationPath string

	// batchEvaluationPath is the path to the batch evaluation endpoint.
	batchEvaluationPath string
}

// ClientOption configures the Client.
type ClientOption func(*Client)

// NewClient creates a new AuthZEN PDP client.
func NewClient(baseURL string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL:             strings.TrimSuffix(baseURL, "/"),
		httpClient:          &http.Client{Timeout: 30 * time.Second},
		headers:             make(http.Header),
		evaluationPath:      "/access/v1/evaluation",
		batchEvaluationPath: "/access/v1/evaluations",
	}

	// Set default headers
	c.headers.Set("Content-Type", "application/json")
	c.headers.Set("Accept", "application/json")

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithBearerToken sets a bearer token for authentication.
func WithBearerToken(token string) ClientOption {
	return func(c *Client) {
		c.headers.Set("Authorization", "Bearer "+token)
	}
}

// WithHeader adds a custom header to all requests.
func WithHeader(key, value string) ClientOption {
	return func(c *Client) {
		c.headers.Set(key, value)
	}
}

// WithEvaluationPath sets a custom evaluation endpoint path.
func WithEvaluationPath(path string) ClientOption {
	return func(c *Client) {
		c.evaluationPath = path
	}
}

// doPost sends a POST request and returns the response body.
func (c *Client) doPost(ctx context.Context, path string, reqBody any) ([]byte, error) {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	for key, values := range c.headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Code != "" {
			return nil, &errResp
		}
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// Evaluate sends an evaluation request to the PDP.
func (c *Client) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
	respBody, err := c.doPost(ctx, c.evaluationPath, req)
	if err != nil {
		return nil, err
	}

	var evalResp EvaluationResponse
	if err := json.Unmarshal(respBody, &evalResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &evalResp, nil
}

// EvaluateBatch sends multiple evaluation requests to the PDP.
func (c *Client) EvaluateBatch(ctx context.Context, req *BatchEvaluationRequest) (*BatchEvaluationResponse, error) {
	respBody, err := c.doPost(ctx, c.batchEvaluationPath, req)
	if err != nil {
		return nil, err
	}

	var batchResp BatchEvaluationResponse
	if err := json.Unmarshal(respBody, &batchResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &batchResp, nil
}

// IsAllowed is a convenience method that evaluates and returns true if permitted.
func (c *Client) IsAllowed(ctx context.Context, subject Subject, resource Resource, action Action) (bool, error) {
	resp, err := c.Evaluate(ctx, &EvaluationRequest{
		Subject:  subject,
		Resource: resource,
		Action:   action,
		Context:  NewContext(),
	})
	if err != nil {
		return false, err
	}
	return resp.Decision.IsAllowed(), nil
}

// IsAllowedWithContext evaluates with additional context.
func (c *Client) IsAllowedWithContext(ctx context.Context, subject Subject, resource Resource, action Action, evalContext Context) (bool, error) {
	resp, err := c.Evaluate(ctx, &EvaluationRequest{
		Subject:  subject,
		Resource: resource,
		Action:   action,
		Context:  evalContext,
	})
	if err != nil {
		return false, err
	}
	return resp.Decision.IsAllowed(), nil
}

// BaseURL returns the configured base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}
