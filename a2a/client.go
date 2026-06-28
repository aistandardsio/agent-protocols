package a2a

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

// Client invokes agent capabilities.
type Client struct {
	httpClient *http.Client
	headers    http.Header
	agentCard  *AgentCard
}

// ClientOption configures the Client.
type ClientOption func(*Client)

// NewClient creates a new A2A client for the given agent.
func NewClient(card *AgentCard, opts ...ClientOption) (*Client, error) {
	if card == nil {
		return nil, fmt.Errorf("agent card is required")
	}
	if card.Endpoints == nil || card.Endpoints.Invoke == "" {
		return nil, fmt.Errorf("agent card missing invoke endpoint")
	}

	c := &Client{
		httpClient: &http.Client{Timeout: 5 * time.Minute},
		headers:    make(http.Header),
		agentCard:  card,
	}

	c.headers.Set("Content-Type", "application/json")
	c.headers.Set("Accept", "application/json")

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// WithClientHTTPClient sets a custom HTTP client.
func WithClientHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithClientBearerToken sets a bearer token for authentication.
func WithClientBearerToken(token string) ClientOption {
	return func(c *Client) {
		c.headers.Set("Authorization", "Bearer "+token)
	}
}

// WithDelegationToken sets a delegation token for agent-to-agent calls.
func WithDelegationToken(token *DelegationToken) ClientOption {
	return func(c *Client) {
		c.headers.Set("Authorization", token.TokenType+" "+token.Token)
	}
}

// WithClientHeader adds a custom header.
func WithClientHeader(key, value string) ClientOption {
	return func(c *Client) {
		c.headers.Set(key, value)
	}
}

// Invoke invokes an agent capability.
func (c *Client) Invoke(ctx context.Context, req *TaskRequest) (*TaskResponse, error) {
	// Validate capability exists
	if !HasCapability(c.agentCard, req.CapabilityID) {
		return nil, fmt.Errorf("capability %q not found in agent card", req.CapabilityID)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.agentCard.Endpoints.Invoke, bytes.NewReader(body))
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
		return nil, fmt.Errorf("invoke request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("invoke failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var taskResp TaskResponse
	if err := json.Unmarshal(respBody, &taskResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &taskResp, nil
}

// GetStatus checks the status of a task.
func (c *Client) GetStatus(ctx context.Context, taskID string) (*TaskStatusResponse, error) {
	if c.agentCard.Endpoints.Status == "" {
		return nil, fmt.Errorf("agent card missing status endpoint")
	}

	url := strings.ReplaceAll(c.agentCard.Endpoints.Status, "{task_id}", taskID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
		return nil, fmt.Errorf("status request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status check failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var statusResp TaskStatusResponse
	if err := json.Unmarshal(respBody, &statusResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &statusResp, nil
}

// Cancel cancels a running task.
func (c *Client) Cancel(ctx context.Context, taskID string) error {
	if c.agentCard.Endpoints.Cancel == "" {
		return fmt.Errorf("agent card missing cancel endpoint")
	}

	url := strings.ReplaceAll(c.agentCard.Endpoints.Cancel, "{task_id}", taskID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	for key, values := range c.headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("cancel request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cancel failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// InvokeAndWait invokes a capability and waits for completion.
func (c *Client) InvokeAndWait(ctx context.Context, req *TaskRequest, pollInterval time.Duration) (*TaskStatusResponse, error) {
	taskResp, err := c.Invoke(ctx, req)
	if err != nil {
		return nil, err
	}

	// If completed synchronously
	if taskResp.Status == TaskStatusCompleted {
		return &TaskStatusResponse{
			TaskID: taskResp.TaskID,
			Status: taskResp.Status,
			Output: taskResp.Output,
		}, nil
	}

	if taskResp.Status == TaskStatusFailed {
		return &TaskStatusResponse{
			TaskID: taskResp.TaskID,
			Status: taskResp.Status,
			Error:  taskResp.Error,
		}, nil
	}

	// Poll for completion
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			status, err := c.GetStatus(ctx, taskResp.TaskID)
			if err != nil {
				return nil, fmt.Errorf("get status: %w", err)
			}

			if status.Status.IsTerminal() {
				return status, nil
			}
		}
	}
}

// AgentCard returns the agent card this client is configured for.
func (c *Client) AgentCard() *AgentCard {
	return c.agentCard
}
