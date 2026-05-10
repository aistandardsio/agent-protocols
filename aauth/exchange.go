package aauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// TokenExchangeRequest represents a token exchange request per RFC 8693.
type TokenExchangeRequest struct {
	// GrantType must be "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantType string `json:"grant_type"`

	// SubjectToken is the token being exchanged (agent token or resource token)
	SubjectToken string `json:"subject_token"`

	// SubjectTokenType identifies the type of subject_token
	SubjectTokenType string `json:"subject_token_type"`

	// ActorToken is the token representing the acting party (optional)
	ActorToken string `json:"actor_token,omitempty"`

	// ActorTokenType identifies the type of actor_token
	ActorTokenType string `json:"actor_token_type,omitempty"`

	// RequestedTokenType is the type of token being requested
	RequestedTokenType string `json:"requested_token_type,omitempty"`

	// Audience is the logical name of the target service
	Audience []string `json:"audience,omitempty"`

	// Scope is the desired scope of the requested token
	Scope string `json:"scope,omitempty"`

	// Resource is the URI of the target service or resource
	Resource []string `json:"resource,omitempty"`
}

// ParseTokenExchangeRequest parses a token exchange request from form values.
func ParseTokenExchangeRequest(r *http.Request) (*TokenExchangeRequest, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("%w: failed to parse form: %v", ErrInvalidRequest, err)
	}

	req := &TokenExchangeRequest{
		GrantType:          r.FormValue("grant_type"),
		SubjectToken:       r.FormValue("subject_token"),
		SubjectTokenType:   r.FormValue("subject_token_type"),
		ActorToken:         r.FormValue("actor_token"),
		ActorTokenType:     r.FormValue("actor_token_type"),
		RequestedTokenType: r.FormValue("requested_token_type"),
		Scope:              r.FormValue("scope"),
	}

	// Handle audience (can be multiple values)
	if audience := r.Form["audience"]; len(audience) > 0 {
		req.Audience = audience
	}

	// Handle resource (can be multiple values)
	if resource := r.Form["resource"]; len(resource) > 0 {
		req.Resource = resource
	}

	return req, nil
}

// Validate validates the token exchange request.
func (r *TokenExchangeRequest) Validate() error {
	if r.GrantType != GrantTypeTokenExchange {
		return fmt.Errorf("%w: invalid grant_type", ErrInvalidGrant)
	}

	if r.SubjectToken == "" {
		return fmt.Errorf("%w: subject_token is required", ErrInvalidRequest)
	}

	if r.SubjectTokenType == "" {
		return fmt.Errorf("%w: subject_token_type is required", ErrInvalidRequest)
	}

	// Validate token types
	validSubjectTypes := map[string]bool{
		TokenTypeURIAgentJWT:    true,
		TokenTypeURIResourceJWT: true,
	}
	if !validSubjectTypes[r.SubjectTokenType] {
		return fmt.Errorf("%w: invalid subject_token_type", ErrInvalidRequest)
	}

	if r.ActorToken != "" && r.ActorTokenType == "" {
		return fmt.Errorf("%w: actor_token_type is required when actor_token is provided", ErrInvalidRequest)
	}

	return nil
}

// ToFormValues converts the request to URL form values.
func (r *TokenExchangeRequest) ToFormValues() url.Values {
	v := url.Values{}
	v.Set("grant_type", r.GrantType)
	v.Set("subject_token", r.SubjectToken)
	v.Set("subject_token_type", r.SubjectTokenType)

	if r.ActorToken != "" {
		v.Set("actor_token", r.ActorToken)
		v.Set("actor_token_type", r.ActorTokenType)
	}

	if r.RequestedTokenType != "" {
		v.Set("requested_token_type", r.RequestedTokenType)
	}

	for _, aud := range r.Audience {
		v.Add("audience", aud)
	}

	if r.Scope != "" {
		v.Set("scope", r.Scope)
	}

	for _, res := range r.Resource {
		v.Add("resource", res)
	}

	return v
}

// TokenExchangeResponse represents a successful token exchange response.
type TokenExchangeResponse struct {
	// AccessToken is the issued token
	AccessToken string `json:"access_token"`

	// IssuedTokenType identifies the type of the issued token
	IssuedTokenType string `json:"issued_token_type"`

	// TokenType is the token type (usually "Bearer")
	TokenType string `json:"token_type"`

	// ExpiresIn is the lifetime in seconds
	ExpiresIn int `json:"expires_in,omitempty"`

	// Scope is the granted scope
	Scope string `json:"scope,omitempty"`

	// RefreshToken is an optional refresh token
	RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenExchangeContext holds the validated context for a token exchange.
type TokenExchangeContext struct {
	// Request is the original exchange request
	Request *TokenExchangeRequest

	// AgentToken is the verified agent token (if subject is agent token)
	AgentToken *AgentToken

	// ResourceToken is the verified resource token (if present)
	ResourceToken *ResourceToken

	// ActorToken is the verified actor token (if present)
	ActorToken *AgentToken

	// AgentID is the agent's identity
	AgentID *AAuthID

	// AgentCNF is the agent's confirmation claim
	AgentCNF *CNF
}

// ExchangeFlowType identifies the type of token exchange flow.
type ExchangeFlowType string

// Supported exchange flow types.
const (
	// FlowResourceManaged is when the resource provides a resource token
	FlowResourceManaged ExchangeFlowType = "resource_managed"

	// FlowPSAsserted is when only the agent token is provided
	FlowPSAsserted ExchangeFlowType = "ps_asserted"

	// FlowDelegation is when there's an actor token for delegation
	FlowDelegation ExchangeFlowType = "delegation"
)

// DetermineFlowType determines the exchange flow type from the request.
func DetermineFlowType(req *TokenExchangeRequest) ExchangeFlowType {
	if req.ActorToken != "" {
		return FlowDelegation
	}
	if req.SubjectTokenType == TokenTypeURIResourceJWT {
		return FlowResourceManaged
	}
	return FlowPSAsserted
}

// NewResourceManagedExchangeRequest creates a token exchange request for
// the resource-managed flow (agent has a resource token).
func NewResourceManagedExchangeRequest(resourceToken string, audience []string, scope string) *TokenExchangeRequest {
	return &TokenExchangeRequest{
		GrantType:          GrantTypeTokenExchange,
		SubjectToken:       resourceToken,
		SubjectTokenType:   TokenTypeURIResourceJWT,
		RequestedTokenType: TokenTypeURIAuthJWT,
		Audience:           audience,
		Scope:              scope,
	}
}

// NewPSAssertedExchangeRequest creates a token exchange request for
// the PS-asserted flow (agent presents only its identity).
func NewPSAssertedExchangeRequest(agentToken string, audience []string, scope string) *TokenExchangeRequest {
	return &TokenExchangeRequest{
		GrantType:          GrantTypeTokenExchange,
		SubjectToken:       agentToken,
		SubjectTokenType:   TokenTypeURIAgentJWT,
		RequestedTokenType: TokenTypeURIAuthJWT,
		Audience:           audience,
		Scope:              scope,
	}
}

// NewDelegationExchangeRequest creates a token exchange request for
// the delegation flow (human delegating to agent).
func NewDelegationExchangeRequest(humanToken, agentToken string, audience []string, scope string) *TokenExchangeRequest {
	return &TokenExchangeRequest{
		GrantType:          GrantTypeTokenExchange,
		SubjectToken:       humanToken,
		SubjectTokenType:   TokenTypeURIAgentJWT,
		ActorToken:         agentToken,
		ActorTokenType:     TokenTypeURIAgentJWT,
		RequestedTokenType: TokenTypeURIAuthJWT,
		Audience:           audience,
		Scope:              scope,
	}
}

// ExchangeClient performs token exchange requests against an auth server.
type ExchangeClient struct {
	tokenEndpoint string
	httpClient    *http.Client
}

// NewExchangeClient creates a new token exchange client.
func NewExchangeClient(tokenEndpoint string, httpClient *http.Client) *ExchangeClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &ExchangeClient{
		tokenEndpoint: tokenEndpoint,
		httpClient:    httpClient,
	}
}

// Exchange performs a token exchange and returns the response.
func (c *ExchangeClient) Exchange(req *TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", c.tokenEndpoint, strings.NewReader(req.ToFormValues().Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("%w: %s", ErrInvalidGrant, errResp.ErrorDescription)
	}

	var tokenResp TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

// ExchangeWithAgent performs a token exchange using an Agent for request signing.
func (c *ExchangeClient) ExchangeWithAgent(agent *Agent, req *TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", c.tokenEndpoint, strings.NewReader(req.ToFormValues().Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Sign the request with the agent
	if err := agent.SignRequest(httpReq); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("%w: %s", ErrInvalidGrant, errResp.ErrorDescription)
	}

	var tokenResp TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}
