package authzserver

// TokenExchangeRequest represents an RFC 8693 token exchange request.
type TokenExchangeRequest struct {
	GrantType          string `json:"grant_type"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	ActorToken         string `json:"actor_token,omitempty"`
	ActorTokenType     string `json:"actor_token_type,omitempty"`
	RequestedTokenType string `json:"requested_token_type,omitempty"`
	Audience           string `json:"audience,omitempty"`
	Scope              string `json:"scope,omitempty"`
	Resource           string `json:"resource,omitempty"`
}

// TokenResponse is returned when a token is issued.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

// ErrorResponse represents an OAuth-style error response.
type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// PolicyDecision represents the result of scope policy evaluation.
type PolicyDecision struct {
	// Protocol indicates which protocol to use: "idjag" for automated, "aauth" for human consent
	Protocol string `json:"protocol"`

	// InteractionType indicates the required interaction level (for AAuth)
	InteractionType string `json:"interaction_type,omitempty"`

	// AllowedScopes is the list of scopes that can be automatically approved
	AllowedScopes []string `json:"allowed_scopes,omitempty"`

	// RequiredConsentScopes are scopes that require human consent
	RequiredConsentScopes []string `json:"required_consent_scopes,omitempty"`

	// Reason provides context for the decision
	Reason string `json:"reason,omitempty"`
}

// IntrospectionResponse is returned for token introspection.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`

	// Actor chain for delegation tokens
	Act map[string]any `json:"act,omitempty"`
}
