package personserver

// AuthorizationRequest is the request from an agent to authorize a mission.
type AuthorizationRequest struct {
	AgentToken      string `json:"agent_token"`
	UserID          string `json:"user_id"`
	Scopes          string `json:"scope"`
	MissionName     string `json:"mission_name,omitempty"`
	MissionDesc     string `json:"mission_description,omitempty"`
	InteractionType string `json:"interaction_type,omitempty"`
	Duration        int64  `json:"duration,omitempty"` // Seconds
	RedirectURI     string `json:"redirect_uri,omitempty"`
	State           string `json:"state,omitempty"`
}

// AuthorizationResponse is returned when authorization is requested.
type AuthorizationResponse struct {
	// For immediate approval (pre-authorized)
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`

	// For deferred consent
	ConsentURI string `json:"consent_uri,omitempty"`
	StatusURI  string `json:"status_uri,omitempty"`
	MissionID  string `json:"mission_id,omitempty"`
	Interval   int    `json:"interval,omitempty"`
}

// ConsentRequest represents a pending consent request shown to the user.
type ConsentRequest struct {
	MissionID   string   `json:"mission_id"`
	AgentID     string   `json:"agent_id"`
	AgentName   string   `json:"agent_name"`
	UserID      string   `json:"user_id"`
	UserName    string   `json:"user_name"`
	Scopes      []string `json:"scopes"`
	Description string   `json:"description"`
	Duration    string   `json:"duration"`
}

// ConsentStatusResponse is returned when polling for consent status.
type ConsentStatusResponse struct {
	Status      string `json:"status"` // pending, approved, denied, expired
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

// TokenRequest is the request to exchange an approval for a token.
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	MissionID    string `json:"mission_id,omitempty"`
	AgentToken   string `json:"agent_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenResponse is returned when a token is issued.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// ErrorResponse represents an OAuth-style error response.
type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// PreAuthorization allows users to pre-approve certain scopes for agents.
type PreAuthorization struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	AgentID   string `json:"agent_id"`
	Scopes    string `json:"scopes"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
}
