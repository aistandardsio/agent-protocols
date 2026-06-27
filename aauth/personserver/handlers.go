package personserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/golang-jwt/jwt/v5"
)

// ============================================================================
// Discovery Handlers
// ============================================================================

// HandleMetadata returns the server metadata (/.well-known/aauth-configuration).
func (s *Server) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]any{
		"issuer":                 s.issuer,
		"authorization_endpoint": s.issuer + "/authorize",
		"token_endpoint":         s.issuer + "/token",
		"revocation_endpoint":    s.issuer + "/revoke",
		"jwks_uri":               s.issuer + "/.well-known/jwks.json",
		"grant_types_supported": []string{
			"urn:ietf:params:oauth:grant-type:mission-approval",
		},
		"response_types_supported":              []string{"code", "token"},
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		s.logger.Error("failed to encode metadata", "error", err)
	}
}

// HandleJWKS returns the public key set (/.well-known/jwks.json).
func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk, err := aauth.PublicKeyToJWK(s.publicKey, s.keyID)
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "failed to generate JWK")
		return
	}

	jwks := map[string]any{
		"keys": []any{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		s.logger.Error("failed to encode jwks", "error", err)
	}
}

// ============================================================================
// Authorization Handlers
// ============================================================================

// HandleAuthorize handles authorization requests from agents (POST /authorize).
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req AuthorizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}

	// Validate required fields
	if req.UserID == "" {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "user_id is required")
		return
	}
	if req.Scopes == "" {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "scope is required")
		return
	}

	// Parse agent token to get agent ID
	agentID := s.extractAgentID(req.AgentToken)
	if agentID == "" {
		s.errorResponse(w, http.StatusUnauthorized, "invalid_token", "invalid or missing agent token")
		return
	}

	// Check if user exists
	user, err := s.store.GetUser(r.Context(), req.UserID)
	if err == ErrNotFound {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "user not found")
		return
	}
	if err != nil {
		s.logger.Error("failed to get user", "error", err)
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Check if agent exists (or create if first time)
	_, err = s.store.GetAgent(r.Context(), agentID)
	if err == ErrNotFound {
		// Auto-register agent
		newAgent := &Agent{
			ID:        agentID,
			Name:      agentID,
			PublicKey: "", // Would extract from agent token in real implementation
		}
		if err := s.store.CreateAgent(r.Context(), newAgent); err != nil {
			s.logger.Error("failed to create agent", "error", err)
		}
	} else if err != nil {
		s.logger.Error("failed to get agent", "error", err)
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Create mission for user approval
	mission := &Mission{
		AgentID:         agentID,
		UserID:          user.ID,
		Name:            req.MissionName,
		Description:     req.MissionDesc,
		Scopes:          req.Scopes,
		InteractionType: req.InteractionType,
		Duration:        req.Duration,
		Status:          MissionStatusPending,
	}

	if mission.Name == "" {
		mission.Name = "Authorization Request"
	}
	if mission.InteractionType == "" {
		mission.InteractionType = "supervised"
	}
	if mission.Duration == 0 {
		mission.Duration = int64(s.tokenTTL.Seconds())
	}

	if err := s.store.CreateMission(r.Context(), mission); err != nil {
		s.logger.Error("failed to create mission", "error", err)
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "failed to create mission")
		return
	}

	// Return 202 Accepted with consent URI
	resp := AuthorizationResponse{
		ConsentURI: s.issuer + "/consent/" + mission.ID,
		StatusURI:  s.issuer + "/consent/status/" + mission.ID,
		MissionID:  mission.ID,
		Interval:   s.pollInterval,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("failed to encode response", "error", err)
	}

	s.logger.Info("mission created",
		"mission_id", mission.ID,
		"agent_id", agentID,
		"user_id", user.ID,
		"scopes", req.Scopes)
}

// ============================================================================
// Consent Handlers
// ============================================================================

// HandleConsentPage renders the consent page for the user (GET /consent/{id}).
func (s *Server) HandleConsentPage(w http.ResponseWriter, r *http.Request) {
	missionID := r.PathValue("id")
	if missionID == "" {
		http.Error(w, "mission ID required", http.StatusBadRequest)
		return
	}

	mission, err := s.store.GetMission(r.Context(), missionID)
	if err == ErrNotFound {
		http.Error(w, "mission not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if mission.Status != MissionStatusPending {
		http.Error(w, "mission already processed", http.StatusGone)
		return
	}

	// Get agent and user info
	agent, _ := s.store.GetAgent(r.Context(), mission.AgentID)
	user, _ := s.store.GetUser(r.Context(), mission.UserID)

	agentName := mission.AgentID
	if agent != nil && agent.Name != "" {
		agentName = agent.Name
	}

	userName := mission.UserID
	if user != nil && user.Name != "" {
		userName = user.Name
	}

	// Format duration
	duration := time.Duration(mission.Duration) * time.Second
	durationStr := formatDuration(duration)

	data := ConsentRequest{
		MissionID:   mission.ID,
		AgentID:     mission.AgentID,
		AgentName:   agentName,
		UserID:      mission.UserID,
		UserName:    userName,
		Scopes:      splitScopes(mission.Scopes),
		Description: mission.Description,
		Duration:    durationStr,
	}

	w.Header().Set("Content-Type", "text/html")
	if err := s.templates.Execute(w, data); err != nil {
		s.logger.Error("failed to render template", "error", err)
	}
}

// HandleConsentSubmit handles the user's consent decision (POST /consent/{id}).
func (s *Server) HandleConsentSubmit(w http.ResponseWriter, r *http.Request) {
	missionID := r.PathValue("id")
	if missionID == "" {
		http.Error(w, "mission ID required", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	decision := r.FormValue("decision")

	mission, err := s.store.GetMission(r.Context(), missionID)
	if err == ErrNotFound {
		http.Error(w, "mission not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if mission.Status != MissionStatusPending {
		http.Error(w, "mission already processed", http.StatusGone)
		return
	}

	switch decision {
	case "approve":
		duration := time.Duration(mission.Duration) * time.Second
		if err := s.store.ApproveMission(r.Context(), missionID, duration); err != nil {
			s.logger.Error("failed to approve mission", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		s.logger.Info("mission approved", "mission_id", missionID)

	case "deny":
		reason := r.FormValue("reason")
		if err := s.store.DenyMission(r.Context(), missionID, reason); err != nil {
			s.logger.Error("failed to deny mission", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.logger.Info("mission denied", "mission_id", missionID, "reason", reason)

	default:
		http.Error(w, "invalid decision", http.StatusBadRequest)
		return
	}

	// Render success page
	w.Header().Set("Content-Type", "text/html")
	data := successData{Decision: decision}
	if decision == "approve" {
		data.Icon = "✓"
		data.Title = "Approved"
	} else {
		data.Icon = "✗"
		data.Title = "Denied"
	}
	if err := successTmpl.Execute(w, data); err != nil {
		s.logger.Error("failed to render success template", "error", err)
	}
}

// HandleConsentStatus returns the consent status for polling (GET /consent/status/{id}).
func (s *Server) HandleConsentStatus(w http.ResponseWriter, r *http.Request) {
	missionID := r.PathValue("id")
	if missionID == "" {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "mission_id required")
		return
	}

	mission, err := s.store.GetMission(r.Context(), missionID)
	if err == ErrNotFound {
		s.errorResponse(w, http.StatusNotFound, "invalid_request", "mission not found")
		return
	}
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	var resp ConsentStatusResponse

	switch mission.Status {
	case MissionStatusPending:
		// Check if expired
		if time.Since(mission.CreatedAt) > s.missionTimeout {
			// Mark as expired
			if err := s.store.DenyMission(r.Context(), missionID, "timeout"); err != nil {
				s.logger.Error("failed to expire mission", "error", err)
			}
			resp.Status = "expired"
			resp.Error = "consent_timeout"
			resp.ErrorDesc = "consent request timed out"
		} else {
			resp.Status = "pending"
		}

	case MissionStatusApproved:
		// Issue token
		token, err := s.issueToken(r.Context(), mission.AgentID, mission.UserID, mission.Scopes)
		if err != nil {
			s.logger.Error("failed to issue token", "error", err)
			s.errorResponse(w, http.StatusInternalServerError, "server_error", "failed to issue token")
			return
		}

		resp.Status = "approved"
		resp.AccessToken = token
		resp.TokenType = "Bearer"
		resp.ExpiresIn = int(s.tokenTTL.Seconds())
		resp.Scope = mission.Scopes

	case MissionStatusDenied:
		resp.Status = "denied"
		resp.Error = "access_denied"
		resp.ErrorDesc = mission.DenialReason

	case MissionStatusExpired:
		resp.Status = "expired"
		resp.Error = "consent_timeout"
		resp.ErrorDesc = "consent request expired"

	default:
		resp.Status = string(mission.Status)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("failed to encode response", "error", err)
	}
}

// ============================================================================
// Token Handlers
// ============================================================================

// HandleToken handles token requests (POST /token).
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "urn:ietf:params:oauth:grant-type:mission-approval":
		missionID := r.FormValue("mission_id")
		if missionID == "" {
			s.errorResponse(w, http.StatusBadRequest, "invalid_request", "mission_id required")
			return
		}

		mission, err := s.store.GetMission(r.Context(), missionID)
		if err == ErrNotFound {
			s.errorResponse(w, http.StatusBadRequest, "invalid_request", "mission not found")
			return
		}
		if err != nil {
			s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
			return
		}

		if mission.Status != MissionStatusApproved {
			s.errorResponse(w, http.StatusBadRequest, "access_denied", "mission not approved")
			return
		}

		token, err := s.issueToken(r.Context(), mission.AgentID, mission.UserID, mission.Scopes)
		if err != nil {
			s.logger.Error("failed to issue token", "error", err)
			s.errorResponse(w, http.StatusInternalServerError, "server_error", "failed to issue token")
			return
		}

		resp := TokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresIn:   int(s.tokenTTL.Seconds()),
			Scope:       mission.Scopes,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.logger.Error("failed to encode response", "error", err)
		}

	default:
		s.errorResponse(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type")
	}
}

// HandleRevoke handles token revocation (POST /revoke).
func (s *Server) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}

	tokenID := r.FormValue("token")
	if tokenID == "" {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "token required")
		return
	}

	if err := s.store.RevokeToken(r.Context(), tokenID); err != nil {
		s.logger.Error("failed to revoke token", "error", err)
		// Per RFC 7009, always return 200 for revocation
	}

	w.WriteHeader(http.StatusOK)
}

// ============================================================================
// Admin Handlers
// ============================================================================

// HandleListUsers lists all users (GET /admin/users).
func (s *Server) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(users); err != nil {
		s.logger.Error("failed to encode users", "error", err)
	}
}

// HandleCreateUser creates a new user (POST /admin/users).
func (s *Server) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}

	if err := s.store.CreateUser(r.Context(), &user); err != nil {
		if err == ErrAlreadyExists {
			s.errorResponse(w, http.StatusConflict, "already_exists", "user already exists")
			return
		}
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		s.logger.Error("failed to encode user", "error", err)
	}
}

// HandleListAgents lists all agents (GET /admin/agents).
func (s *Server) HandleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents(r.Context())
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(agents); err != nil {
		s.logger.Error("failed to encode agents", "error", err)
	}
}

// HandleCreateAgent creates a new agent (POST /admin/agents).
func (s *Server) HandleCreateAgent(w http.ResponseWriter, r *http.Request) {
	var agent Agent
	if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}

	if err := s.store.CreateAgent(r.Context(), &agent); err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(agent); err != nil {
		s.logger.Error("failed to encode agent", "error", err)
	}
}

// HandleListMissions lists pending missions (GET /admin/missions).
func (s *Server) HandleListMissions(w http.ResponseWriter, r *http.Request) {
	missions, err := s.store.ListPendingMissions(r.Context())
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(missions); err != nil {
		s.logger.Error("failed to encode missions", "error", err)
	}
}

// ============================================================================
// Helper methods
// ============================================================================

func (s *Server) issueToken(ctx context.Context, agentID, userID, scopes string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(s.tokenTTL)

	claims := jwt.MapClaims{
		"iss":   s.issuer,
		"sub":   agentID,
		"aud":   s.issuer,
		"iat":   now.Unix(),
		"exp":   expiresAt.Unix(),
		"scope": scopes,
		"act": map[string]string{
			"sub": userID,
		},
	}

	token := jwt.NewWithClaims(s.signingMethod, claims)
	token.Header["kid"] = s.keyID
	token.Header["typ"] = "aa-auth+jwt"

	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Store token record
	tokenRecord := &Token{
		AgentID:   agentID,
		UserID:    userID,
		Scopes:    scopes,
		Protocol:  "aauth",
		ExpiresAt: expiresAt,
	}
	if err := s.store.CreateToken(ctx, tokenRecord); err != nil {
		s.logger.Error("failed to store token record", "error", err)
		// Continue anyway - token is valid
	}

	return signedToken, nil
}

func (s *Server) extractAgentID(agentToken string) string {
	if agentToken == "" {
		return ""
	}

	// Try to parse as JWT
	token, _, err := new(jwt.Parser).ParseUnverified(agentToken, jwt.MapClaims{})
	if err == nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if sub, ok := claims["sub"].(string); ok {
				return sub
			}
		}
	}

	// Fallback: use the token as the agent ID
	return agentToken
}

func (s *Server) errorResponse(w http.ResponseWriter, status int, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:       errCode,
		Description: errDesc,
	}); err != nil {
		s.logger.Error("failed to encode error response", "error", err)
	}
}

func formatDuration(d time.Duration) string {
	if d >= 24*time.Hour {
		days := d / (24 * time.Hour)
		return fmt.Sprintf("%d day(s)", days)
	}
	if d >= time.Hour {
		hours := d / time.Hour
		return fmt.Sprintf("%d hour(s)", hours)
	}
	if d >= time.Minute {
		mins := d / time.Minute
		return fmt.Sprintf("%d minute(s)", mins)
	}
	return d.String()
}

// splitScopes splits a space-separated scope string.
func splitScopes(scopes string) []string {
	if scopes == "" {
		return nil
	}
	var result []string
	current := ""
	for _, c := range scopes {
		if c == ' ' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
