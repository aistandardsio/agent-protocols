package personserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Mock Store Implementation
// ============================================================================

type mockStore struct {
	mu           sync.RWMutex
	users        map[string]*User
	agents       map[string]*Agent
	missions     map[string]*Mission
	tokens       map[string]*Token
	usersByEmail map[string]*User
}

func newMockStore() *mockStore {
	return &mockStore{
		users:        make(map[string]*User),
		agents:       make(map[string]*Agent),
		missions:     make(map[string]*Mission),
		tokens:       make(map[string]*Token),
		usersByEmail: make(map[string]*User),
	}
}

func (m *mockStore) Close() error { return nil }

func (m *mockStore) CreateUser(ctx context.Context, user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.users[user.ID]; exists {
		return ErrAlreadyExists
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	if user.Email != "" {
		m.usersByEmail[user.Email] = user
	}
	return nil
}

func (m *mockStore) GetUser(ctx context.Context, id string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	user, exists := m.users[id]
	if !exists {
		return nil, ErrNotFound
	}
	return user, nil
}

func (m *mockStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	user, exists := m.usersByEmail[email]
	if !exists {
		return nil, ErrNotFound
	}
	return user, nil
}

func (m *mockStore) ListUsers(ctx context.Context) ([]*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	users := make([]*User, 0, len(m.users))
	for _, u := range m.users {
		users = append(users, u)
	}
	return users, nil
}

func (m *mockStore) CreateAgent(ctx context.Context, agent *Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.agents[agent.ID]; exists {
		return ErrAlreadyExists
	}
	agent.CreatedAt = time.Now()
	agent.UpdatedAt = time.Now()
	m.agents[agent.ID] = agent
	return nil
}

func (m *mockStore) GetAgent(ctx context.Context, id string) (*Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agent, exists := m.agents[id]
	if !exists {
		return nil, ErrNotFound
	}
	return agent, nil
}

func (m *mockStore) ListAgents(ctx context.Context) ([]*Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agents := make([]*Agent, 0, len(m.agents))
	for _, a := range m.agents {
		agents = append(agents, a)
	}
	return agents, nil
}

func (m *mockStore) CreateMission(ctx context.Context, mission *Mission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mission.ID == "" {
		mission.ID = generateID()
	}
	mission.CreatedAt = time.Now()
	mission.UpdatedAt = time.Now()
	m.missions[mission.ID] = mission
	return nil
}

func (m *mockStore) GetMission(ctx context.Context, id string) (*Mission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	mission, exists := m.missions[id]
	if !exists {
		return nil, ErrNotFound
	}
	return mission, nil
}

func (m *mockStore) ApproveMission(ctx context.Context, id string, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mission, exists := m.missions[id]
	if !exists {
		return ErrNotFound
	}
	now := time.Now()
	expiresAt := now.Add(duration)
	mission.Status = MissionStatusApproved
	mission.ApprovedAt = &now
	mission.ExpiresAt = &expiresAt
	mission.UpdatedAt = now
	return nil
}

func (m *mockStore) DenyMission(ctx context.Context, id, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mission, exists := m.missions[id]
	if !exists {
		return ErrNotFound
	}
	now := time.Now()
	mission.Status = MissionStatusDenied
	mission.DeniedAt = &now
	mission.DenialReason = reason
	mission.UpdatedAt = now
	return nil
}

func (m *mockStore) ListPendingMissions(ctx context.Context) ([]*Mission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	missions := make([]*Mission, 0)
	for _, mission := range m.missions {
		if mission.Status == MissionStatusPending {
			missions = append(missions, mission)
		}
	}
	return missions, nil
}

func (m *mockStore) ListMissionsByUser(ctx context.Context, userID string) ([]*Mission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	missions := make([]*Mission, 0)
	for _, mission := range m.missions {
		if mission.UserID == userID {
			missions = append(missions, mission)
		}
	}
	return missions, nil
}

func (m *mockStore) CreateToken(ctx context.Context, token *Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if token.ID == "" {
		token.ID = generateID()
	}
	token.IssuedAt = time.Now()
	m.tokens[token.ID] = token
	return nil
}

func (m *mockStore) GetToken(ctx context.Context, id string) (*Token, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	token, exists := m.tokens[id]
	if !exists {
		return nil, ErrNotFound
	}
	return token, nil
}

func (m *mockStore) RevokeToken(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	token, exists := m.tokens[id]
	if !exists {
		return ErrNotFound
	}
	now := time.Now()
	token.RevokedAt = &now
	return nil
}

var idCounter int
var idMu sync.Mutex

func generateID() string {
	idMu.Lock()
	defer idMu.Unlock()
	idCounter++
	return strings.ReplaceAll(time.Now().Format("20060102150405.000000"), ".", "") + string(rune('0'+idCounter%10))
}

// ============================================================================
// Test Helper Functions
// ============================================================================

func setupTestServer(t *testing.T) (*Server, *mockStore) {
	t.Helper()
	store := newMockStore()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	server, err := New(store, "http://localhost:8080", privateKey, "test-key-1",
		WithTokenTTL(time.Hour),
		WithMissionTimeout(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	return server, store
}

//nolint:unparam // return value may be useful in future tests
func createTestUser(t *testing.T, store *mockStore, id, email, name string) *User {
	t.Helper()
	user := &User{ID: id, Email: email, Name: name}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return user
}

//nolint:unparam // return value may be useful in future tests
func createTestAgent(t *testing.T, store *mockStore, id, name string) *Agent {
	t.Helper()
	agent := &Agent{ID: id, Name: name}
	if err := store.CreateAgent(context.Background(), agent); err != nil {
		t.Fatalf("failed to create test agent: %v", err)
	}
	return agent
}

//nolint:unparam // userID varies by test context
func createTestMission(t *testing.T, store *mockStore, agentID, userID, scopes string, status MissionStatus) *Mission {
	t.Helper()
	mission := &Mission{
		AgentID:         agentID,
		UserID:          userID,
		Name:            "Test Mission",
		Scopes:          scopes,
		InteractionType: "supervised",
		Status:          status,
		Duration:        3600,
	}
	if err := store.CreateMission(context.Background(), mission); err != nil {
		t.Fatalf("failed to create test mission: %v", err)
	}
	return mission
}

// ============================================================================
// Discovery Handler Tests
// ============================================================================

func TestHandleMetadata(t *testing.T) {
	server, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/aauth-configuration", nil)
	rec := httptest.NewRecorder()

	server.HandleMetadata(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var metadata map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	expectedFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"revocation_endpoint",
		"jwks_uri",
		"grant_types_supported",
		"response_types_supported",
	}

	for _, field := range expectedFields {
		if _, ok := metadata[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	if metadata["issuer"] != "http://localhost:8080" {
		t.Errorf("expected issuer http://localhost:8080, got %v", metadata["issuer"])
	}
}

func TestHandleJWKS(t *testing.T) {
	server, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	server.HandleJWKS(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var jwks map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Error("expected at least one key in JWKS")
	}

	key := keys[0].(map[string]any)
	if key["kid"] != "test-key-1" {
		t.Errorf("expected kid test-key-1, got %v", key["kid"])
	}
	if key["kty"] != "EC" {
		t.Errorf("expected kty EC, got %v", key["kty"])
	}
}

// ============================================================================
// Authorization Handler Tests
// ============================================================================

func TestHandleAuthorize_Success(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")

	reqBody := AuthorizationRequest{
		AgentToken:  "test-agent-1",
		UserID:      "user-1",
		Scopes:      "read:email read:profile",
		MissionName: "Read User Profile",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleAuthorize(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("expected status %d, got %d: %s", http.StatusAccepted, rec.Code, rec.Body.String())
	}

	var resp AuthorizationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.MissionID == "" {
		t.Error("expected mission_id in response")
	}
	if resp.ConsentURI == "" {
		t.Error("expected consent_uri in response")
	}
	if resp.StatusURI == "" {
		t.Error("expected status_uri in response")
	}
}

func TestHandleAuthorize_MissingUserID(t *testing.T) {
	server, _ := setupTestServer(t)

	reqBody := AuthorizationRequest{
		AgentToken: "test-agent-1",
		Scopes:     "read:email",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleAuthorize(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResp.Error != "invalid_request" {
		t.Errorf("expected error invalid_request, got %s", errResp.Error)
	}
}

func TestHandleAuthorize_MissingScope(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")

	reqBody := AuthorizationRequest{
		AgentToken: "test-agent-1",
		UserID:     "user-1",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleAuthorize(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestHandleAuthorize_MissingAgentToken(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")

	reqBody := AuthorizationRequest{
		UserID: "user-1",
		Scopes: "read:email",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleAuthorize(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestHandleAuthorize_UserNotFound(t *testing.T) {
	server, _ := setupTestServer(t)

	reqBody := AuthorizationRequest{
		AgentToken: "test-agent-1",
		UserID:     "nonexistent-user",
		Scopes:     "read:email",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleAuthorize(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestHandleAuthorize_InvalidJSON(t *testing.T) {
	server, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleAuthorize(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

// ============================================================================
// Consent Handler Tests
// ============================================================================

func TestHandleConsentPage_Success(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	createTestAgent(t, store, "agent-1", "Test Agent")
	mission := createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusPending)

	req := httptest.NewRequest(http.MethodGet, "/consent/"+mission.ID, nil)
	req.SetPathValue("id", mission.ID)
	rec := httptest.NewRecorder()

	server.HandleConsentPage(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "text/html" {
		t.Errorf("expected Content-Type text/html, got %s", contentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Test Agent") {
		t.Error("expected agent name in consent page")
	}
}

func TestHandleConsentPage_MissionNotFound(t *testing.T) {
	server, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/consent/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	rec := httptest.NewRecorder()

	server.HandleConsentPage(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}

func TestHandleConsentPage_AlreadyProcessed(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	mission := createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusApproved)

	req := httptest.NewRequest(http.MethodGet, "/consent/"+mission.ID, nil)
	req.SetPathValue("id", mission.ID)
	rec := httptest.NewRecorder()

	server.HandleConsentPage(rec, req)

	if rec.Code != http.StatusGone {
		t.Errorf("expected status %d, got %d", http.StatusGone, rec.Code)
	}
}

func TestHandleConsentSubmit_Approve(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	mission := createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusPending)

	form := url.Values{}
	form.Set("decision", "approve")

	req := httptest.NewRequest(http.MethodPost, "/consent/"+mission.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", mission.ID)
	rec := httptest.NewRecorder()

	server.HandleConsentSubmit(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Verify mission was approved
	updatedMission, _ := store.GetMission(context.Background(), mission.ID)
	if updatedMission.Status != MissionStatusApproved {
		t.Errorf("expected mission status approved, got %s", updatedMission.Status)
	}
}

func TestHandleConsentSubmit_Deny(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	mission := createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusPending)

	form := url.Values{}
	form.Set("decision", "deny")
	form.Set("reason", "Not authorized for this action")

	req := httptest.NewRequest(http.MethodPost, "/consent/"+mission.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", mission.ID)
	rec := httptest.NewRecorder()

	server.HandleConsentSubmit(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	// Verify mission was denied
	updatedMission, _ := store.GetMission(context.Background(), mission.ID)
	if updatedMission.Status != MissionStatusDenied {
		t.Errorf("expected mission status denied, got %s", updatedMission.Status)
	}
	if updatedMission.DenialReason != "Not authorized for this action" {
		t.Errorf("expected denial reason, got %s", updatedMission.DenialReason)
	}
}

func TestHandleConsentSubmit_InvalidDecision(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	mission := createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusPending)

	form := url.Values{}
	form.Set("decision", "invalid")

	req := httptest.NewRequest(http.MethodPost, "/consent/"+mission.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", mission.ID)
	rec := httptest.NewRecorder()

	server.HandleConsentSubmit(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestHandleConsentStatus_Pending(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	mission := createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusPending)

	req := httptest.NewRequest(http.MethodGet, "/consent/status/"+mission.ID, nil)
	req.SetPathValue("id", mission.ID)
	rec := httptest.NewRecorder()

	server.HandleConsentStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp ConsentStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Status != "pending" {
		t.Errorf("expected status pending, got %s", resp.Status)
	}
}

func TestHandleConsentStatus_Approved(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	mission := createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusPending)

	// Approve the mission
	if err := store.ApproveMission(context.Background(), mission.ID, time.Hour); err != nil {
		t.Fatalf("failed to approve mission: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/consent/status/"+mission.ID, nil)
	req.SetPathValue("id", mission.ID)
	rec := httptest.NewRecorder()

	server.HandleConsentStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp ConsentStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Status != "approved" {
		t.Errorf("expected status approved, got %s", resp.Status)
	}
	if resp.AccessToken == "" {
		t.Error("expected access_token in response")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token_type Bearer, got %s", resp.TokenType)
	}
}

func TestHandleConsentStatus_Denied(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	mission := createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusPending)

	// Deny the mission
	if err := store.DenyMission(context.Background(), mission.ID, "User declined"); err != nil {
		t.Fatalf("failed to deny mission: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/consent/status/"+mission.ID, nil)
	req.SetPathValue("id", mission.ID)
	rec := httptest.NewRecorder()

	server.HandleConsentStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp ConsentStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Status != "denied" {
		t.Errorf("expected status denied, got %s", resp.Status)
	}
	if resp.Error != "access_denied" {
		t.Errorf("expected error access_denied, got %s", resp.Error)
	}
}

func TestHandleConsentStatus_NotFound(t *testing.T) {
	server, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/consent/status/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	rec := httptest.NewRecorder()

	server.HandleConsentStatus(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}

// ============================================================================
// Token Handler Tests
// ============================================================================

func TestHandleToken_MissionApproval(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	mission := createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusPending)

	// Approve the mission first
	if err := store.ApproveMission(context.Background(), mission.ID, time.Hour); err != nil {
		t.Fatalf("failed to approve mission: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:mission-approval")
	form.Set("mission_id", mission.ID)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	server.HandleToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp TokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("expected access_token in response")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token_type Bearer, got %s", resp.TokenType)
	}
	if resp.Scope != "read:email" {
		t.Errorf("expected scope read:email, got %s", resp.Scope)
	}
}

func TestHandleToken_MissionNotApproved(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	mission := createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusPending)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:mission-approval")
	form.Set("mission_id", mission.ID)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	server.HandleToken(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResp.Error != "access_denied" {
		t.Errorf("expected error access_denied, got %s", errResp.Error)
	}
}

func TestHandleToken_MissionNotFound(t *testing.T) {
	server, _ := setupTestServer(t)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:mission-approval")
	form.Set("mission_id", "nonexistent")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	server.HandleToken(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestHandleToken_UnsupportedGrantType(t *testing.T) {
	server, _ := setupTestServer(t)

	form := url.Values{}
	form.Set("grant_type", "unsupported")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	server.HandleToken(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResp.Error != "unsupported_grant_type" {
		t.Errorf("expected error unsupported_grant_type, got %s", errResp.Error)
	}
}

func TestHandleRevoke(t *testing.T) {
	server, store := setupTestServer(t)

	// Create a token
	token := &Token{
		ID:        "test-token-1",
		AgentID:   "agent-1",
		UserID:    "user-1",
		Scopes:    "read:email",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.CreateToken(context.Background(), token); err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	form := url.Values{}
	form.Set("token", "test-token-1")

	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	server.HandleRevoke(rec, req)

	// Per RFC 7009, revocation always returns 200
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestHandleRevoke_MissingToken(t *testing.T) {
	server, _ := setupTestServer(t)

	form := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	server.HandleRevoke(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

// ============================================================================
// Admin Handler Tests
// ============================================================================

func TestHandleListUsers(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "user1@example.com", "User One")
	createTestUser(t, store, "user-2", "user2@example.com", "User Two")

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	rec := httptest.NewRecorder()

	server.HandleListUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var users []*User
	if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

func TestHandleCreateUser(t *testing.T) {
	server, _ := setupTestServer(t)

	user := User{
		ID:    "new-user",
		Email: "new@example.com",
		Name:  "New User",
	}
	body, _ := json.Marshal(user)

	req := httptest.NewRequest(http.MethodPost, "/admin/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleCreateUser(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, rec.Code, rec.Body.String())
	}

	var createdUser User
	if err := json.Unmarshal(rec.Body.Bytes(), &createdUser); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if createdUser.ID != "new-user" {
		t.Errorf("expected user ID new-user, got %s", createdUser.ID)
	}
}

func TestHandleCreateUser_AlreadyExists(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "existing-user", "existing@example.com", "Existing User")

	user := User{
		ID:    "existing-user",
		Email: "other@example.com",
		Name:  "Other User",
	}
	body, _ := json.Marshal(user)

	req := httptest.NewRequest(http.MethodPost, "/admin/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleCreateUser(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d", http.StatusConflict, rec.Code)
	}
}

func TestHandleListAgents(t *testing.T) {
	server, store := setupTestServer(t)
	createTestAgent(t, store, "agent-1", "Agent One")
	createTestAgent(t, store, "agent-2", "Agent Two")

	req := httptest.NewRequest(http.MethodGet, "/admin/agents", nil)
	rec := httptest.NewRecorder()

	server.HandleListAgents(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var agents []*Agent
	if err := json.Unmarshal(rec.Body.Bytes(), &agents); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

func TestHandleCreateAgent(t *testing.T) {
	server, _ := setupTestServer(t)

	agent := Agent{
		ID:   "new-agent",
		Name: "New Agent",
	}
	body, _ := json.Marshal(agent)

	req := httptest.NewRequest(http.MethodPost, "/admin/agents", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleCreateAgent(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, rec.Code)
	}
}

func TestHandleListMissions(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")
	createTestMission(t, store, "agent-1", "user-1", "read:email", MissionStatusPending)
	createTestMission(t, store, "agent-2", "user-1", "write:email", MissionStatusPending)

	req := httptest.NewRequest(http.MethodGet, "/admin/missions", nil)
	rec := httptest.NewRecorder()

	server.HandleListMissions(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var missions []*Mission
	if err := json.Unmarshal(rec.Body.Bytes(), &missions); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(missions) != 2 {
		t.Errorf("expected 2 pending missions, got %d", len(missions))
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestFullConsentFlow(t *testing.T) {
	server, store := setupTestServer(t)
	createTestUser(t, store, "user-1", "test@example.com", "Test User")

	handler := server.Handler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Step 1: Request authorization
	authReq := AuthorizationRequest{
		AgentToken:  "test-agent",
		UserID:      "user-1",
		Scopes:      "read:profile",
		MissionName: "Read Profile",
	}
	authBody, _ := json.Marshal(authReq)

	resp, err := http.Post(ts.URL+"/authorize", "application/json", bytes.NewReader(authBody))
	if err != nil {
		t.Fatalf("failed to send authorization request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, resp.StatusCode)
	}

	var authResp AuthorizationResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		t.Fatalf("failed to decode authorization response: %v", err)
	}

	missionID := authResp.MissionID

	// Step 2: Check status (should be pending)
	statusResp, err := http.Get(ts.URL + "/consent/status/" + missionID)
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	defer statusResp.Body.Close()

	var status ConsentStatusResponse
	if err := json.NewDecoder(statusResp.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}

	if status.Status != "pending" {
		t.Errorf("expected status pending, got %s", status.Status)
	}

	// Step 3: Approve the mission
	form := url.Values{}
	form.Set("decision", "approve")

	approveResp, err := http.Post(ts.URL+"/consent/"+missionID, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed to approve mission: %v", err)
	}
	defer approveResp.Body.Close()

	if approveResp.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, approveResp.StatusCode)
	}

	// Step 4: Check status (should be approved with token)
	statusResp2, err := http.Get(ts.URL + "/consent/status/" + missionID)
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	defer statusResp2.Body.Close()

	var status2 ConsentStatusResponse
	if err := json.NewDecoder(statusResp2.Body).Decode(&status2); err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}

	if status2.Status != "approved" {
		t.Errorf("expected status approved, got %s", status2.Status)
	}
	if status2.AccessToken == "" {
		t.Error("expected access_token in approved response")
	}
}

// ============================================================================
// Server Configuration Tests
// ============================================================================

func TestNewServer_InvalidPrivateKey(t *testing.T) {
	store := newMockStore()

	// Pass a non-signer key (int is not a crypto.Signer)
	_, err := New(store, "http://localhost:8080", 123, "key-1")
	if err != ErrInvalidPrivateKey {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestServerOptions(t *testing.T) {
	store := newMockStore()
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	server, err := New(store, "http://localhost:8080", privateKey, "key-1",
		WithTokenTTL(2*time.Hour),
		WithMissionTimeout(15*time.Minute),
	)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if server.tokenTTL != 2*time.Hour {
		t.Errorf("expected tokenTTL 2h, got %v", server.tokenTTL)
	}
	if server.missionTimeout != 15*time.Minute {
		t.Errorf("expected missionTimeout 15m, got %v", server.missionTimeout)
	}
}

func TestServerAccessors(t *testing.T) {
	server, _ := setupTestServer(t)

	if server.Store() == nil {
		t.Error("expected non-nil store")
	}
	if server.Issuer() != "http://localhost:8080" {
		t.Errorf("expected issuer http://localhost:8080, got %s", server.Issuer())
	}
	if server.KeyID() != "test-key-1" {
		t.Errorf("expected keyID test-key-1, got %s", server.KeyID())
	}
	if server.PublicKey() == nil {
		t.Error("expected non-nil public key")
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"read:email", []string{"read:email"}},
		{"read:email read:profile", []string{"read:email", "read:profile"}},
		{"read:email  read:profile", []string{"read:email", "read:profile"}}, // double space
		{" read:email ", []string{"read:email"}},                             // leading/trailing
	}

	for _, tt := range tests {
		result := splitScopes(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("splitScopes(%q) = %v, expected %v", tt.input, result, tt.expected)
			continue
		}
		for i, v := range result {
			if v != tt.expected[i] {
				t.Errorf("splitScopes(%q)[%d] = %q, expected %q", tt.input, i, v, tt.expected[i])
			}
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5 minute(s)"},
		{1 * time.Hour, "1 hour(s)"},
		{2 * time.Hour, "2 hour(s)"},
		{24 * time.Hour, "1 day(s)"},
		{48 * time.Hour, "2 day(s)"},
	}

	for _, tt := range tests {
		result := formatDuration(tt.input)
		if result != tt.expected {
			t.Errorf("formatDuration(%v) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestMissionIsActive(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	tests := []struct {
		name     string
		mission  Mission
		expected bool
	}{
		{
			name:     "pending mission",
			mission:  Mission{Status: MissionStatusPending},
			expected: false,
		},
		{
			name:     "approved, not expired",
			mission:  Mission{Status: MissionStatusApproved, ExpiresAt: &future},
			expected: true,
		},
		{
			name:     "approved, expired",
			mission:  Mission{Status: MissionStatusApproved, ExpiresAt: &past},
			expected: false,
		},
		{
			name:     "approved, no expiry",
			mission:  Mission{Status: MissionStatusApproved},
			expected: true,
		},
		{
			name:     "denied mission",
			mission:  Mission{Status: MissionStatusDenied},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mission.IsActive(); got != tt.expected {
				t.Errorf("IsActive() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestTokenIsValid(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	tests := []struct {
		name     string
		token    Token
		expected bool
	}{
		{
			name:     "valid token",
			token:    Token{ExpiresAt: future},
			expected: true,
		},
		{
			name:     "expired token",
			token:    Token{ExpiresAt: past},
			expected: false,
		},
		{
			name:     "revoked token",
			token:    Token{ExpiresAt: future, RevokedAt: &now},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, expected %v", got, tt.expected)
			}
		})
	}
}
