package aauth

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
)

// AuthServer handles authorization token issuance for AAuth.
// It implements the Person Server (PS) or Access Server (AS) role.
type AuthServer struct {
	issuer  string
	keyPair *KeyPair
	opts    *authServerOptions
}

// NewAuthServer creates a new authorization server.
func NewAuthServer(issuer string, privateKey crypto.PrivateKey, keyID string, opts ...AuthServerOption) (*AuthServer, error) {
	if issuer == "" {
		return nil, fmt.Errorf("issuer URL is required")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	kp, err := keyPairFromPrivateKey(privateKey, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	options := defaultAuthServerOptions()
	for _, opt := range opts {
		opt(options)
	}

	return &AuthServer{
		issuer:  issuer,
		keyPair: kp,
		opts:    options,
	}, nil
}

// Issuer returns the auth server issuer URL.
func (as *AuthServer) Issuer() string {
	return as.issuer
}

// ServeHTTP implements http.Handler for the token endpoint.
func (as *AuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		as.writeError(w, http.StatusMethodNotAllowed, ErrorInvalidRequest, "method not allowed")
		return
	}

	// Limit request body size to prevent memory exhaustion (1MB max)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Parse the token exchange request
	req, err := ParseTokenExchangeRequest(r)
	if err != nil {
		as.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, err.Error())
		return
	}

	// Validate the request
	if err := req.Validate(); err != nil {
		as.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, err.Error())
		return
	}

	// Check grant type is supported
	if !as.isGrantTypeSupported(req.GrantType) {
		as.writeError(w, http.StatusBadRequest, ErrorUnsupportedGrantType, "unsupported grant type")
		return
	}

	// Process the token exchange
	exchangeCtx, err := as.validateExchangeRequest(r.Context(), req)
	if err != nil {
		as.writeError(w, http.StatusBadRequest, ErrorInvalidGrant, err.Error())
		return
	}

	// Determine scope
	scope := req.Scope
	if as.opts.scopeHandler != nil {
		scope, err = as.opts.scopeHandler(exchangeCtx.AgentID, req.Scope)
		if err != nil {
			as.writeError(w, http.StatusForbidden, ErrorInvalidScope, err.Error())
			return
		}
	}

	// Issue the auth token
	authToken, err := as.IssueAuthToken(exchangeCtx.AgentID, exchangeCtx.AgentCNF, req.Audience, scope)
	if err != nil {
		as.writeError(w, http.StatusInternalServerError, ErrorServerError, "failed to issue token")
		return
	}

	// Sign the token
	tokenStr, err := authToken.Sign(as.opts.signingMethod, as.keyPair.PrivateKey, as.keyPair.KeyID)
	if err != nil {
		as.writeError(w, http.StatusInternalServerError, ErrorServerError, "failed to sign token")
		return
	}

	// Write response
	resp := &TokenExchangeResponse{
		AccessToken:     tokenStr,
		IssuedTokenType: TokenTypeURIAuthJWT,
		TokenType:       "Bearer",
		ExpiresIn:       int(as.opts.authTokenTTL.Seconds()),
		Scope:           scope,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp) //nolint:gosec // G117 false positive for token response
}

// IssueAuthToken creates an auth token for an authorized agent.
func (as *AuthServer) IssueAuthToken(agentID *AAuthID, agentCNF *CNF, audience []string, scope string) (*AuthToken, error) {
	if agentID == nil {
		return nil, fmt.Errorf("agent ID is required")
	}
	if agentCNF == nil {
		return nil, fmt.Errorf("agent CNF is required")
	}
	if len(audience) == 0 {
		return nil, fmt.Errorf("at least one audience is required")
	}

	token := NewAuthToken(
		as.issuer,
		agentID.String(),
		audience,
		agentCNF,
		as.opts.authTokenTTL,
	)

	if scope != "" {
		token.WithScope(scope)
	}

	return token, nil
}

// SignAuthToken creates and signs an auth token.
func (as *AuthServer) SignAuthToken(agentID *AAuthID, agentCNF *CNF, audience []string, scope string) (string, error) {
	token, err := as.IssueAuthToken(agentID, agentCNF, audience, scope)
	if err != nil {
		return "", err
	}

	return token.Sign(as.opts.signingMethod, as.keyPair.PrivateKey, as.keyPair.KeyID)
}

// validateExchangeRequest validates and processes a token exchange request.
func (as *AuthServer) validateExchangeRequest(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeContext, error) {
	exchangeCtx := &TokenExchangeContext{
		Request: req,
	}

	flowType := DetermineFlowType(req)

	switch flowType {
	case FlowResourceManaged:
		// Resource token exchange: verify the resource token
		resourceToken, err := as.verifyResourceToken(ctx, req.SubjectToken)
		if err != nil {
			return nil, fmt.Errorf("invalid resource token: %w", err)
		}
		exchangeCtx.ResourceToken = resourceToken

		// Parse agent ID from resource token
		agentID, err := ParseAAuthID(resourceToken.Subject)
		if err != nil {
			return nil, fmt.Errorf("invalid agent subject: %w", err)
		}
		exchangeCtx.AgentID = agentID

		// Create CNF from agent_jkt
		exchangeCtx.AgentCNF = &CNF{Kid: resourceToken.AgentJKT}

	case FlowPSAsserted:
		// Agent token exchange: verify the agent token
		agentToken, err := as.verifyAgentToken(ctx, req.SubjectToken)
		if err != nil {
			return nil, fmt.Errorf("invalid agent token: %w", err)
		}
		exchangeCtx.AgentToken = agentToken

		// Parse agent ID
		agentID, err := ParseAAuthID(agentToken.Subject)
		if err != nil {
			return nil, fmt.Errorf("invalid agent subject: %w", err)
		}
		exchangeCtx.AgentID = agentID
		exchangeCtx.AgentCNF = agentToken.CNF

	case FlowDelegation:
		// Delegation flow: verify both subject and actor tokens
		subjectToken, err := as.verifyAgentToken(ctx, req.SubjectToken)
		if err != nil {
			return nil, fmt.Errorf("invalid subject token: %w", err)
		}

		actorToken, err := as.verifyAgentToken(ctx, req.ActorToken)
		if err != nil {
			return nil, fmt.Errorf("invalid actor token: %w", err)
		}

		exchangeCtx.AgentToken = subjectToken
		exchangeCtx.ActorToken = actorToken

		// The acting agent's identity
		agentID, err := ParseAAuthID(actorToken.Subject)
		if err != nil {
			return nil, fmt.Errorf("invalid actor subject: %w", err)
		}
		exchangeCtx.AgentID = agentID
		exchangeCtx.AgentCNF = actorToken.CNF

	default:
		return nil, fmt.Errorf("unsupported flow type")
	}

	return exchangeCtx, nil
}

// verifyAgentToken verifies an agent token.
func (as *AuthServer) verifyAgentToken(ctx context.Context, tokenStr string) (*AgentToken, error) {
	if as.opts.agentTokenVerifier != nil {
		return as.opts.agentTokenVerifier.VerifyAgentToken(ctx, tokenStr)
	}

	// Parse without verification (in production, use JWKS verifier)
	token, err := ParseAgentToken(tokenStr)
	if err != nil {
		return nil, err
	}

	if token.IsExpired() {
		return nil, ErrTokenExpired
	}

	return token, nil
}

// verifyResourceToken verifies a resource token.
func (as *AuthServer) verifyResourceToken(ctx context.Context, tokenStr string) (*ResourceToken, error) {
	if as.opts.resourceTokenVerifier != nil {
		return as.opts.resourceTokenVerifier.VerifyResourceToken(ctx, tokenStr)
	}

	// Parse without verification (in production, use JWKS verifier)
	token, err := ParseResourceToken(tokenStr)
	if err != nil {
		return nil, err
	}

	if token.IsExpired() {
		return nil, ErrTokenExpired
	}

	// Verify audience includes this auth server
	if !token.HasAudience(as.issuer) {
		return nil, ErrAudienceMismatch
	}

	return token, nil
}

// isGrantTypeSupported checks if a grant type is supported.
func (as *AuthServer) isGrantTypeSupported(grantType string) bool {
	for _, gt := range as.opts.supportedGrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// writeError writes an error response.
func (as *AuthServer) writeError(w http.ResponseWriter, statusCode int, errCode, description string) {
	resp := &TokenErrorResponse{
		Error:            errCode,
		ErrorDescription: description,
	}
	resp.WriteJSON(w, statusCode)
}

// KeyPair returns the auth server's key pair.
func (as *AuthServer) KeyPair() *KeyPair {
	return as.keyPair
}

// Options returns the auth server options.
func (as *AuthServer) Options() *authServerOptions {
	return as.opts
}

// PublicJWKS returns the public keys as a JWKS for discovery.
func (as *AuthServer) PublicJWKS() (*JWKS, error) {
	jwk, err := as.keyPair.ToJWK()
	if err != nil {
		return nil, err
	}

	return &JWKS{
		Keys: []JWK{*jwk},
	}, nil
}

// AuthServerMetadata represents the .well-known/oauth-authorization-server metadata.
type AuthServerMetadata struct {
	// Issuer is the authorization server's issuer identifier
	Issuer string `json:"issuer"`

	// TokenEndpoint is the URL of the token endpoint
	TokenEndpoint string `json:"token_endpoint"`

	// JWKSURI is the URL of the JSON Web Key Set document
	JWKSURI string `json:"jwks_uri"`

	// GrantTypesSupported lists the supported grant types
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported lists the client auth methods
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// ScopesSupported lists the supported scopes
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// SubjectTokenTypesSupported lists supported subject_token_type values
	SubjectTokenTypesSupported []string `json:"subject_token_types_supported,omitempty"`

	// ActorTokenTypesSupported lists supported actor_token_type values
	ActorTokenTypesSupported []string `json:"actor_token_types_supported,omitempty"`
}

// Metadata returns the auth server metadata for discovery.
func (as *AuthServer) Metadata() *AuthServerMetadata {
	return &AuthServerMetadata{
		Issuer:              as.issuer,
		TokenEndpoint:       as.issuer + as.opts.tokenEndpointPath,
		JWKSURI:             as.issuer + "/.well-known/jwks.json",
		GrantTypesSupported: as.opts.supportedGrantTypes,
		TokenEndpointAuthMethodsSupported: []string{
			"none",
			"private_key_jwt",
		},
		SubjectTokenTypesSupported: []string{
			TokenTypeURIAgentJWT,
			TokenTypeURIResourceJWT,
		},
		ActorTokenTypesSupported: []string{
			TokenTypeURIAgentJWT,
		},
	}
}

// Handler returns an http.Handler for the token endpoint.
func (as *AuthServer) Handler() http.Handler {
	return as
}

// TokenEndpoint returns the token endpoint URL.
func (as *AuthServer) TokenEndpoint() string {
	return as.issuer + as.opts.tokenEndpointPath
}
