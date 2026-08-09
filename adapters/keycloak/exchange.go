package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aistandardsio/agent-protocols/idjag"
)

// Exchanger exchanges an ID-JAG assertion for a Keycloak access token using
// the RFC 7523 jwt-bearer grant with confidential client authentication.
//
//nolint:gosec // G117: OAuth client credential fields, not hardcoded secrets
type Exchanger struct {
	// TokenEndpoint is the realm token endpoint. Use DiscoverRealm or
	// NewExchanger to resolve it.
	TokenEndpoint string

	// ClientID is the confidential client with the jwt-authorization-grant
	// flag enabled.
	ClientID string

	// ClientSecret authenticates the confidential client
	// (client_secret_basic).
	ClientSecret string

	// HTTPClient is used for token requests. Defaults to a 30s-timeout client.
	HTTPClient *http.Client
}

// NewExchanger discovers the realm's token endpoint and returns an Exchanger
// for the given confidential client.
func NewExchanger(ctx context.Context, baseURL, realm, clientID, clientSecret string) (*Exchanger, error) {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	config, err := DiscoverRealm(ctx, httpClient, baseURL, realm)
	if err != nil {
		return nil, err
	}
	return &Exchanger{
		TokenEndpoint: config.TokenEndpoint,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		HTTPClient:    httpClient,
	}, nil
}

// Exchange presents the signed ID-JAG assertion at the Keycloak token
// endpoint via grant_type jwt-bearer and returns the issued access token.
func (e *Exchanger) Exchange(ctx context.Context, assertion string, scopes ...string) (*idjag.TokenExchangeResponse, error) {
	data := url.Values{}
	data.Set("grant_type", idjag.GrantTypeJWTBearer)
	data.Set("assertion", assertion)
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(e.ClientID), url.QueryEscape(e.ClientSecret))

	httpClient := e.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var oauthErr struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, fmt.Errorf("keycloak token exchange failed (%d): %s: %s",
				resp.StatusCode, oauthErr.Error, oauthErr.ErrorDescription)
		}
		return nil, fmt.Errorf("keycloak token exchange failed: status %d", resp.StatusCode)
	}

	var tokenResp idjag.TokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}
