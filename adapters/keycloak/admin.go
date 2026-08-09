package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientAttrJWTAuthorizationGrant is the client attribute that enables the
// jwt-authorization-grant (ID-JAG reception) on a confidential client.
// Experimental in Keycloak 26.7; the attribute name may change upstream.
const ClientAttrJWTAuthorizationGrant = "oauth2.jwt.authorization.grant.enabled"

// AdminClient is a minimal Keycloak Admin REST client for bootstrapping a
// realm as an ID-JAG receiver. It authenticates against the master realm
// with the admin-cli password grant.
//
//nolint:gosec // G117: admin credential fields, not hardcoded secrets
type AdminClient struct {
	BaseURL    string
	Username   string
	Password   string
	HTTPClient *http.Client

	token       string
	tokenExpiry time.Time
}

// NewAdminClient creates an AdminClient for the Keycloak instance at baseURL.
func NewAdminClient(baseURL, username, password string) *AdminClient {
	return &AdminClient{
		BaseURL:    strings.TrimSuffix(baseURL, "/"),
		Username:   username,
		Password:   password,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// ExternalIssuer describes an external ID-JAG issuer to trust.
type ExternalIssuer struct {
	// Alias is the identity provider alias within the realm.
	Alias string

	// IssuerURL is the external issuer identifier (iss claim value).
	IssuerURL string

	// JWKSURL is the issuer's JWKS endpoint used to validate assertion
	// signatures.
	JWKSURL string
}

// ReceiverClient describes the confidential client that accepts the
// jwt-bearer grant carrying ID-JAG assertions.
//
//nolint:gosec // G117: OAuth client credential fields, not hardcoded secrets
type ReceiverClient struct {
	ClientID     string
	ClientSecret string
	// Attributes are merged over the defaults (the jwt-authorization-grant
	// flag is always set).
	Attributes map[string]string
}

// BootstrapReceiver provisions a realm configured as an ID-JAG receiver:
// the realm itself, an identity-provider entry trusting the external
// issuer, and a confidential client with the jwt-authorization-grant flag.
// Idempotent: HTTP 409 responses (already exists) are treated as success.
func (a *AdminClient) BootstrapReceiver(ctx context.Context, realm string, issuer ExternalIssuer, client ReceiverClient) error {
	if err := a.CreateRealm(ctx, realm); err != nil {
		return fmt.Errorf("creating realm %s: %w", realm, err)
	}
	if err := a.CreateExternalIssuer(ctx, realm, issuer); err != nil {
		return fmt.Errorf("registering external issuer %s: %w", issuer.Alias, err)
	}
	if err := a.CreateReceiverClient(ctx, realm, client); err != nil {
		return fmt.Errorf("creating receiver client %s: %w", client.ClientID, err)
	}
	return nil
}

// CreateRealm creates an enabled realm.
func (a *AdminClient) CreateRealm(ctx context.Context, realm string) error {
	return a.post(ctx, "/admin/realms", map[string]any{
		"realm":   realm,
		"enabled": true,
	})
}

// CreateExternalIssuer registers the external ID-JAG issuer as an OIDC
// identity provider with JWKS-based signature validation. The provider
// entry establishes the trust anchor the jwt-authorization-grant uses to
// validate incoming assertions (per the Keycloak 26.7 experimental guide).
func (a *AdminClient) CreateExternalIssuer(ctx context.Context, realm string, issuer ExternalIssuer) error {
	return a.post(ctx, "/admin/realms/"+url.PathEscape(realm)+"/identity-provider/instances", map[string]any{
		"alias":      issuer.Alias,
		"providerId": "oidc",
		"enabled":    true,
		"config": map[string]string{
			"issuer":            issuer.IssuerURL,
			"jwksUrl":           issuer.JWKSURL,
			"useJwksUrl":        "true",
			"validateSignature": "true",
			// Endpoints are required by the OIDC provider type but unused
			// for assertion validation; point them at the issuer.
			"authorizationUrl": issuer.IssuerURL,
			"tokenUrl":         issuer.IssuerURL,
		},
	})
}

// CreateReceiverClient creates the confidential client that accepts ID-JAG
// assertions via the jwt-bearer grant.
func (a *AdminClient) CreateReceiverClient(ctx context.Context, realm string, client ReceiverClient) error {
	attributes := map[string]string{
		ClientAttrJWTAuthorizationGrant: "true",
	}
	for k, v := range client.Attributes {
		attributes[k] = v
	}

	return a.post(ctx, "/admin/realms/"+url.PathEscape(realm)+"/clients", map[string]any{
		"clientId":                  client.ClientID,
		"secret":                    client.ClientSecret,
		"enabled":                   true,
		"publicClient":              false,
		"standardFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
		"attributes":                attributes,
	})
}

// post sends an authenticated JSON POST to the Admin REST API. A 409
// (conflict / already exists) is treated as success for idempotency.
func (a *AdminClient) post(ctx context.Context, path string, payload any) error {
	token, err := a.adminToken(ctx)
	if err != nil {
		return err
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	//nolint:gosec // G704: BaseURL is configured by application, not user input
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	//nolint:gosec // G704: BaseURL is configured by application, not user input
	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusConflict {
		return nil // already exists
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("admin API %s failed: status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// adminToken obtains (and caches) an admin access token from the master
// realm using the admin-cli password grant.
func (a *AdminClient) adminToken(ctx context.Context) (string, error) {
	if a.token != "" && time.Now().Before(a.tokenExpiry) {
		return a.token, nil
	}

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", "admin-cli")
	data.Set("username", a.Username)
	data.Set("password", a.Password)

	tokenURL := a.BaseURL + "/realms/master/protocol/openid-connect/token"
	//nolint:gosec // G704: BaseURL is configured by application, not user input
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	//nolint:gosec // G704: BaseURL is configured by application, not user input
	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("admin login failed: status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	a.token = tokenResp.AccessToken
	a.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-10) * time.Second)
	return a.token, nil
}
