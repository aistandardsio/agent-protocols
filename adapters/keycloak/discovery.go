package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RealmIssuer returns the issuer URL for a realm (https://{host}/realms/{realm}).
func RealmIssuer(baseURL, realm string) string {
	return strings.TrimSuffix(baseURL, "/") + "/realms/" + realm
}

// OIDCConfig holds the relevant fields from a realm's OIDC discovery document.
type OIDCConfig struct {
	Issuer                string   `json:"issuer"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	GrantTypesSupported   []string `json:"grant_types_supported"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
}

// DiscoverRealm fetches the OIDC discovery document for a realm.
func DiscoverRealm(ctx context.Context, client *http.Client, baseURL, realm string) (*OIDCConfig, error) {
	if client == nil {
		client = http.DefaultClient
	}
	wellKnown := RealmIssuer(baseURL, realm) + "/.well-known/openid-configuration"

	//nolint:gosec // G704: base URL is configured by application, not user input
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}

	//nolint:gosec // G704: base URL is configured by application, not user input
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("realm discovery failed: status %d", resp.StatusCode)
	}

	var config OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

// SupportsJWTBearer reports whether the realm advertises the RFC 7523
// jwt-bearer grant needed for ID-JAG reception.
func (c *OIDCConfig) SupportsJWTBearer() bool {
	for _, gt := range c.GrantTypesSupported {
		if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			return true
		}
	}
	return false
}
