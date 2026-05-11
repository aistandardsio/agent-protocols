package zitadel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// OIDCConfig represents the relevant fields from OIDC discovery.
type OIDCConfig struct {
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

// discoverOIDCConfig fetches the OIDC configuration from the issuer.
func discoverOIDCConfig(issuer string, client *http.Client) (*OIDCConfig, error) {
	wellKnownURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	//nolint:gosec // G107: issuer is trusted configuration input
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery failed: status %d", resp.StatusCode)
	}

	var config OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// discoverTokenEndpoint fetches the token endpoint from OIDC discovery.
func discoverTokenEndpoint(issuer string, client *http.Client) (string, error) {
	config, err := discoverOIDCConfig(issuer, client)
	if err != nil {
		return "", err
	}

	if config.TokenEndpoint == "" {
		return "", fmt.Errorf("token_endpoint not found in discovery document")
	}

	return config.TokenEndpoint, nil
}

// discoverJWKSURL fetches the JWKS URL from OIDC discovery.
func discoverJWKSURL(issuer string, client *http.Client) (string, error) {
	config, err := discoverOIDCConfig(issuer, client)
	if err != nil {
		return "", err
	}

	if config.JWKSURI == "" {
		return "", fmt.Errorf("jwks_uri not found in discovery document")
	}

	return config.JWKSURI, nil
}
