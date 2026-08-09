package omniskill

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/plexusone/omniskill/mcp/oauth2"
)

// Verifier validates externally-issued JWT access tokens for omniskill's
// ExternalAuth seam using agent-protocols ID-JAG verification. It implements
// omniskill's oauth2.TokenVerifier interface.
type Verifier struct {
	issuer   string
	audience string

	opts       idjag.VerifierOptions
	jwksURL    string
	httpClient *http.Client

	mu       sync.Mutex
	verifier idjag.Verifier
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithJWKSURL pins the JWKS endpoint, skipping discovery.
func WithJWKSURL(url string) Option {
	return func(v *Verifier) { v.jwksURL = url }
}

// WithHTTPClient sets the HTTP client used for discovery and JWKS fetching.
func WithHTTPClient(client *http.Client) Option {
	return func(v *Verifier) { v.httpClient = client }
}

// WithClockSkew tolerates clock differences between systems.
func WithClockSkew(skew time.Duration) Option {
	return func(v *Verifier) { v.opts.ClockSkew = skew }
}

// WithAllowedAlgorithms restricts accepted signing algorithms. Defaults to
// the RS/ES families; HS* and "none" are always rejected by idjag.
func WithAllowedAlgorithms(algs ...string) Option {
	return func(v *Verifier) { v.opts.AllowedAlgorithms = algs }
}

// WithIDJAGVerifier supplies a custom idjag.Verifier (for example a
// static-key verifier in tests), bypassing JWKS discovery entirely.
func WithIDJAGVerifier(verifier idjag.Verifier) Option {
	return func(v *Verifier) { v.verifier = verifier }
}

// NewVerifier creates a Verifier for tokens issued by issuer and audienced
// at audience. The JWKS endpoint is resolved lazily on first use unless
// WithJWKSURL or WithIDJAGVerifier is supplied.
func NewVerifier(issuer, audience string, opts ...Option) *Verifier {
	v := &Verifier{
		issuer:     issuer,
		audience:   audience,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	v.opts.ExpectedIssuer = issuer
	v.opts.ExpectedAudience = audience
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyToken implements omniskill's oauth2.TokenVerifier: it validates the
// bearer token's signature (via the issuer's JWKS), issuer, audience, and
// expiry, and maps the verified identity into an oauth2.TokenInfo.
func (v *Verifier) VerifyToken(ctx context.Context, token string) (*oauth2.TokenInfo, error) {
	verifier, err := v.resolveVerifier(ctx)
	if err != nil {
		return nil, err
	}

	assertion, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	return tokenInfoFromAssertion(token, assertion), nil
}

// resolveVerifier returns the underlying idjag.Verifier, resolving the JWKS
// endpoint on first use.
func (v *Verifier) resolveVerifier(ctx context.Context) (idjag.Verifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.verifier != nil {
		return v.verifier, nil
	}

	jwksURL := v.jwksURL
	if jwksURL == "" {
		jwksURL = v.discoverJWKSURL(ctx)
	}

	v.verifier = idjag.NewJWKSVerifier(jwksURL, v.opts).WithHTTPClient(v.httpClient)
	return v.verifier, nil
}

// discoverJWKSURL resolves the issuer's JWKS endpoint via OIDC discovery,
// then OAuth authorization server metadata, then the conventional path.
func (v *Verifier) discoverJWKSURL(ctx context.Context) string {
	base := strings.TrimSuffix(v.issuer, "/")

	for _, wellKnown := range []string{
		base + "/.well-known/openid-configuration",
		base + "/.well-known/oauth-authorization-server",
	} {
		jwksURL, err := fetchJWKSURI(ctx, v.httpClient, wellKnown)
		if err == nil && jwksURL != "" {
			return jwksURL
		}
	}

	// Conventional fallback used by the idjag reference servers.
	return base + "/.well-known/jwks.json"
}

func fetchJWKSURI(ctx context.Context, client *http.Client, metadataURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata fetch failed: status %d", resp.StatusCode)
	}

	var metadata struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return "", err
	}
	return metadata.JWKSURI, nil
}

// tokenInfoFromAssertion maps a verified idjag.Assertion into omniskill's
// TokenInfo, preserving the RFC 8693 delegation chain and extra claims.
func tokenInfoFromAssertion(token string, a *idjag.Assertion) *oauth2.TokenInfo {
	var actors []string
	for _, actor := range a.DelegationChain() {
		actors = append(actors, actor.Subject)
	}

	scope := ""
	claims := make(map[string]any, len(a.Claims)+3)
	for k, val := range a.Claims {
		claims[k] = val
	}
	if s, ok := claims["scope"].(string); ok {
		scope = s
	}
	claims["iss"] = a.Issuer
	if a.JWTID != "" {
		claims["jti"] = a.JWTID
	}
	if len(a.Audience) > 0 {
		claims["aud"] = a.Audience
	}

	return &oauth2.TokenInfo{
		AccessToken: token,
		TokenType:   "Bearer",
		ClientID:    a.ClientID,
		Subject:     a.Subject,
		Scope:       scope,
		Actor:       actors,
		Claims:      claims,
		ExpiresAt:   a.ExpiresAt,
		CreatedAt:   a.IssuedAt,
	}
}
