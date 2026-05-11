# Zitadel Adapter API Reference

Complete API documentation for the `adapters/zitadel` package.

## Package

```go
import "github.com/aistandardsio/agent-protocols/adapters/zitadel"
```

## TokenExchanger

Wraps Zitadel's token exchange with ID-JAG support.

### NewTokenExchanger

```go
func NewTokenExchanger(issuer string, opts ...TokenExchangerOption) (*TokenExchanger, error)
```

Creates a new token exchanger for the given Zitadel issuer. Uses OIDC discovery to find the token endpoint unless `WithStaticTokenEndpoint` is used.

### Methods

#### Issuer

```go
func (e *TokenExchanger) Issuer() string
```

Returns the Zitadel issuer URL.

#### TokenURL

```go
func (e *TokenExchanger) TokenURL() string
```

Returns the token endpoint URL.

#### ExchangeAssertion

```go
func (e *TokenExchanger) ExchangeAssertion(ctx context.Context, assertion string, opts ...ExchangeOption) (*TokenResponse, error)
```

Exchanges an ID-JAG assertion for an access token. The assertion should be a signed JWT.

#### ExchangeWithActor

```go
func (e *TokenExchanger) ExchangeWithActor(ctx context.Context, assertion, actorToken string, opts ...ExchangeOption) (*TokenResponse, error)
```

Exchanges an assertion with delegation (act claim support). The actorToken represents the identity of the acting party.

### TokenExchangerOption

```go
// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) TokenExchangerOption

// WithStaticTokenEndpoint skips OIDC discovery
func WithStaticTokenEndpoint(url string) TokenExchangerOption

// WithClientCredentials sets client authentication
func WithClientCredentials(clientID, clientSecret string) TokenExchangerOption
```

### ExchangeOption

```go
// WithScope sets the requested scope
func WithScope(scope string) ExchangeOption

// WithAudience sets the target audience
func WithAudience(audience string) ExchangeOption

// WithResource sets the target resource
func WithResource(resource string) ExchangeOption

// WithRequestedTokenType sets the requested token type
func WithRequestedTokenType(tokenType string) ExchangeOption
```

### TokenResponse

```go
type TokenResponse struct {
    AccessToken     string `json:"access_token"`
    IssuedTokenType string `json:"issued_token_type"`
    TokenType       string `json:"token_type"`
    ExpiresIn       int    `json:"expires_in,omitempty"`
    Scope           string `json:"scope,omitempty"`
    RefreshToken    string `json:"refresh_token,omitempty"`
    IDToken         string `json:"id_token,omitempty"`
}
```

---

## JWTProfileSource

Implements `oauth2.TokenSource` using ID-JAG assertions for JWT profile grants.

### NewJWTProfileSource

```go
func NewJWTProfileSource(issuer, clientID string, signer AssertionSigner, opts ...JWTProfileOption) (*JWTProfileSource, error)
```

Creates a token source for JWT profile grants.

### Methods

#### Token

```go
func (s *JWTProfileSource) Token() (*oauth2.Token, error)
```

Returns an access token, caching and refreshing as needed.

#### Invalidate

```go
func (s *JWTProfileSource) Invalidate()
```

Clears the cached token, forcing a new token request.

### JWTProfileOption

```go
// WithJWTProfileTokenEndpoint sets a static token endpoint
func WithJWTProfileTokenEndpoint(url string) JWTProfileOption

// WithJWTProfileScopes sets the requested scopes
func WithJWTProfileScopes(scopes ...string) JWTProfileOption

// WithJWTProfileHTTPClient sets a custom HTTP client
func WithJWTProfileHTTPClient(client *http.Client) JWTProfileOption
```

### AssertionSigner

Interface for signing JWT assertions.

```go
type AssertionSigner interface {
    SignAssertion(audience []string) (string, error)
}
```

### IDJAGAssertionSigner

Default implementation of `AssertionSigner` for ID-JAG assertions.

```go
func NewIDJAGAssertionSigner(
    issuer, subject string,
    method jwt.SigningMethod,
    privateKey interface{},
    keyID string,
    opts ...IDJAGSignerOption,
) *IDJAGAssertionSigner
```

#### IDJAGSignerOption

```go
// WithIDJAGSignerTTL sets the assertion TTL
func WithIDJAGSignerTTL(ttl time.Duration) IDJAGSignerOption
```

---

## Verifier

Validates tokens against Zitadel's JWKS.

### NewVerifier

```go
func NewVerifier(issuer string, opts ...VerifierOption) (*Verifier, error)
```

Creates a Zitadel-backed token verifier using OIDC discovery.

### Methods

#### Issuer

```go
func (v *Verifier) Issuer() string
```

Returns the issuer URL.

#### JWKSURL

```go
func (v *Verifier) JWKSURL() string
```

Returns the JWKS endpoint URL.

#### VerifyIDJAGAssertion

```go
func (v *Verifier) VerifyIDJAGAssertion(ctx context.Context, tokenString string) (*idjag.Assertion, error)
```

Verifies an ID-JAG assertion token.

#### VerifyAIMSWIT

```go
func (v *Verifier) VerifyAIMSWIT(ctx context.Context, tokenString string) (*aims.WorkloadIdentityToken, error)
```

Verifies an AIMS Workload Identity Token.

#### VerifyAAuthAgentToken

```go
func (v *Verifier) VerifyAAuthAgentToken(ctx context.Context, tokenString string) (*aauth.AgentToken, error)
```

Verifies an AAuth agent token.

### VerifierOption

```go
// WithStaticJWKSURL skips OIDC discovery
func WithStaticJWKSURL(url string) VerifierOption

// WithClockSkew allows clock drift
func WithClockSkew(d time.Duration) VerifierOption

// WithAllowedAlgorithms restricts signing algorithms
func WithAllowedAlgorithms(algs ...string) VerifierOption

// WithRequiredAudience requires specific audience
func WithRequiredAudience(aud string) VerifierOption

// WithVerifierHTTPClient sets a custom HTTP client
func WithVerifierHTTPClient(client *http.Client) VerifierOption
```

---

## Middleware

HTTP middleware for Zitadel token validation.

### NewMiddleware

```go
func NewMiddleware(verifier *Verifier, opts MiddlewareOptions) *Middleware
```

Creates authentication middleware.

### Protocol-Specific Constructors

```go
// RequireIDJAG creates middleware for ID-JAG assertions
func RequireIDJAG(verifier *Verifier, opts MiddlewareOptions) *Middleware

// RequireAIMS creates middleware for AIMS WITs
func RequireAIMS(verifier *Verifier, opts MiddlewareOptions) *Middleware

// RequireAAuth creates middleware for AAuth agent tokens
func RequireAAuth(verifier *Verifier, opts MiddlewareOptions) *Middleware
```

### Methods

#### Handler

```go
func (m *Middleware) Handler(next http.Handler) http.Handler
```

Wraps an `http.Handler` with token validation.

### MiddlewareOptions

```go
type MiddlewareOptions struct {
    // RequiredAudience requires a specific audience claim
    RequiredAudience string

    // AllowAnonymous allows unauthenticated requests
    AllowAnonymous bool

    // ErrorHandler handles authentication errors
    ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
}
```

### Context Helpers

```go
// IDJAGAssertionFromContext extracts ID-JAG assertion
func IDJAGAssertionFromContext(ctx context.Context) (*idjag.Assertion, bool)

// AIMSWITFromContext extracts AIMS WIT
func AIMSWITFromContext(ctx context.Context) (*aims.WorkloadIdentityToken, bool)

// AAuthTokenFromContext extracts AAuth agent token
func AAuthTokenFromContext(ctx context.Context) (*aauth.AgentToken, bool)
```

---

## Errors

```go
var (
    // ErrDiscoveryFailed indicates OIDC discovery failed
    ErrDiscoveryFailed = errors.New("zitadel: OIDC discovery failed")

    // ErrTokenExchangeFailed indicates token exchange failed
    ErrTokenExchangeFailed = errors.New("zitadel: token exchange failed")

    // ErrVerificationFailed indicates token verification failed
    ErrVerificationFailed = errors.New("zitadel: token verification failed")

    // ErrInvalidTokenType indicates wrong token type
    ErrInvalidTokenType = errors.New("zitadel: invalid token type")

    // ErrMissingToken indicates no token in request
    ErrMissingToken = errors.New("zitadel: missing bearer token")
)
```

---

## Constants

### Grant Types

```go
const (
    GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
    GrantTypeJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)
```

### Token Types

```go
const (
    TokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
    TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
    TokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"
)
```

### OAuth Error Codes

```go
const (
    ErrorInvalidRequest = "invalid_request"
    ErrorInvalidGrant   = "invalid_grant"
    ErrorInvalidClient  = "invalid_client"
    ErrorInvalidScope   = "invalid_scope"
)
```
