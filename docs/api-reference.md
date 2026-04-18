# API Reference

Complete reference for the `idjag` package.

## Assertion

### Types

#### Assertion

```go
type Assertion struct {
    Issuer    string         // iss claim
    Subject   string         // sub claim
    Audience  []string       // aud claim
    IssuedAt  time.Time      // iat claim
    ExpiresAt time.Time      // exp claim
    NotBefore time.Time      // nbf claim (optional)
    JWTID     string         // jti claim (optional)
    Actor     *Actor         // act claim (optional, for delegation)
    Claims    map[string]any // Additional custom claims
}
```

#### Actor

```go
type Actor struct {
    Subject string  // sub claim within act
    Issuer  string  // iss claim within act (optional)
    Actor   *Actor  // Nested delegation (optional)
}
```

### Functions

#### NewAssertion

```go
func NewAssertion(issuer, subject string, audience []string, ttl time.Duration) *Assertion
```

Creates a new assertion with standard claims.

#### NewDelegatedAssertion

```go
func NewDelegatedAssertion(issuer, subject, actorSubject string, audience []string, ttl time.Duration) *Assertion
```

Creates an assertion with delegation (act claim).

### Methods

#### Sign

```go
func (a *Assertion) Sign(method jwt.SigningMethod, key crypto.PrivateKey, keyID string) (string, error)
```

Signs the assertion and returns a JWT string.

#### IsExpired

```go
func (a *Assertion) IsExpired() bool
```

Returns true if the assertion has expired.

#### IsDelegated

```go
func (a *Assertion) IsDelegated() bool
```

Returns true if the assertion has an actor claim.

#### DelegationChain

```go
func (a *Assertion) DelegationChain() []*Actor
```

Returns the full delegation chain from outermost to innermost actor.

## Verifier

### Interfaces

#### Verifier

```go
type Verifier interface {
    Verify(ctx context.Context, tokenString string) (*Assertion, error)
}
```

### Types

#### VerifierOptions

```go
type VerifierOptions struct {
    ExpectedIssuer    string
    ExpectedAudience  string
    AllowedAlgorithms []string
    ClockSkew         time.Duration
    RequireActor      bool
}
```

#### StaticKeyVerifier

Verifies JWTs using a pre-configured public key.

```go
func NewStaticKeyVerifier(publicKey crypto.PublicKey, keyID string, opts VerifierOptions) *StaticKeyVerifier
```

#### JWKSVerifier

Verifies JWTs using keys fetched from a JWKS endpoint.

```go
func NewJWKSVerifier(jwksURL string, opts VerifierOptions) *JWKSVerifier
```

## Token Exchange

### Types

#### TokenExchangeClient

```go
type TokenExchangeClient struct {
    TokenURL     string
    HTTPClient   *http.Client
    ClientID     string
    ClientSecret string
}
```

#### TokenExchangeRequest

```go
type TokenExchangeRequest struct {
    SubjectToken       string
    SubjectTokenType   string
    ActorToken         string
    ActorTokenType     string
    RequestedTokenType string
    Scope              string
    Resource           string
    Audience           string
}
```

#### TokenExchangeResponse

```go
type TokenExchangeResponse struct {
    AccessToken     string
    IssuedTokenType string
    TokenType       string
    ExpiresIn       int
    Scope           string
    RefreshToken    string
}
```

### Functions

#### NewTokenExchangeClient

```go
func NewTokenExchangeClient(tokenURL string) *TokenExchangeClient
```

### Methods

#### Exchange

```go
func (c *TokenExchangeClient) Exchange(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeResponse, error)
```

Performs a full token exchange request.

#### ExchangeAssertion

```go
func (c *TokenExchangeClient) ExchangeAssertion(ctx context.Context, assertion string, scope string) (*TokenExchangeResponse, error)
```

Convenience method for exchanging an ID-JAG assertion.

## Server

### Types

#### AuthorizationServer

```go
type AuthorizationServer struct {
    Verifier       Verifier
    SigningMethod  jwt.SigningMethod
    SigningKey     crypto.PrivateKey
    KeyID          string
    Issuer         string
    TokenTTL       time.Duration
    AllowedScopes  []string
    ScopeValidator func(assertion *Assertion, requestedScope string) error
}
```

Implements `http.Handler` for the token endpoint.

#### ResourceServer

```go
type ResourceServer struct {
    Verifier Verifier
}
```

Provides middleware for validating Bearer tokens.

#### JWKSHandler

```go
type JWKSHandler struct {
    // ...
}
```

Serves a JWKS endpoint. Implements `http.Handler`.

### Functions

#### NewAuthorizationServer

```go
func NewAuthorizationServer(verifier Verifier, signingMethod jwt.SigningMethod, signingKey crypto.PrivateKey, keyID, issuer string) *AuthorizationServer
```

#### NewResourceServer

```go
func NewResourceServer(verifier Verifier) *ResourceServer
```

#### NewJWKSHandler

```go
func NewJWKSHandler(jwks *JWKS) *JWKSHandler
```

### Context Functions

#### ContextWithAssertion

```go
func ContextWithAssertion(ctx context.Context, assertion *Assertion) context.Context
```

Adds an assertion to the context.

#### AssertionFromContext

```go
func AssertionFromContext(ctx context.Context) *Assertion
```

Retrieves an assertion from the context.

## JWKS

### Types

#### JWKS

```go
type JWKS struct {
    Keys []JWK
}
```

#### JWK

```go
type JWK struct {
    KeyType   string // "RSA" or "EC"
    KeyID     string
    Algorithm string
    Use       string
    N, E      string // RSA parameters
    Curve     string // EC curve name
    X, Y      string // EC coordinates
}
```

### Functions

#### NewJWKFromRSAPublicKey

```go
func NewJWKFromRSAPublicKey(pubKey *rsa.PublicKey, keyID, algorithm string) JWK
```

#### NewJWKFromECPublicKey

```go
func NewJWKFromECPublicKey(pubKey *ecdsa.PublicKey, keyID, algorithm string) JWK
```

## Errors

```go
var (
    ErrInvalidAssertion     error
    ErrExpiredAssertion     error
    ErrInvalidIssuer        error
    ErrInvalidAudience      error
    ErrInvalidSubject       error
    ErrSignatureInvalid     error
    ErrKeyNotFound          error
    ErrTokenExchangeFailed  error
    ErrUnsupportedAlgorithm error
    ErrMissingRequiredClaim error
)
```

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
    TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
    TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
    TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
    TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)
```

### Algorithms

```go
const (
    AlgorithmRS256 = "RS256"
    AlgorithmRS384 = "RS384"
    AlgorithmRS512 = "RS512"
    AlgorithmES256 = "ES256"
    AlgorithmES384 = "ES384"
    AlgorithmES512 = "ES512"
)
```
