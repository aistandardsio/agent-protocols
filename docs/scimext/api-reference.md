# API Reference

Complete API reference for the SCIM Agent Extension Go client.

## Package scimext

The main package provides the client and configuration options.

### Client

```go
type Client struct {
    // contains filtered or unexported fields
}
```

The Client provides access to the SCIM Agent Extension API.

#### NewClient

```go
func NewClient(opts ...Option) (*Client, error)
```

Creates a new SCIM Agent Extension client.

**Example:**

```go
client, err := scimext.NewClient(
    scimext.WithBaseURL("https://scim.example.com/v2"),
    scimext.WithBearerToken("token"),
)
```

#### Client.Agents

```go
func (c *Client) Agents() *agents.Service
```

Returns the agents service for managing Agent resources.

#### Client.Applications

```go
func (c *Client) Applications() *applications.Service
```

Returns the applications service for managing AgenticApplication resources.

#### Client.API

```go
func (c *Client) API() *api.Client
```

Returns the underlying ogen API client for advanced use cases.

### Options

#### WithBaseURL

```go
func WithBaseURL(url string) Option
```

Sets the base URL for the SCIM server.

#### WithBearerToken

```go
func WithBearerToken(token string) Option
```

Sets the bearer token for authentication.

#### WithHTTPClient

```go
func WithHTTPClient(client *http.Client) Option
```

Sets the HTTP client to use for requests.

#### WithTimeout

```go
func WithTimeout(timeout time.Duration) Option
```

Sets the timeout for HTTP requests.

### Errors

```go
var (
    ErrNotFound     = errors.New("scimext: resource not found")
    ErrUnauthorized = errors.New("scimext: unauthorized")
    ErrForbidden    = errors.New("scimext: forbidden")
    ErrConflict     = errors.New("scimext: conflict")
    ErrBadRequest   = errors.New("scimext: bad request")
)
```

#### Error Helpers

```go
func IsNotFound(err error) bool
func IsUnauthorized(err error) bool
func IsForbidden(err error) bool
func IsConflict(err error) bool
func IsBadRequest(err error) bool
```

---

## Package agents

The agents package provides operations for managing SCIM Agent resources.

### Service

```go
type Service struct {
    // contains filtered or unexported fields
}
```

#### Service.Create

```go
func (s *Service) Create(ctx context.Context, req *CreateRequest) (*Agent, error)
```

Creates a new agent.

#### Service.Get

```go
func (s *Service) Get(ctx context.Context, id string) (*Agent, error)
```

Retrieves an agent by ID.

#### Service.List

```go
func (s *Service) List(ctx context.Context, opts *ListOptions) (*ListResponse, error)
```

Retrieves a list of agents.

#### Service.Replace

```go
func (s *Service) Replace(ctx context.Context, id string, req *CreateRequest) (*Agent, error)
```

Replaces an existing agent entirely.

#### Service.Delete

```go
func (s *Service) Delete(ctx context.Context, id string) error
```

Deletes an agent.

### Types

#### Agent

```go
type Agent struct {
    ID           string
    ExternalID   string
    Name         string
    DisplayName  string
    Description  string
    AgentType    string
    Active       bool
    Subject      string
    Groups       []GroupRef
    Entitlements []Entitlement
    Roles        []Role
    X509Certs    []X509Certificate
    Applications []ApplicationRef
    Protocols    []Protocol
    Parent       *Reference
    Owners       []Reference
    Meta         *Meta
}
```

#### CreateRequest

```go
type CreateRequest struct {
    ExternalID   string
    Name         string // Required
    DisplayName  string
    Description  string
    AgentType    string
    Active       bool
    Subject      string
    Entitlements []Entitlement
    Roles        []Role
    X509Certs    []X509Certificate
    Protocols    []Protocol
    Parent       *Reference
    Owners       []Reference
}
```

#### ListOptions

```go
type ListOptions struct {
    Filter             string
    StartIndex         int
    Count              int
    SortBy             string
    SortOrder          string // "ascending" or "descending"
    Attributes         string
    ExcludedAttributes string
}
```

#### ListResponse

```go
type ListResponse struct {
    TotalResults int
    StartIndex   int
    ItemsPerPage int
    Resources    []*Agent
}
```

#### Protocol

```go
type Protocol struct {
    Type             string // "A2A", "OpenAPI", "MCP-Server"
    SpecificationURL string
}
```

#### Reference

```go
type Reference struct {
    Value   string
    Ref     string
    Display string
}
```

#### Meta

```go
type Meta struct {
    ResourceType string
    Created      string
    LastModified string
    Location     string
    Version      string
}
```

---

## Package applications

The applications package provides operations for managing SCIM AgenticApplication resources.

### Service

```go
type Service struct {
    // contains filtered or unexported fields
}
```

#### Service.Create

```go
func (s *Service) Create(ctx context.Context, req *CreateRequest) (*AgenticApplication, error)
```

Creates a new agentic application.

#### Service.Get

```go
func (s *Service) Get(ctx context.Context, id string) (*AgenticApplication, error)
```

Retrieves an agentic application by ID.

#### Service.List

```go
func (s *Service) List(ctx context.Context, opts *ListOptions) (*ListResponse, error)
```

Retrieves a list of agentic applications.

#### Service.Replace

```go
func (s *Service) Replace(ctx context.Context, id string, req *CreateRequest) (*AgenticApplication, error)
```

Replaces an existing agentic application entirely.

#### Service.Delete

```go
func (s *Service) Delete(ctx context.Context, id string) error
```

Deletes an agentic application.

### Types

#### AgenticApplication

```go
type AgenticApplication struct {
    ID                  string
    ExternalID          string
    Name                string
    DisplayName         string
    Description         string
    Active              bool
    ApplicationURLs     []ApplicationURL
    LastAccessed        string
    OAuthConfigurations []OAuthConfiguration
    Agents              []AgentRef
    ExternalIdentifiers []ExternalIdentifier
    Meta                *Meta
}
```

#### CreateRequest

```go
type CreateRequest struct {
    ExternalID          string
    Name                string // Required
    DisplayName         string
    Description         string
    Active              bool
    ApplicationURLs     []ApplicationURL
    OAuthConfigurations []OAuthConfiguration
    Agents              []AgentRef
    ExternalIdentifiers []ExternalIdentifier
}
```

#### ApplicationURL

```go
type ApplicationURL struct {
    Type        string // "ssoEndpoint", "loginPage", "api", "homepage"
    Primary     bool
    Value       string
    Description string
}
```

#### OAuthConfiguration

```go
type OAuthConfiguration struct {
    ClientID     string
    Description  string
    AudienceURI  string
    IssuerURI    string
    RedirectURIs []string
}
```

#### AgentRef

```go
type AgentRef struct {
    Value   string
    Ref     string
    Display string
    Type    string // "owned", "authorized", "guest"
}
```

#### ExternalIdentifier

```go
type ExternalIdentifier struct {
    Type   string
    Value  string
    System string
}
```

#### ListOptions

```go
type ListOptions struct {
    Filter             string
    StartIndex         int
    Count              int
    SortBy             string
    SortOrder          string // "ascending" or "descending"
    Attributes         string
    ExcludedAttributes string
}
```

#### ListResponse

```go
type ListResponse struct {
    TotalResults int
    StartIndex   int
    ItemsPerPage int
    Resources    []*AgenticApplication
}
```

---

## SCIM Filter Syntax

The `Filter` option in list operations supports SCIM filter expressions:

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equal | `name eq 'my-agent'` |
| `ne` | Not equal | `active ne false` |
| `co` | Contains | `name co 'assistant'` |
| `sw` | Starts with | `name sw 'prod-'` |
| `ew` | Ends with | `name ew '-bot'` |
| `pr` | Present | `displayName pr` |
| `gt` | Greater than | `meta.created gt "2024-01-01"` |
| `ge` | Greater or equal | `meta.created ge "2024-01-01"` |
| `lt` | Less than | `meta.created lt "2024-12-31"` |
| `le` | Less or equal | `meta.created le "2024-12-31"` |
| `and` | Logical AND | `active eq true and agentType eq 'Assistant'` |
| `or` | Logical OR | `agentType eq 'Assistant' or agentType eq 'Researcher'` |
| `not` | Logical NOT | `not (active eq false)` |

**Examples:**

```go
// Find active assistants
opts := &agents.ListOptions{
    Filter: "active eq true and agentType eq 'Assistant'",
}

// Find agents by external ID
opts := &agents.ListOptions{
    Filter: "externalId eq '12345'",
}

// Find applications with specific URL
opts := &applications.ListOptions{
    Filter: "applicationUrls.value eq 'https://api.example.com'",
}
```
