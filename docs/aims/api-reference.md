# API Reference

Complete reference for the `aims` package.

## SPIFFE ID

### Types

#### SPIFFEID

```go
type SPIFFEID struct {
    TrustDomain string  // e.g., "example.com"
    Path        string  // e.g., "/agent/calendar-bot"
}
```

### Functions

#### ParseSPIFFEID

```go
func ParseSPIFFEID(uri string) (*SPIFFEID, error)
```

Parses a SPIFFE ID string into its components.

#### MustParseSPIFFEID

```go
func MustParseSPIFFEID(uri string) *SPIFFEID
```

Parses a SPIFFE ID string, panicking on error. Use for constants.

#### NewSPIFFEID

```go
func NewSPIFFEID(trustDomain, path string) (*SPIFFEID, error)
```

Creates a SPIFFE ID from trust domain and path components.

### Methods

#### String

```go
func (s *SPIFFEID) String() string
```

Returns the SPIFFE ID as a URI string.

#### URI

```go
func (s *SPIFFEID) URI() *url.URL
```

Returns the SPIFFE ID as a `*url.URL`.

#### IsAgent / IsWorkload / IsService / IsUser

```go
func (s *SPIFFEID) IsAgent() bool
func (s *SPIFFEID) IsWorkload() bool
func (s *SPIFFEID) IsService() bool
func (s *SPIFFEID) IsUser() bool
```

Returns true if the path indicates the identity type.

#### Name

```go
func (s *SPIFFEID) Name() string
```

Returns the final component of the path (workload name).

#### Equal

```go
func (s *SPIFFEID) Equal(other *SPIFFEID) bool
```

Returns true if two SPIFFE IDs are equal.

#### InTrustDomain

```go
func (s *SPIFFEID) InTrustDomain(domain string) bool
```

Returns true if this SPIFFE ID belongs to the given trust domain.

### Constants

```go
const SPIFFEScheme = "spiffe"

const (
    PathPrefixAgent    = "/agent/"
    PathPrefixWorkload = "/workload/"
    PathPrefixService  = "/service/"
    PathPrefixUser     = "/user/"
)
```

## Workload Identity Token (WIT)

### Types

#### WorkloadIdentityToken

```go
type WorkloadIdentityToken struct {
    Issuer    string    `json:"iss"`    // Trust domain issuer
    Subject   string    `json:"sub"`    // SPIFFE ID
    Audience  []string  `json:"aud"`    // Intended recipients
    Expiry    time.Time `json:"exp"`
    IssuedAt  time.Time `json:"iat"`
    NotBefore time.Time `json:"nbf,omitempty"`
    JWTID     string    `json:"jti,omitempty"`
    CNF       *CNF      `json:"cnf,omitempty"`  // Confirmation key
}
```

#### CNF

```go
type CNF struct {
    JWK json.RawMessage `json:"jwk,omitempty"`     // Embedded JWK
    Kid string          `json:"kid,omitempty"`     // Key ID reference
    X5T string          `json:"x5t#S256,omitempty"` // X.509 thumbprint
}
```

### Functions

#### NewWIT

```go
func NewWIT(spiffeID *SPIFFEID, audience []string, ttl time.Duration, opts ...WITOption) *WorkloadIdentityToken
```

Creates a new Workload Identity Token.

#### GenerateJTI

```go
func GenerateJTI() string
```

Generates a random JWT ID.

### WITOption Functions

```go
func WithWITJTI(jti string) WITOption
func WithWITNotBefore(nbf time.Time) WITOption
func WithWITCNF(cnf *CNF) WITOption
```

### Methods

#### Sign

```go
func (w *WorkloadIdentityToken) Sign(signer crypto.Signer, keyID string) (string, error)
```

Creates a signed JWT string from this WIT.

#### Validate

```go
func (w *WorkloadIdentityToken) Validate() error
```

Checks if the WIT has all required fields and is temporally valid.

#### SPIFFEID

```go
func (w *WorkloadIdentityToken) SPIFFEID() (*SPIFFEID, error)
```

Returns the SPIFFE ID from the subject claim.

#### IsExpired

```go
func (w *WorkloadIdentityToken) IsExpired() bool
```

Returns true if the token has expired.

#### TimeToExpiry

```go
func (w *WorkloadIdentityToken) TimeToExpiry() time.Duration
```

Returns the duration until this token expires.

## WIMSE Proof Token (WPT)

### Types

#### WIMSEProofToken

```go
type WIMSEProofToken struct {
    Issuer   string    `json:"iss"`   // Must match WIT subject
    Audience string    `json:"aud"`   // Target service
    IssuedAt time.Time `json:"iat"`
    Expiry   time.Time `json:"exp,omitempty"`
    JWTID    string    `json:"jti,omitempty"`
    Nonce    string    `json:"nonce,omitempty"`
    HTM      string    `json:"htm"`   // HTTP method
    HTU      string    `json:"htu"`   // HTTP URI
    ATH      string    `json:"ath,omitempty"` // Access token hash
}
```

### Constants

```go
const (
    HeaderWPT  = "Workload-Identity-Token"
    HeaderDPoP = "DPoP"
)
```

### Functions

#### NewWPT

```go
func NewWPT(issuer, audience, method, uri string, opts ...WPTOption) *WIMSEProofToken
```

Creates a new WIMSE Proof Token for an HTTP request.

#### NewWPTFromWIT

```go
func NewWPTFromWIT(wit *WorkloadIdentityToken, audience, method, uri string, opts ...WPTOption) *WIMSEProofToken
```

Creates a WPT bound to a WIT.

#### NewWPTForRequest

```go
func NewWPTForRequest(issuer, audience string, r *http.Request, opts ...WPTOption) *WIMSEProofToken
```

Creates a WPT bound to an `http.Request`.

#### WPTFromHeader

```go
func WPTFromHeader(r *http.Request) string
```

Extracts a WPT JWT from an HTTP header.

### WPTOption Functions

```go
func WithWPTNonce(nonce string) WPTOption
func WithWPTJTI(jti string) WPTOption
func WithWPTExpiry(exp time.Time) WPTOption
func WithWPTAccessToken(accessToken string) WPTOption
```

### Methods

#### Sign

```go
func (p *WIMSEProofToken) Sign(signer crypto.Signer, keyID string) (string, error)
```

Creates a signed JWT string from this WPT.

#### BindToRequest

```go
func (p *WIMSEProofToken) BindToRequest(r *http.Request, signer crypto.Signer, keyID string) error
```

Adds the WPT to an HTTP request header.

#### Validate

```go
func (p *WIMSEProofToken) Validate() error
```

Checks if the WPT has all required fields.

#### MatchesRequest

```go
func (p *WIMSEProofToken) MatchesRequest(r *http.Request) bool
```

Checks if this WPT matches the given HTTP request.

#### IsExpired

```go
func (p *WIMSEProofToken) IsExpired() bool
```

Returns true if the proof token has expired.

## Credentials

### Interfaces

#### Credential

```go
type Credential interface {
    Type() CredentialType
    SPIFFEID() *SPIFFEID
    IsExpired() bool
    ExpiresAt() time.Time
}
```

### Types

#### CredentialType

```go
type CredentialType string

const (
    CredentialX509SVID CredentialType = "x509-svid"
    CredentialJWTSVID  CredentialType = "jwt-svid"
    CredentialWIT      CredentialType = "wit"
)
```

#### X509SVID

```go
type X509SVID struct {
    Certificates []*x509.Certificate
    PrivateKey   crypto.PrivateKey
}
```

X.509 SPIFFE Verifiable Identity Document for mTLS authentication.

#### JWTSVID

```go
type JWTSVID struct {
    Token string
}
```

JWT-based SPIFFE Verifiable Identity Document.

### Functions

#### NewX509SVID

```go
func NewX509SVID(certs []*x509.Certificate, key crypto.PrivateKey) (*X509SVID, error)
```

Creates an X509SVID from a certificate chain and private key.

#### NewJWTSVID

```go
func NewJWTSVID(token string, spiffeID *SPIFFEID, expiry time.Time) *JWTSVID
```

Creates a JWTSVID from its components.

### X509SVID Methods

#### LeafCertificate

```go
func (s *X509SVID) LeafCertificate() *x509.Certificate
```

Returns the leaf (end-entity) certificate.

## Agent Identity

### Types

#### AgentIdentity

```go
type AgentIdentity struct {
    SPIFFEID    *SPIFFEID
    Credential  Credential
    Attestation *Attestation
    Metadata    map[string]string
    CreatedAt   time.Time
}
```

Represents a fully-attested agent identity.

### Functions

#### NewAgentIdentity

```go
func NewAgentIdentity(spiffeID *SPIFFEID, cred Credential, opts ...IdentityOption) *AgentIdentity
```

Creates an agent identity from a SPIFFE ID and credential.

### IdentityOption Functions

```go
func WithAttestation(att *Attestation) IdentityOption
func WithMetadata(key, value string) IdentityOption
```

### Methods

#### IsValid

```go
func (ai *AgentIdentity) IsValid() bool
```

Checks if the identity is currently valid.

#### ExpiresAt

```go
func (ai *AgentIdentity) ExpiresAt() time.Time
```

Returns when this identity expires.

#### TimeToExpiry

```go
func (ai *AgentIdentity) TimeToExpiry() time.Duration
```

Returns the duration until this identity expires.

## Attestation

### Types

#### AttestationType

```go
type AttestationType string

const (
    AttestationTPM        AttestationType = "tpm"
    AttestationSGX        AttestationType = "sgx"
    AttestationSEVSNP     AttestationType = "sev-snp"
    AttestationTDX        AttestationType = "tdx"
    AttestationKubernetes AttestationType = "kubernetes"
    AttestationAWS        AttestationType = "aws"
    AttestationGCP        AttestationType = "gcp"
    AttestationAzure      AttestationType = "azure"
    AttestationGitHub     AttestationType = "github"
    AttestationUnix       AttestationType = "unix"
    AttestationDocker     AttestationType = "docker"
)
```

#### Attestation

```go
type Attestation struct {
    Type       AttestationType
    Evidence   []byte
    Timestamp  time.Time
    Attributes map[string]string
}
```

### Functions

#### NewAttestation

```go
func NewAttestation(attestType AttestationType, evidence []byte) *Attestation
```

Creates a new attestation with the given type and evidence.

#### NewAttestationWithOptions

```go
func NewAttestationWithOptions(attestType AttestationType, evidence []byte, opts ...AttestationOption) *Attestation
```

Creates an attestation with options.

### AttestationOption Functions

```go
func WithAttestationTimestamp(t time.Time) AttestationOption
func WithAttribute(key, value string) AttestationOption
```

### Methods

#### Age

```go
func (a *Attestation) Age() time.Duration
```

Returns how old the attestation is.

#### IsFresh

```go
func (a *Attestation) IsFresh(maxAge time.Duration) bool
```

Returns true if the attestation is younger than the given duration.

#### GetAttribute

```go
func (a *Attestation) GetAttribute(key string) (string, bool)
```

Returns an attestation attribute value.

### AttestationType Methods

#### Description

```go
func (at AttestationType) Description() string
```

Returns a human-readable description.

#### IsHardware

```go
func (at AttestationType) IsHardware() bool
```

Returns true for hardware-based attestation (TPM, SGX, SEV-SNP, TDX).

#### IsCloud

```go
func (at AttestationType) IsCloud() bool
```

Returns true for cloud provider attestation (AWS, GCP, Azure).

### Attribute Keys

```go
const (
    AttrInstanceID     = "instance-id"
    AttrRegion         = "region"
    AttrAccountID      = "account-id"
    AttrNamespace      = "namespace"
    AttrServiceAccount = "service-account"
    AttrPodName        = "pod-name"
    AttrContainerID    = "container-id"
    AttrImageDigest    = "image-digest"
    AttrPCR0           = "pcr0"
    AttrMRENCLAVE      = "mrenclave"
    AttrMRSIGNER       = "mrsigner"
)
```

## AIMS Layers

### Types

#### Layer

```go
type Layer int

const (
    LayerIdentifiers    Layer = iota + 1
    LayerCredentials
    LayerAttestation
    LayerProvisioning
    LayerAuthentication
    LayerAuthorization
    LayerMonitoring
    LayerPolicy
    LayerCompliance
)
```

### Functions

#### AllLayers

```go
func AllLayers() []Layer
```

Returns all 9 AIMS layers in order.

### Methods

#### String

```go
func (l Layer) String() string
```

Returns the human-readable name of the layer.

#### Description

```go
func (l Layer) Description() string
```

Returns a brief description of the layer's purpose.

## Errors

```go
var (
    // SPIFFE ID errors
    ErrInvalidSPIFFEID        error
    ErrEmptyTrustDomain       error
    ErrInvalidScheme          error
    ErrPathContainsQuery      error
    ErrPathContainsFragment   error
    ErrTrustDomainHasPort     error
    ErrTrustDomainHasUserInfo error

    // WIT errors
    ErrWITMissingSubject  error
    ErrWITMissingIssuer   error
    ErrWITMissingAudience error
    ErrWITExpired         error
    ErrWITNotYetValid     error

    // WPT errors
    ErrWPTMissingIssuer   error
    ErrWPTMissingAudience error
    ErrWPTMissingHTM      error
    ErrWPTMissingHTU      error
    ErrWPTExpired         error
)
```
