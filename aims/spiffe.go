package aims

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// SPIFFE ID errors.
var (
	ErrInvalidSPIFFEID        = errors.New("invalid SPIFFE ID")
	ErrEmptyTrustDomain       = errors.New("trust domain cannot be empty")
	ErrInvalidScheme          = errors.New("SPIFFE ID must use 'spiffe' scheme")
	ErrPathContainsQuery      = errors.New("SPIFFE ID path cannot contain query parameters")
	ErrPathContainsFragment   = errors.New("SPIFFE ID path cannot contain fragments")
	ErrTrustDomainHasPort     = errors.New("trust domain cannot contain port")
	ErrTrustDomainHasUserInfo = errors.New("trust domain cannot contain user info")
)

// SPIFFEScheme is the URI scheme for SPIFFE IDs.
const SPIFFEScheme = "spiffe"

// Common path prefixes for SPIFFE IDs.
const (
	PathPrefixAgent    = "/agent/"
	PathPrefixWorkload = "/workload/"
	PathPrefixService  = "/service/"
	PathPrefixUser     = "/user/"
)

// SPIFFEID represents a SPIFFE identity URI.
// Format: spiffe://<trust-domain>/<path>
//
// The trust domain identifies the trust root (e.g., "example.com").
// The path identifies the specific workload within that domain.
type SPIFFEID struct {
	// TrustDomain is the identity's trust domain (e.g., "example.com").
	TrustDomain string

	// Path is the workload path (e.g., "/agent/calendar-bot").
	// It must start with "/" if non-empty.
	Path string
}

// ParseSPIFFEID parses a SPIFFE ID string into its components.
// The input must be a valid SPIFFE ID URI per the SPIFFE specification.
//
// Valid examples:
//
//	spiffe://example.com
//	spiffe://example.com/agent/calendar-bot
//	spiffe://prod.example.com/workload/api-server
func ParseSPIFFEID(uri string) (*SPIFFEID, error) {
	if uri == "" {
		return nil, ErrInvalidSPIFFEID
	}

	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSPIFFEID, err)
	}

	// Validate scheme
	if u.Scheme != SPIFFEScheme {
		return nil, ErrInvalidScheme
	}

	// Trust domain is the host
	trustDomain := u.Host
	if trustDomain == "" {
		return nil, ErrEmptyTrustDomain
	}

	// Check for disallowed components
	if u.User != nil {
		return nil, ErrTrustDomainHasUserInfo
	}
	if strings.Contains(u.Host, ":") {
		return nil, ErrTrustDomainHasPort
	}
	if u.RawQuery != "" {
		return nil, ErrPathContainsQuery
	}
	if u.Fragment != "" {
		return nil, ErrPathContainsFragment
	}

	return &SPIFFEID{
		TrustDomain: trustDomain,
		Path:        u.Path,
	}, nil
}

// MustParseSPIFFEID parses a SPIFFE ID string, panicking on error.
// Use only when the input is known to be valid (e.g., constants).
func MustParseSPIFFEID(uri string) *SPIFFEID {
	id, err := ParseSPIFFEID(uri)
	if err != nil {
		panic(err)
	}
	return id
}

// NewSPIFFEID creates a SPIFFE ID from trust domain and path components.
// The path must start with "/" if non-empty.
func NewSPIFFEID(trustDomain, path string) (*SPIFFEID, error) {
	if trustDomain == "" {
		return nil, ErrEmptyTrustDomain
	}

	// Validate trust domain doesn't contain invalid chars
	if strings.Contains(trustDomain, ":") {
		return nil, ErrTrustDomainHasPort
	}
	if strings.Contains(trustDomain, "@") {
		return nil, ErrTrustDomainHasUserInfo
	}

	// Normalize path
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return &SPIFFEID{
		TrustDomain: trustDomain,
		Path:        path,
	}, nil
}

// String returns the SPIFFE ID as a URI string.
func (s *SPIFFEID) String() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("%s://%s%s", SPIFFEScheme, s.TrustDomain, s.Path)
}

// URI returns the SPIFFE ID as a *url.URL.
func (s *SPIFFEID) URI() *url.URL {
	if s == nil {
		return nil
	}
	return &url.URL{
		Scheme: SPIFFEScheme,
		Host:   s.TrustDomain,
		Path:   s.Path,
	}
}

// IsAgent returns true if the path indicates this is an agent identity.
// Agent identities typically have paths starting with "/agent/".
func (s *SPIFFEID) IsAgent() bool {
	if s == nil {
		return false
	}
	return strings.HasPrefix(s.Path, PathPrefixAgent)
}

// IsWorkload returns true if the path indicates this is a workload identity.
// Workload identities typically have paths starting with "/workload/".
func (s *SPIFFEID) IsWorkload() bool {
	if s == nil {
		return false
	}
	return strings.HasPrefix(s.Path, PathPrefixWorkload)
}

// IsService returns true if the path indicates this is a service identity.
// Service identities typically have paths starting with "/service/".
func (s *SPIFFEID) IsService() bool {
	if s == nil {
		return false
	}
	return strings.HasPrefix(s.Path, PathPrefixService)
}

// IsUser returns true if the path indicates this is a user identity.
// User identities typically have paths starting with "/user/".
func (s *SPIFFEID) IsUser() bool {
	if s == nil {
		return false
	}
	return strings.HasPrefix(s.Path, PathPrefixUser)
}

// Name returns the final component of the path (the workload name).
// For example, "/agent/calendar-bot" returns "calendar-bot".
func (s *SPIFFEID) Name() string {
	if s == nil || s.Path == "" {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(s.Path, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// Equal returns true if two SPIFFE IDs are equal.
func (s *SPIFFEID) Equal(other *SPIFFEID) bool {
	if s == nil && other == nil {
		return true
	}
	if s == nil || other == nil {
		return false
	}
	return s.TrustDomain == other.TrustDomain && s.Path == other.Path
}

// InTrustDomain returns true if this SPIFFE ID belongs to the given trust domain.
func (s *SPIFFEID) InTrustDomain(domain string) bool {
	if s == nil {
		return false
	}
	return s.TrustDomain == domain
}

// MemberOf returns true if this SPIFFE ID's path starts with the given prefix.
func (s *SPIFFEID) MemberOf(pathPrefix string) bool {
	if s == nil {
		return false
	}
	return strings.HasPrefix(s.Path, pathPrefix)
}
