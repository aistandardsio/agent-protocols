package aims

import (
	"crypto"
	"crypto/x509"
	"time"
)

// CredentialType identifies the format of an agent credential.
type CredentialType string

const (
	// CredentialX509SVID is an X.509 certificate-based SPIFFE Verifiable Identity Document.
	CredentialX509SVID CredentialType = "x509-svid"

	// CredentialJWTSVID is a JWT-based SPIFFE Verifiable Identity Document.
	CredentialJWTSVID CredentialType = "jwt-svid"

	// CredentialWIT is a WIMSE Workload Identity Token.
	CredentialWIT CredentialType = "wit"
)

// String returns the credential type as a string.
func (ct CredentialType) String() string {
	return string(ct)
}

// Credential is the interface for agent authentication credentials.
// All credential types (X.509 SVID, JWT-SVID, WIT) implement this interface.
type Credential interface {
	// Type returns the credential type.
	Type() CredentialType

	// SPIFFEID returns the SPIFFE ID embedded in this credential.
	SPIFFEID() *SPIFFEID

	// IsExpired returns true if the credential has expired.
	IsExpired() bool

	// ExpiresAt returns when the credential expires.
	ExpiresAt() time.Time
}

// X509SVID represents an X.509 SPIFFE Verifiable Identity Document.
// It contains a certificate chain and private key for mTLS authentication.
type X509SVID struct {
	// Certificates is the certificate chain, with the leaf certificate first.
	Certificates []*x509.Certificate

	// PrivateKey is the private key for the leaf certificate.
	PrivateKey crypto.PrivateKey

	// spiffeID is cached from parsing the certificate.
	spiffeID *SPIFFEID
}

// NewX509SVID creates an X509SVID from a certificate chain and private key.
// The leaf certificate must contain a SPIFFE ID in its URI SAN.
func NewX509SVID(certs []*x509.Certificate, key crypto.PrivateKey) (*X509SVID, error) {
	if len(certs) == 0 {
		return nil, ErrInvalidSPIFFEID
	}

	// Extract SPIFFE ID from leaf certificate URI SANs
	var spiffeID *SPIFFEID
	for _, uri := range certs[0].URIs {
		if uri.Scheme == SPIFFEScheme {
			id, err := ParseSPIFFEID(uri.String())
			if err != nil {
				continue
			}
			spiffeID = id
			break
		}
	}

	if spiffeID == nil {
		return nil, ErrInvalidSPIFFEID
	}

	return &X509SVID{
		Certificates: certs,
		PrivateKey:   key,
		spiffeID:     spiffeID,
	}, nil
}

// Type returns CredentialX509SVID.
func (s *X509SVID) Type() CredentialType {
	return CredentialX509SVID
}

// SPIFFEID returns the SPIFFE ID from the certificate's URI SAN.
func (s *X509SVID) SPIFFEID() *SPIFFEID {
	return s.spiffeID
}

// IsExpired returns true if the leaf certificate has expired.
func (s *X509SVID) IsExpired() bool {
	if len(s.Certificates) == 0 {
		return true
	}
	return time.Now().After(s.Certificates[0].NotAfter)
}

// ExpiresAt returns the expiration time of the leaf certificate.
func (s *X509SVID) ExpiresAt() time.Time {
	if len(s.Certificates) == 0 {
		return time.Time{}
	}
	return s.Certificates[0].NotAfter
}

// LeafCertificate returns the leaf (end-entity) certificate.
func (s *X509SVID) LeafCertificate() *x509.Certificate {
	if len(s.Certificates) == 0 {
		return nil
	}
	return s.Certificates[0]
}

// JWTSVID represents a JWT SPIFFE Verifiable Identity Document.
// This is a JWT token that encodes the SPIFFE ID and can be used
// for non-mTLS authentication scenarios.
type JWTSVID struct {
	// Token is the raw JWT token string.
	Token string

	// spiffeID is the SPIFFE ID from the token's subject claim.
	spiffeID *SPIFFEID

	// expiry is the token's expiration time.
	expiry time.Time
}

// NewJWTSVID creates a JWTSVID from its components.
func NewJWTSVID(token string, spiffeID *SPIFFEID, expiry time.Time) *JWTSVID {
	return &JWTSVID{
		Token:    token,
		spiffeID: spiffeID,
		expiry:   expiry,
	}
}

// Type returns CredentialJWTSVID.
func (j *JWTSVID) Type() CredentialType {
	return CredentialJWTSVID
}

// SPIFFEID returns the SPIFFE ID from the token's subject claim.
func (j *JWTSVID) SPIFFEID() *SPIFFEID {
	return j.spiffeID
}

// IsExpired returns true if the token has expired.
func (j *JWTSVID) IsExpired() bool {
	return time.Now().After(j.expiry)
}

// ExpiresAt returns the token's expiration time.
func (j *JWTSVID) ExpiresAt() time.Time {
	return j.expiry
}
