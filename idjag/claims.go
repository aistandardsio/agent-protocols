package idjag

// Standard JWT claim names per RFC 7519.
const (
	ClaimIssuer         = "iss"
	ClaimSubject        = "sub"
	ClaimAudience       = "aud"
	ClaimExpirationTime = "exp"
	ClaimNotBefore      = "nbf"
	ClaimIssuedAt       = "iat"
	ClaimJWTID          = "jti"
)

// ID-JAG specific claim names.
const (
	// ClaimActor is the "act" claim for delegation per RFC 8693.
	// It contains information about the acting party when delegation is used.
	ClaimActor = "act"

	// ClaimClientID identifies the client making the token exchange request.
	ClaimClientID = "client_id"

	// ClaimScope contains the requested scope for the access token.
	ClaimScope = "scope"
)

// Grant types for token exchange.
//
//nolint:gosec // G101: OAuth URNs per RFC 8693/7523, not credentials
const (
	// GrantTypeTokenExchange is the grant type for RFC 8693 token exchange.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// GrantTypeJWTBearer is the grant type for RFC 7523 JWT bearer assertion.
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// Token types for token exchange requests.
//
//nolint:gosec // G101: OAuth URNs per RFC 8693, not credentials
const (
	// TokenTypeAccessToken indicates an OAuth 2.0 access token.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// TokenTypeRefreshToken indicates an OAuth 2.0 refresh token.
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"

	// TokenTypeIDToken indicates an OpenID Connect ID token.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

	// TokenTypeJWT indicates a JWT token.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// TokenTypeIDJAG indicates an ID-JAG assertion per draft-ietf-oauth-identity-assertion-authz-grant.
	TokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"

	// TokenTypeSAML1 indicates a SAML 1.1 assertion.
	TokenTypeSAML1 = "urn:ietf:params:oauth:token-type:saml1"

	// TokenTypeSAML2 indicates a SAML 2.0 assertion.
	TokenTypeSAML2 = "urn:ietf:params:oauth:token-type:saml2"
)

// JWT header types per IETF specifications.
const (
	// JWTTypeIDJAG is the typ header value for ID-JAG assertions
	// per draft-ietf-oauth-identity-assertion-authz-grant.
	JWTTypeIDJAG = "oauth-id-jag+jwt"
)

// Supported JWT signing algorithms.
const (
	AlgorithmRS256 = "RS256"
	AlgorithmRS384 = "RS384"
	AlgorithmRS512 = "RS512"
	AlgorithmES256 = "ES256"
	AlgorithmES384 = "ES384"
	AlgorithmES512 = "ES512"
	AlgorithmPS256 = "PS256"
	AlgorithmPS384 = "PS384"
	AlgorithmPS512 = "PS512"
)

// JWKS (JSON Web Key Set) constants.
const (
	// JWKSPath is the standard path for JWKS endpoint.
	JWKSPath = "/.well-known/jwks.json"

	// OpenIDConfigPath is the standard path for OpenID Connect discovery.
	OpenIDConfigPath = "/.well-known/openid-configuration"
)

// HTTP header names.
const (
	HeaderAuthorization = "Authorization"
	HeaderContentType   = "Content-Type"
)

// Content type values.
const (
	ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"
	ContentTypeJSON           = "application/json"
)
