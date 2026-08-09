// Package keycloak provides adapters integrating agent-protocols with
// Keycloak as an ID-JAG receiver.
//
// Keycloak 26.7 ships an EXPERIMENTAL identity-assertion-jwt feature that
// implements the receiver role of the Identity Assertion JWT Authorization
// Grant (draft-ietf-oauth-identity-assertion-authz-grant): Keycloak accepts
// an ID-JAG minted by an external issuer at its token endpoint (RFC 7523
// jwt-bearer grant) and issues a realm access token. The issuer role is not
// yet implemented upstream; pair Keycloak with the reference
// idjag.IdPAuthorizationServer as the enterprise IdP.
//
// Start Keycloak with the feature enabled and the version pinned:
//
//	docker run quay.io/keycloak/keycloak:26.7 start-dev \
//	    --features=identity-assertion-jwt
//
// The package provides:
//
//   - AdminClient: Keycloak Admin REST helpers to bootstrap a realm as an
//     ID-JAG receiver (external issuer trust + confidential client with the
//     jwt-authorization-grant flag). See also scripts/keycloak-bootstrap.sh
//     for the kcadm.sh equivalent.
//   - Exchanger: exchanges an ID-JAG assertion for a Keycloak access token
//     via the jwt-bearer grant with confidential client authentication.
//   - Discovery helpers for the realm's OIDC endpoints and JWKS.
//
// MCP servers validating Keycloak-issued access tokens should use the
// omniskill adapter (adapters/omniskill) pointed at the realm issuer URL
// (https://{host}/realms/{realm}).
//
// WARNING: the upstream feature is experimental and not for production;
// admin attribute names may change between Keycloak releases. This adapter
// is developed and tested against Keycloak 26.7 only.
//
// # References
//
//   - https://www.keycloak.org/securing-apps/identity-assertion-jwt-authorization-grant
//   - https://www.keycloak.org/securing-apps/jwt-authorization-grant
//   - https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/
package keycloak
