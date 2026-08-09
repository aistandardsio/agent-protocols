#!/usr/bin/env bash
# Bootstrap Keycloak 26.7 as an ID-JAG receiver using kcadm.sh.
# kcadm equivalent of keycloak.AdminClient.BootstrapReceiver (admin.go).
#
# Prereqs: Keycloak started with the experimental feature enabled:
#   docker run -p 8081:8080 \
#     -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
#     quay.io/keycloak/keycloak:26.7 start-dev --features=identity-assertion-jwt
#
# Usage:
#   KEYCLOAK_URL=http://localhost:8081 \
#   IDJAG_ISSUER=http://localhost:18081 \
#   ./keycloak-bootstrap.sh
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8081}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM="${REALM:-agents}"
IDP_ALIAS="${IDP_ALIAS:-corp-idp}"
IDJAG_ISSUER="${IDJAG_ISSUER:-http://localhost:18081}"
IDJAG_JWKS_URL="${IDJAG_JWKS_URL:-${IDJAG_ISSUER}/.well-known/jwks.json}"
CLIENT_ID="${CLIENT_ID:-mcp-google}"
CLIENT_SECRET="${CLIENT_SECRET:-demo-secret}"

KCADM="${KCADM:-kcadm.sh}"

"$KCADM" config credentials --server "$KEYCLOAK_URL" --realm master \
  --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD"

# 1. Realm
"$KCADM" create realms -s realm="$REALM" -s enabled=true || echo "realm ${REALM} exists"

# 2. External issuer trust (identity provider entry with JWKS validation)
"$KCADM" create "identity-provider/instances" -r "$REALM" \
  -s alias="$IDP_ALIAS" \
  -s providerId=oidc \
  -s enabled=true \
  -s "config.issuer=$IDJAG_ISSUER" \
  -s "config.jwksUrl=$IDJAG_JWKS_URL" \
  -s "config.useJwksUrl=true" \
  -s "config.validateSignature=true" \
  -s "config.authorizationUrl=$IDJAG_ISSUER" \
  -s "config.tokenUrl=$IDJAG_ISSUER" || echo "idp ${IDP_ALIAS} exists"

# 3. Confidential receiver client with the jwt-authorization-grant flag
# (experimental attribute; tracked against Keycloak 26.7)
"$KCADM" create clients -r "$REALM" \
  -s clientId="$CLIENT_ID" \
  -s secret="$CLIENT_SECRET" \
  -s enabled=true \
  -s publicClient=false \
  -s standardFlowEnabled=false \
  -s directAccessGrantsEnabled=false \
  -s 'attributes."oauth2.jwt.authorization.grant.enabled"=true' || echo "client ${CLIENT_ID} exists"

echo "Keycloak realm '${REALM}' bootstrapped as ID-JAG receiver."
echo "Token endpoint: ${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"
