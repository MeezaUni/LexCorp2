#!/bin/sh
# Sign-in service for the LexCorp2 VPN (openvpn-auth-oauth2).
#
# When someone connects, OpenVPN hands the connection to this service over its management
# interface. The person's VPN client opens https://VPN_HOST:LOGIN_PORT (served through Caddy),
# which sends them to Google. The connection is accepted only if Google confirms an email that
# is verified and listed in ALLOWED_EMAILS; otherwise it is refused and never reaches the network.
# In a company, Google would be replaced by the company's own identity provider (Microsoft
# Entra ID, AD FS, Keycloak...): the same OIDC standard, different issuer and client values.
set -eu

: "${VPN_HOST:?set VPN_HOST in network/vpn/.env}"
: "${GOOGLE_CLIENT_ID:?set GOOGLE_CLIENT_ID in network/vpn/.env}"
: "${GOOGLE_CLIENT_SECRET:?set GOOGLE_CLIENT_SECRET in network/vpn/.env}"
: "${ALLOWED_EMAILS:?set ALLOWED_EMAILS in network/vpn/.env (comma-separated)}"
LOGIN_PORT="${LOGIN_PORT:-9443}"
MGMT_ADDR="${MGMT_ADDR:-172.30.0.2}"
MGMT_PORT="${MGMT_PORT:-7505}"

# ALLOWED_EMAILS -> a CEL rule. Only plain email characters are accepted, so a typo can't
# change the meaning of the rule.
list=""
for raw in $(echo "$ALLOWED_EMAILS" | tr ',' ' '); do
  email=$(echo "$raw" | tr 'A-Z' 'a-z')
  if ! echo "$email" | grep -Eq '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'; then
    echo "ALLOWED_EMAILS: '$raw' is not a valid email address" >&2
    exit 1
  fi
  list="${list:+$list, }\"$email\""
done
[ -n "$list" ] || { echo "ALLOWED_EMAILS is empty" >&2; exit 1; }
echo "Allowed accounts: $list"

until [ -s /shared/management-password.txt ] && [ -s /shared/http-secret.txt ]; do
  echo "Waiting for the VPN server to create its secrets..."; sleep 2
done

export OPENVPN_AUTH_OAUTH2_HTTP_LISTEN=":9000"
export OPENVPN_AUTH_OAUTH2_HTTP_BASEURL="https://${VPN_HOST}:${LOGIN_PORT}"
export OPENVPN_AUTH_OAUTH2_HTTP_SECRET="file:///shared/http-secret.txt"
export OPENVPN_AUTH_OAUTH2_OPENVPN_ADDR="tcp://${MGMT_ADDR}:${MGMT_PORT}"
export OPENVPN_AUTH_OAUTH2_OPENVPN_PASSWORD="file:///shared/management-password.txt"
export OPENVPN_AUTH_OAUTH2_OAUTH2_PROVIDER="google"
export OPENVPN_AUTH_OAUTH2_OAUTH2_ISSUER="https://accounts.google.com"
export OPENVPN_AUTH_OAUTH2_OAUTH2_CLIENT_ID="$GOOGLE_CLIENT_ID"
export OPENVPN_AUTH_OAUTH2_OAUTH2_CLIENT_SECRET="$GOOGLE_CLIENT_SECRET"
# Only sign-in scopes (the provider's default adds a Google Workspace groups scope a personal account can't grant)
export OPENVPN_AUTH_OAUTH2_OAUTH2_SCOPES="openid profile email"
export OPENVPN_AUTH_OAUTH2_OAUTH2_OPENVPN_USERNAME="user.email"
export OPENVPN_AUTH_OAUTH2_OAUTH2_VALIDATE_EXPRESSION="token.claims.email_verified == true && user.email.lowerAscii() in [${list}]"
unset GOOGLE_CLIENT_SECRET

exec openvpn-auth-oauth2
