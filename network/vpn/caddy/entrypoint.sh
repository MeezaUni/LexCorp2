#!/bin/sh
# CADDY_ROLE=gateway (sign-in page) or site (the app). At the site, replies to VPN clients
# (10.8.0.0/24) go back through the site-link container: a route, not address translation, so
# LexCorp sees each remote person's own VPN address in its audit trail.
set -eu
case "${CADDY_ROLE:-}" in
  gateway|site) ;;
  *) echo "set CADDY_ROLE to gateway or site" >&2; exit 1 ;;
esac
if [ -n "${VPN_GATEWAY:-}" ]; then
  ip route replace "${VPN_CIDR:-10.8.0.0/24}" via "${VPN_GATEWAY}"
fi
exec caddy run --config "/etc/caddy/Caddyfile.${CADDY_ROLE}" --adapter caddyfile
