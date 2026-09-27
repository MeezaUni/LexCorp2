#!/bin/sh
# Replies to VPN clients (10.8.0.0/24) go back through the VPN container. This is a route, not
# address translation, so LexCorp2 sees each remote person's own VPN address in its audit trail.
set -eu
ip route replace "${VPN_CIDR:-10.8.0.0/24}" via "${VPN_GATEWAY:-172.30.0.2}"
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
