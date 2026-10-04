#!/bin/sh
# Site link: the encrypted tunnel (WireGuard) from the machine running LexCorp to the VPN gateway.
#
# The site opens the tunnel outwards, so it works behind carrier-grade NAT and needs no ports
# opened at the site. Replies and keepalives keep it up. VPN clients' requests to the web proxy
# (APP_IP) arrive through it; this container forwards only those, HTTPS only, and nothing else.
set -eu

: "${GATEWAY_ENDPOINT:?set GATEWAY_ENDPOINT in site.env (gateway host:51820)}"
: "${WG_SITE_PRIVATE_KEY:?set WG_SITE_PRIVATE_KEY in site.env}"
: "${WG_GATEWAY_PUBLIC_KEY:?set WG_GATEWAY_PUBLIC_KEY in site.env}"
: "${WG_PRESHARED_KEY:?set WG_PRESHARED_KEY in site.env}"
VPN_CIDR="${VPN_CIDR:-10.8.0.0/24}"
APP_IP="${APP_IP:-172.30.0.10}"

ip link del wg0 2>/dev/null || true
ip link add wg0 type wireguard
printf '%s' "$WG_SITE_PRIVATE_KEY" > /run/wg.key
printf '%s' "$WG_PRESHARED_KEY" > /run/wg.psk
wg set wg0 private-key /run/wg.key \
  peer "$WG_GATEWAY_PUBLIC_KEY" preshared-key /run/wg.psk endpoint "$GATEWAY_ENDPOINT" \
  allowed-ips "10.9.0.1/32,${VPN_CIDR}" persistent-keepalive 25
rm -f /run/wg.key /run/wg.psk
unset WG_SITE_PRIVATE_KEY WG_PRESHARED_KEY
ip addr add 10.9.0.2/24 dev wg0
ip link set wg0 up
ip route replace "${VPN_CIDR}" dev wg0

iptables -F FORWARD
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i wg0 -s "${VPN_CIDR}" -d "${APP_IP}" -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -i wg0 -s "${VPN_CIDR}" -d "${APP_IP}" -p icmp --icmp-type echo-request -j ACCEPT
# Public record verification from the gateway's proxy (10.9.0.1): the verify-only listener only
iptables -A FORWARD -i wg0 -s 10.9.0.1 -d "${APP_IP}" -p tcp --dport 8080 -j ACCEPT
iptables -F INPUT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i wg0 -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i wg0 -j DROP

echo "Site link up: 10.9.0.2 -> gateway ${GATEWAY_ENDPOINT}; forwarding ${VPN_CIDR} -> ${APP_IP}:443 and the gateway's verify proxy -> ${APP_IP}:8080 only"
# Report the link's state now and then (the last handshake should stay under ~2 minutes old)
while true; do
  sleep 30
  hs=$(wg show wg0 latest-handshakes | awk '{print $2}')
  if [ -n "$hs" ] && [ "$hs" -gt 0 ]; then
    age=$(( $(date +%s) - hs ))
    [ "$age" -lt 180 ] || echo "$(date -u +%FT%TZ) site link: no handshake for ${age}s (is the gateway reachable on UDP 51820?)"
  else
    echo "$(date -u +%FT%TZ) site link: waiting for the first handshake with ${GATEWAY_ENDPOINT}"
  fi
done
