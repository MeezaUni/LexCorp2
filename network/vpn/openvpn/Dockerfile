# OpenVPN Community Edition (Debian's 2.6) + openvpn-auth-oauth2 + WireGuard tools, one image used by
# the VPN server, the sign-in service that asks Google who is connecting, and the site link
# (the encrypted tunnel from the machine running LexCorp to the gateway).
FROM debian:trixie-slim

ARG OAUTH2_VERSION=2.2.0
ARG OAUTH2_SHA256=a4871c30666afd5cd6504501ae83653dfcb2c31a147f3450ba8092a471203e3c

RUN apt-get update \
 && apt-get install -y --no-install-recommends openvpn easy-rsa iptables iproute2 wireguard-tools openssl ca-certificates curl \
 && curl -fsSL -o /tmp/oauth2.deb \
      "https://github.com/jkroepke/openvpn-auth-oauth2/releases/download/v${OAUTH2_VERSION}/openvpn-auth-oauth2_${OAUTH2_VERSION}_linux_amd64.deb" \
 && echo "${OAUTH2_SHA256}  /tmp/oauth2.deb" | sha256sum -c - \
 && apt-get install -y --no-install-recommends /tmp/oauth2.deb \
 && rm -rf /tmp/oauth2.deb /var/lib/apt/lists/*

COPY entrypoint-openvpn.sh entrypoint-auth.sh entrypoint-sitelink.sh vpn-client-connect.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint-*.sh /usr/local/bin/vpn-client-connect.sh
