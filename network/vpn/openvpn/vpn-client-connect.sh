#!/bin/sh
# OpenVPN client-connect hook: a new address for every connection.
#
# Each connection gets the next free address in the VPN range (2-254 of the /24), so two devices
# never share one and a device that reconnects gets a different one. LexCorp binds its sessions to
# the address, so a reconnect also ends the LexCorp session, and the audit trail tells devices and
# connections apart. Addresses in use are read from OpenVPN's status file; a lock keeps two
# simultaneous connections from taking the same one. Runs as the unprivileged OpenVPN user.
set -eu
out="$1"
prefix=$(cat /run/lexcorp/prefix)            # e.g. 10.8.0, written by entrypoint-openvpn.sh
# kept under /run/lexcorp: owned by the OpenVPN user and reachable by it (/data is root-only)
state=/run/lexcorp/next-host
exec 9>/run/lexcorp/lock
flock 9
n=$(cat "$state" 2>/dev/null || echo 2)
in_use=$(awk -F, '$1 == "CLIENT_LIST" {print $4}' /run/lexcorp/status.log 2>/dev/null || true)
tries=0
while [ "$tries" -lt 253 ]; do
  case "$n" in ''|*[!0-9]*) n=2 ;; esac
  { [ "$n" -ge 2 ] && [ "$n" -le 254 ]; } || n=2
  ip="${prefix}.${n}"
  n=$((n + 1))
  if ! printf '%s\n' "$in_use" | grep -qx "$ip"; then
    echo "$n" > "$state"
    echo "ifconfig-push ${ip} 255.255.255.0" > "$out"
    echo "LexCorp VPN: connection from ${untrusted_ip:-unknown} (${common_name:-?}) gets ${ip}" >&2
    exit 0
  fi
  tries=$((tries + 1))
done
echo "LexCorp VPN: no free address left" >&2
exit 1
