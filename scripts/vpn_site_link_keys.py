"""Create network/vpn/gateway.env and network/vpn/site.env with fresh site-link (WireGuard) keys.

    python scripts/vpn_site_link_keys.py            # fills in what is missing, keeps what is set
    python scripts/vpn_site_link_keys.py --rotate   # new site-link keys in both files

Values already in network/vpn/.env (DuckDNS names and token, Google client, allowlist, ports) are
copied into the right file, so they are entered once. The gateway file gets the gateway's private
key and the site's public key; the site file the reverse; both the shared preshared key. Both
files are git-ignored. Nothing secret is printed. Copy gateway.env to the gateway server.
"""

import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

VPN = Path(__file__).resolve().parent.parent / "network" / "vpn"


def read_env(path: Path) -> dict:
    values = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip()
    return values


def keypair() -> tuple[str, str]:
    key = X25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(private).decode(), base64.b64encode(public).decode()


def fill(template: Path, target: Path, values: dict) -> list[str]:
    """Write target from template, using values for every KEY= line. Returns keys left empty."""
    lines, empty = [], []
    for line in template.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, default = line.split("=", 1)
            v = values.get(k.strip()) or default.strip()
            if not v:
                empty.append(k.strip())
            line = f"{k}={v}"
        lines.append(line)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return empty


def main():
    rotate = "--rotate" in sys.argv
    shared = read_env(VPN / ".env")
    gateway, site = read_env(VPN / "gateway.env"), read_env(VPN / "site.env")
    known = {**shared, **site, **gateway}

    keys_present = all(gateway.get(k) for k in ("WG_GATEWAY_PRIVATE_KEY", "WG_SITE_PUBLIC_KEY", "WG_PRESHARED_KEY")) and \
        all(site.get(k) for k in ("WG_SITE_PRIVATE_KEY", "WG_GATEWAY_PUBLIC_KEY", "WG_PRESHARED_KEY"))
    if rotate or not keys_present:
        gw_priv, gw_pub = keypair()
        site_priv, site_pub = keypair()
        psk = base64.b64encode(os.urandom(32)).decode()
        known.update(WG_GATEWAY_PRIVATE_KEY=gw_priv, WG_GATEWAY_PUBLIC_KEY=gw_pub, WG_SITE_PRIVATE_KEY=site_priv,
                     WG_SITE_PUBLIC_KEY=site_pub, WG_PRESHARED_KEY=psk)
        print("Created new site-link keys.")
    else:
        print("Site-link keys already present (use --rotate for new ones).")
    if not known.get("GATEWAY_ENDPOINT") and known.get("VPN_HOST"):
        known["GATEWAY_ENDPOINT"] = f"{known['VPN_HOST']}:51820"

    for name in ("gateway", "site"):
        empty = fill(VPN / f"{name}.env.example", VPN / f"{name}.env", known)
        print(f"Wrote network/vpn/{name}.env" + (f" (still empty: {', '.join(empty)})" if empty else ""))


if __name__ == "__main__":
    main()
