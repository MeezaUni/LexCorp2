"""Generate LexCorp2 local secrets (idempotent). Prints only public addresses and paths.

Creates, if missing (existing values are kept unless --rotate NAME is given):

  .env                    POSTGRES_PASSWORD           (read by docker compose)
  secrets/chain.env       DEPLOYER_PRIVATE_KEY/ADDRESS (governance key: DEFAULT_ADMIN_ROLE)
                          REGISTRAR_ADDRESS            (public address of the chain operator)
  backend/.env            ENVIRONMENT, DEBUG, DATABASE_URL(_SYNC), JWT_SECRET, VC_SIGNING_SECRET,
                          DATA_ENCRYPTION_KEYS, CHAIN_OPERATOR_PRIVATE_KEY, PUBLIC_BASE_URL

All three files are git-ignored. Nothing here is a production secret store: in
production supply the same variables from a real secret manager.

Usage:  python scripts/init_secrets.py [--rotate JWT_SECRET] [--environment development]
"""

import argparse
import base64
import os
import secrets
import sys
from pathlib import Path

from eth_account import Account

ROOT = Path(__file__).resolve().parent.parent
FILES = {
    "root": ROOT / ".env",
    "chain": ROOT / "secrets" / "chain.env",
    "backend": ROOT / "backend" / ".env",
}


def read_env(path: Path) -> dict:
    out = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def write_env(path: Path, values: dict, header: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{k}={v}\n" for k, v in values.items())
    path.write_text(f"# {header}\n# GENERATED - DO NOT COMMIT - DO NOT SHARE\n{body}", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rotate", action="append", default=[], help="regenerate this variable")
    ap.add_argument("--environment", default="development", choices=["development", "production"])
    a = ap.parse_args()
    rot = set(a.rotate)

    root, chain, backend = (read_env(FILES[k]) for k in ("root", "chain", "backend"))

    def keep(store: dict, name: str, gen):
        if name in rot or not store.get(name):
            store[name] = gen()
        return store[name]

    pg = keep(root, "POSTGRES_PASSWORD", lambda: secrets.token_urlsafe(24))

    deployer = keep(chain, "DEPLOYER_PRIVATE_KEY", lambda: "0x" + secrets.token_hex(32))
    chain["DEPLOYER_ADDRESS"] = Account.from_key(deployer).address
    operator = keep(backend, "CHAIN_OPERATOR_PRIVATE_KEY", lambda: "0x" + secrets.token_hex(32))
    chain["REGISTRAR_ADDRESS"] = Account.from_key(operator).address

    backend["ENVIRONMENT"] = backend.get("ENVIRONMENT") or a.environment
    backend.setdefault("DEBUG", "false")
    backend["DATABASE_URL"] = f"postgresql+asyncpg://lexcorp:{pg}@127.0.0.1:5432/lexcorp_sih"
    backend["DATABASE_URL_SYNC"] = f"postgresql://lexcorp:{pg}@127.0.0.1:5432/lexcorp_sih"
    keep(backend, "JWT_SECRET", lambda: secrets.token_urlsafe(48))
    keep(backend, "VC_SIGNING_SECRET", lambda: secrets.token_urlsafe(48))
    if "DATA_ENCRYPTION_KEYS" in rot and backend.get("DATA_ENCRYPTION_KEYS"):
        # rotation keeps the old keys for decryption; run backend/scripts/rotate_encryption_keys.py next
        backend["DATA_ENCRYPTION_KEYS"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode() + "," + backend["DATA_ENCRYPTION_KEYS"]
    else:
        keep(backend, "DATA_ENCRYPTION_KEYS", lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
    backend.setdefault("PUBLIC_BASE_URL", "http://localhost:5173")

    write_env(FILES["root"], root, "docker compose variables for LexCorp2")
    write_env(FILES["chain"], chain, "LexCorp2 contract deployment (governance) credentials")
    write_env(FILES["backend"], backend, "LexCorp2 backend configuration")

    print("Secrets written (values not shown):")
    for k, p in FILES.items():
        print(f"  {p.relative_to(ROOT)}")
    print(f"Governance/admin address : {chain['DEPLOYER_ADDRESS']}")
    print(f"Chain operator (registrar): {chain['REGISTRAR_ADDRESS']}")
    if rot:
        print(f"Rotated: {', '.join(sorted(rot))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
