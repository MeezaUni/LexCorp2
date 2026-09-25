"""Re-encrypt all at-rest secrets under the active DATA_ENCRYPTION_KEYS[0].

Usage (from backend/):
    python scripts/rotate_encryption_keys.py --dry-run
    python scripts/rotate_encryption_keys.py [--legacy-jwt-secret-env OLD_JWT_SECRET] [--old-keys-env OLD_DATA_KEYS]

Old keys are read from the named ENVIRONMENT VARIABLES (never from the command line,
so they do not land in shell history). Prints counts only - never secret values.
Take a database backup first.
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings  # noqa: E402
from app.core.crypto import legacy_jwt_derived_key  # noqa: E402
from app.core.database import async_session_factory  # noqa: E402
from app.services.key_rotation import rotate_encryption  # noqa: E402


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--legacy-jwt-secret-env", help="env var holding the JWT_SECRET used by the old derived key")
    ap.add_argument("--old-keys-env", help="env var holding comma-separated retired Fernet keys")
    ap.add_argument("--no-plaintext", action="store_true", help="treat plaintext values as errors")
    a = ap.parse_args()

    old = []
    if a.old_keys_env:
        old += [k.strip() for k in os.environ.get(a.old_keys_env, "").split(",") if k.strip()]
    if a.legacy_jwt_secret_env:
        legacy = os.environ.get(a.legacy_jwt_secret_env)
        if not legacy:
            print(f"{a.legacy_jwt_secret_env} is empty"); return 2
        old.append(legacy_jwt_derived_key(legacy))

    async with async_session_factory() as db:
        r = await rotate_encryption(db, settings.data_encryption_keys, old,
                                    migrate_plaintext=not a.no_plaintext, dry_run=a.dry_run)
    print(f"checked={r.records_checked} reencrypted={r.reencrypted} plaintext_migrated={r.plaintext_migrated} "
          f"unreadable={len(r.unreadable)} committed={r.ok and not a.dry_run}")
    for uid, field in r.unreadable:
        print(f"  unreadable: user={uid} field={field}")
    return 0 if r.ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
