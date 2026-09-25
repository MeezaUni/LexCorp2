"""Re-encrypt every at-rest secret under the active data-encryption key.

Covers records written under (a) an older key in DATA_ENCRYPTION_KEYS, (b) the legacy
key that earlier versions derived from JWT_SECRET, and (c) legacy plaintext values.
The operation runs in one transaction and verifies every record decrypts under the
NEW key ring alone before committing; any failure rolls everything back.
"""

from dataclasses import dataclass, field
from typing import Iterable, Optional

from cryptography.fernet import MultiFernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import build_keyring, decrypt_secret, encrypt_secret, is_encrypted
from app.models.domain import User

ENCRYPTED_USER_FIELDS = ("totp_secret", "totp_factor2_secret", "totp_factor3_secret", "wallet_wrap_secret")


@dataclass
class RotationReport:
    records_checked: int = 0
    reencrypted: int = 0
    plaintext_migrated: int = 0
    unreadable: list = field(default_factory=list)  # (user_id, field) - never values

    @property
    def ok(self) -> bool:
        return not self.unreadable


async def rotate_encryption(
    db: AsyncSession,
    new_keys: list[str],
    old_keys: Iterable[str] = (),
    *,
    migrate_plaintext: bool = True,
    dry_run: bool = False,
) -> RotationReport:
    new_ring: MultiFernet = build_keyring(list(new_keys))
    read_ring: MultiFernet = build_keyring(list(new_keys) + [k for k in old_keys if k not in new_keys])
    report = RotationReport()
    users = (await db.execute(select(User))).scalars().all()
    for user in users:
        for name in ENCRYPTED_USER_FIELDS:
            stored: Optional[str] = getattr(user, name)
            if not stored:
                continue
            report.records_checked += 1
            if is_encrypted(stored):
                plain = decrypt_secret(stored, read_ring)
                if plain is None:
                    report.unreadable.append((str(user.id), name))
                    continue
                report.reencrypted += 1
            elif migrate_plaintext:
                plain = stored
                report.plaintext_migrated += 1
            else:
                report.unreadable.append((str(user.id), name))
                continue
            new_value = encrypt_secret(plain, new_ring)
            if decrypt_secret(new_value, new_ring) != plain:  # verify before writing
                report.unreadable.append((str(user.id), name))
                continue
            setattr(user, name, new_value)
    if dry_run or not report.ok:
        await db.rollback()
    else:
        await db.commit()
    return report
