"""Per-user wallet wrapping secret for the browser's encrypted keystore.

The browser stores the wallet only as an encrypted keystore (scrypt + AES,
ethers v3 JSON). The key that unlocks it is this server-held random secret
(itself Fernet-encrypted at rest), released only to an authenticated session
and rotated on every provisioning / admin reset.

Revision ID: 0004_wallet_wrap_secret
Revises: 0003_auth_hardening
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0004_wallet_wrap_secret"
down_revision: Union[str, None] = "0003_auth_hardening"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS wallet_wrap_secret VARCHAR(255)")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS wallet_wrap_secret")
