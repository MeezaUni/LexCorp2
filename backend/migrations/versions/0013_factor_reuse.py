"""Let a person choose to use their login authenticator and passkey for Factor 2 and/or
Factor 3 instead of setting up separate ones.

Revision ID: 0013_factor_reuse
Revises: 0012_audit_log_index
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0013_factor_reuse"
down_revision: Union[str, None] = "0012_audit_log_index"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS factor2_uses_login BOOLEAN NOT NULL DEFAULT false")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS factor3_uses_login BOOLEAN NOT NULL DEFAULT false")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS factor3_uses_login")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS factor2_uses_login")
