"""Record the actor's role on each audit event at the time it happens.

Earlier the role shown and filtered in the audit trail was joined from the person's CURRENT
identity, so a later role change rewrote how past events read. audit_events is append-only
(0011), so existing rows are not backfilled: they keep NULL and readers fall back to the
current identity for them.

Revision ID: 0014_audit_actor_role
Revises: 0013_factor_reuse
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0014_audit_actor_role"
down_revision: Union[str, None] = "0013_factor_reuse"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_role VARCHAR(20)")


def downgrade() -> None:
    op.execute("ALTER TABLE audit_events DROP COLUMN IF EXISTS actor_role")
