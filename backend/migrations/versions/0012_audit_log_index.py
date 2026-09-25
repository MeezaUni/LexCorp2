"""Index chain events per LOG, not per transaction.

One transaction can emit several contract events (e.g. the constructor emits two
RoleGranted). De-duplicating on tx_hash alone silently dropped every event after the
first. Chain events are now unique on (tx_hash, log_index); off-chain API events keep a
NULL log_index and their synthetic, unique tx_hash.

Revision ID: 0012_audit_log_index
Revises: 0011_append_only_audit
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0012_audit_log_index"
down_revision: Union[str, None] = "0011_append_only_audit"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS log_index INTEGER")
    op.execute("DROP INDEX IF EXISTS ix_audit_events_tx_hash")
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_events_tx_hash ON audit_events (tx_hash)")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_events_tx_log ON audit_events (tx_hash, log_index) NULLS NOT DISTINCT")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_audit_events_tx_log")
    op.execute("DROP INDEX IF EXISTS ix_audit_events_tx_hash")
    op.execute("CREATE UNIQUE INDEX ix_audit_events_tx_hash ON audit_events (tx_hash)")
    op.execute("ALTER TABLE audit_events DROP COLUMN IF EXISTS log_index")
