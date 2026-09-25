"""Persisted indexer cursor (block number + block hash + contract address).

The indexer previously derived its cursor from max(audit_events.block_number). After
the local chain was reset that value came from the OLD chain (9995), so the indexer
skipped blocks 0-9995 of the new chain and missed real events. Keeping the block hash
lets it detect a replaced chain or a new contract and rescan without deleting anything
(events are de-duplicated by tx hash). No existing rows are modified.

Revision ID: 0010_indexer_state
Revises: 0009_security_alerts
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0010_indexer_state"
down_revision: Union[str, None] = "0009_security_alerts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS indexer_state (
        id INTEGER PRIMARY KEY,
        contract_address VARCHAR(42) NOT NULL,
        last_block INTEGER NOT NULL,
        last_block_hash VARCHAR(66) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    )""")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS indexer_state")
