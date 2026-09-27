"""The product is LexCorp (not LexCorp2): organisation default and existing people, and the
message of the append-only audit protection.

Revision ID: 0016_lexcorp_name
Revises: 0015_passkey_rp_id
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0016_lexcorp_name"
down_revision: Union[str, None] = "0015_passkey_rp_id"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FUNCTION = """
CREATE OR REPLACE FUNCTION lexcorp_forbid_history_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '{name} audit history is append-only (% on % rejected)', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql
"""


def upgrade() -> None:
    op.execute("ALTER TABLE users ALTER COLUMN organization SET DEFAULT 'LexCorp'")
    op.execute("UPDATE users SET organization = 'LexCorp' WHERE organization = 'LexCorp2'")
    op.execute(_FUNCTION.format(name="LexCorp"))


def downgrade() -> None:
    op.execute(_FUNCTION.format(name="LexCorp2"))
    op.execute("UPDATE users SET organization = 'LexCorp2' WHERE organization = 'LexCorp'")
    op.execute("ALTER TABLE users ALTER COLUMN organization SET DEFAULT 'LexCorp2'")
