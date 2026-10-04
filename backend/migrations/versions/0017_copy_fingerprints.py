"""Record each issued copy's SHA-256 and its invisible mark on its action.

Verification can then tell an exact issued copy from an edited one by its hash, and read the
invisible mark back to find which copy a file really came from. Earlier actions keep NULL and
are verified by their visible watermark only.

Revision ID: 0017_copy_fingerprints
Revises: 0016_lexcorp_name
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0017_copy_fingerprints"
down_revision: Union[str, None] = "0016_lexcorp_name"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE document_actions ADD COLUMN IF NOT EXISTS copy_sha256 VARCHAR(64)")
    op.execute("ALTER TABLE document_actions ADD COLUMN IF NOT EXISTS hidden_mark VARCHAR(32)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_document_actions_copy_sha256 ON document_actions (copy_sha256)")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_document_actions_hidden_mark ON document_actions (hidden_mark)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_document_actions_hidden_mark")
    op.execute("DROP INDEX IF EXISTS ix_document_actions_copy_sha256")
    op.execute("ALTER TABLE document_actions DROP COLUMN IF EXISTS hidden_mark")
    op.execute("ALTER TABLE document_actions DROP COLUMN IF EXISTS copy_sha256")
