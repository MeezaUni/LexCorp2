"""Append-only audit history enforced by the database; neutral organisation default.

* audit_events and security_alert_actions reject UPDATE, DELETE and TRUNCATE for every
  database role (including the table owner) through triggers. The application no
  longer mirrors alert state onto audit rows (it lives in security_alerts).
* The legacy users.organization default named a real third-party company; LexCorp2
  is an independent product, so the default becomes 'LexCorp2'.

Revision ID: 0011_append_only_audit
Revises: 0010_indexer_state
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0011_append_only_audit"
down_revision: Union[str, None] = "0010_indexer_state"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLES = ("audit_events", "security_alert_actions")


def upgrade() -> None:
    op.execute("ALTER TABLE users ALTER COLUMN organization SET DEFAULT 'LexCorp2'")
    op.execute("ALTER TABLE audit_events ALTER COLUMN alert_status DROP NOT NULL")
    op.execute("ALTER TABLE audit_events ALTER COLUMN alert_status DROP DEFAULT")
    op.execute("""
    CREATE OR REPLACE FUNCTION lexcorp_forbid_history_mutation() RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'LexCorp2 audit history is append-only (% on % rejected)', TG_OP, TG_TABLE_NAME
            USING ERRCODE = 'insufficient_privilege';
    END;
    $$ LANGUAGE plpgsql
    """)
    for t in TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {t}_append_only ON {t}")
        op.execute(f"CREATE TRIGGER {t}_append_only BEFORE UPDATE OR DELETE ON {t} "
                   f"FOR EACH ROW EXECUTE FUNCTION lexcorp_forbid_history_mutation()")
        op.execute(f"DROP TRIGGER IF EXISTS {t}_no_truncate ON {t}")
        op.execute(f"CREATE TRIGGER {t}_no_truncate BEFORE TRUNCATE ON {t} "
                   f"FOR EACH STATEMENT EXECUTE FUNCTION lexcorp_forbid_history_mutation()")


def downgrade() -> None:
    for t in TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {t}_append_only ON {t}")
        op.execute(f"DROP TRIGGER IF EXISTS {t}_no_truncate ON {t}")
    op.execute("DROP FUNCTION IF EXISTS lexcorp_forbid_history_mutation()")
    op.execute("ALTER TABLE users ALTER COLUMN organization SET DEFAULT 'Bharat Electronics Limited (BEL)'")
