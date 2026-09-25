"""Action IDs (CRT/VW/DL/MOD-YYYYMMDD-XXXX), version lineage and token-ID sequence.

- action_id_counters: atomic per-prefix, per-UTC-day counters for backend-generated IDs.
  Existing (legacy-format) IDs are left untouched.
- assets.version_number / assets.root_asset_id: backfilled from the existing
  parent_asset_id chain (root = version 1). Deterministic and idempotent.
- document_actions.asset_version: the version an action applied to (backfilled from
  the linked asset).
- asset_token_id_seq: replaces random token IDs; starts above every existing token_id.

Revision ID: 0006_action_ids_versions
Revises: 0005_departments
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0006_action_ids_versions"
down_revision: Union[str, None] = "0005_departments"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS action_id_counters (
        prefix VARCHAR(8) NOT NULL,
        day DATE NOT NULL,
        last_value INTEGER NOT NULL,
        PRIMARY KEY (prefix, day)
    )""")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS version_number INTEGER NOT NULL DEFAULT 1")
    op.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS root_asset_id UUID")
    op.execute("""
    DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'assets_root_asset_id_fkey') THEN
            ALTER TABLE assets ADD CONSTRAINT assets_root_asset_id_fkey FOREIGN KEY (root_asset_id) REFERENCES assets(id);
        END IF;
    END $$""")
    op.execute("CREATE INDEX IF NOT EXISTS ix_assets_root_asset_id ON assets (root_asset_id)")
    op.execute("""
    WITH RECURSIVE lineage AS (
        SELECT id, id AS root_id, 1 AS depth FROM assets WHERE parent_asset_id IS NULL
        UNION ALL
        SELECT a.id, l.root_id, l.depth + 1 FROM assets a JOIN lineage l ON a.parent_asset_id = l.id
    )
    UPDATE assets SET root_asset_id = lineage.root_id, version_number = lineage.depth
    FROM lineage WHERE assets.id = lineage.id
      AND (assets.root_asset_id IS DISTINCT FROM lineage.root_id OR assets.version_number <> lineage.depth)""")
    op.execute("ALTER TABLE document_actions ADD COLUMN IF NOT EXISTS asset_version INTEGER")
    op.execute("""
    UPDATE document_actions d SET asset_version = a.version_number
    FROM assets a WHERE d.asset_id = a.id AND d.asset_version IS NULL""")
    op.execute("""
    DO $$ DECLARE start_at BIGINT; BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relkind = 'S' AND relname = 'asset_token_id_seq') THEN
            SELECT COALESCE(MAX(token_id), 0) + 1 INTO start_at FROM assets;
            EXECUTE format('CREATE SEQUENCE asset_token_id_seq START WITH %s MAXVALUE 2147483647', start_at);
        END IF;
    END $$""")


def downgrade() -> None:
    raise NotImplementedError("0006 is forward-only (backfilled lineage data).")
