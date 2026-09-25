"""Delegated access grants: separate view/download permissions, optional expiry,
optional max view count (enforced atomically), request/approval linkage, revocation.

Existing grants keep their behaviour: can_view = TRUE, can_download = FALSE,
no expiry. asset_id is backfilled from asset_serial.

Revision ID: 0007_access_grants
Revises: 0006_action_ids_versions
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0007_access_grants"
down_revision: Union[str, None] = "0006_action_ids_versions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for stmt in (
        "ALTER TABLE asset_access_grants ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES assets(id)",
        "ALTER TABLE asset_access_grants ADD COLUMN IF NOT EXISTS can_view BOOLEAN NOT NULL DEFAULT TRUE",
        "ALTER TABLE asset_access_grants ADD COLUMN IF NOT EXISTS can_download BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE asset_access_grants ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ",
        "ALTER TABLE asset_access_grants ADD COLUMN IF NOT EXISTS request_action_id VARCHAR(64)",
        "ALTER TABLE asset_access_grants ADD COLUMN IF NOT EXISTS requested_by_did VARCHAR",
        "ALTER TABLE asset_access_grants ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ",
        "ALTER TABLE asset_access_grants ADD COLUMN IF NOT EXISTS revoked_by_did VARCHAR",
        "CREATE INDEX IF NOT EXISTS ix_asset_access_grants_asset_id ON asset_access_grants (asset_id)",
        "UPDATE asset_access_grants g SET asset_id = a.id FROM assets a WHERE g.asset_id IS NULL AND a.serial_number = g.asset_serial",
    ):
        op.execute(stmt)


def downgrade() -> None:
    raise NotImplementedError("0007 is forward-only.")
