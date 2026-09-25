"""Global, normalised uniqueness for physical asset identifiers.

Adds functional unique indexes (live data verified conflict-free before this was
written; no rows are modified):
  - serial numbers: case/whitespace-insensitive, across the whole registry
  - MAC addresses: separator/case-insensitive (aa:bb:cc:dd:ee:ff == AABB.CCDD.EEFF)
  - unique addresses: case/whitespace-insensitive
The existing exact-match unique indexes stay in place.

Revision ID: 0008_physical_uniqueness
Revises: 0007_access_grants
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0008_physical_uniqueness"
down_revision: Union[str, None] = "0007_access_grants"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_serial_norm ON assets (lower(btrim(serial_number)))")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_mac_norm ON assets "
               "(lower(regexp_replace(mac_address, '[^0-9a-fA-F]', '', 'g'))) WHERE mac_address IS NOT NULL")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_unique_address_norm ON assets "
               "(lower(btrim(device_unique_address))) WHERE device_unique_address IS NOT NULL")


def downgrade() -> None:
    for name in ("ux_assets_serial_norm", "ux_assets_mac_norm", "ux_assets_unique_address_norm"):
        op.execute(f"DROP INDEX IF EXISTS {name}")
