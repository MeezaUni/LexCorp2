"""Remember which site name (WebAuthn RP ID) each passkey was created for.

People reach LexCorp2 as localhost on the server machine and by the VPN name remotely
(REMOTE_APP_ORIGIN). A passkey only works on the name it was created for, so each person
may have one passkey per purpose per name. Existing passkeys keep NULL, meaning the
configured default RP_ID.

Revision ID: 0015_passkey_rp_id
Revises: 0014_audit_actor_role
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0015_passkey_rp_id"
down_revision: Union[str, None] = "0014_audit_actor_role"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS rp_id VARCHAR(255)")


def downgrade() -> None:
    op.execute("ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS rp_id")
