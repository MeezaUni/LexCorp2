"""Authentication hardening: hashed provisioning PINs, TOTP replay counters,
server-side session activity, identity revocation fields, DB-backed challenges
and purpose-bound step-up grants.

Data changes (scoped, idempotent):
- users.one_time_pin (plaintext) -> users.pin_hash (scrypt); plaintext cleared.
  Expiry and used-state are preserved, so an outstanding PIN keeps working
  exactly until its original 3-hour deadline.
- naive UTC timestamps (pin_expires_at, token_expires_at) -> timestamptz.

Revision ID: 0003_auth_hardening
Revises: 0002_sync_existing_schema
"""
import hashlib
import secrets
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_auth_hardening"
down_revision: Union[str, None] = "0002_sync_existing_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _run(sql: str) -> None:
    for stmt in sql.split(";"):
        if stmt.strip():
            op.execute(stmt)


def _hash_pin(pin: str) -> str:
    # Must match app.core.crypto.hash_pin
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(pin.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def upgrade() -> None:
    _run("""
    ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_hash VARCHAR(200);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_requested_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_reason TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS revocation_reason TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_factor2_last_step BIGINT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_factor3_last_step BIGINT;
    ALTER TABLE users ALTER COLUMN totp_secret TYPE VARCHAR(255);
    ALTER TABLE users ALTER COLUMN totp_factor2_secret TYPE VARCHAR(255);
    ALTER TABLE users ALTER COLUMN totp_factor3_secret TYPE VARCHAR(255)
    """)

    bind = op.get_bind()
    for table, column in (("users", "pin_expires_at"), ("document_actions", "token_expires_at")):
        dtype = bind.execute(sa.text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ), {"t": table, "c": column}).scalar()
        if dtype == "timestamp without time zone":
            op.execute(
                f"ALTER TABLE {table} ALTER COLUMN {column} TYPE TIMESTAMPTZ "
                f"USING {column} AT TIME ZONE 'UTC'"
            )

    rows = bind.execute(sa.text(
        "SELECT id, one_time_pin FROM users WHERE one_time_pin IS NOT NULL AND pin_hash IS NULL"
    )).fetchall()
    for user_id, pin in rows:
        bind.execute(
            sa.text("UPDATE users SET pin_hash = :h, one_time_pin = NULL WHERE id = :id"),
            {"h": _hash_pin(pin), "id": user_id},
        )

    _run("""
    CREATE TABLE IF NOT EXISTS auth_challenges (
        id UUID PRIMARY KEY,
        kind VARCHAR(20) NOT NULL,
        wallet_address VARCHAR(42),
        user_id UUID REFERENCES users(id),
        purpose VARCHAR(20),
        action VARCHAR(64),
        challenge VARCHAR(255) NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        consumed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_auth_challenges_kind ON auth_challenges (kind);
    CREATE INDEX IF NOT EXISTS ix_auth_challenges_wallet_address ON auth_challenges (wallet_address);
    CREATE UNIQUE INDEX IF NOT EXISTS ix_auth_challenges_challenge ON auth_challenges (challenge);

    CREATE TABLE IF NOT EXISTS step_up_grants (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(id),
        purpose VARCHAR(20) NOT NULL,
        action VARCHAR(64) NOT NULL,
        method VARCHAR(10) NOT NULL,
        token_hash VARCHAR(64) NOT NULL,
        session_version INTEGER NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        consumed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_step_up_grants_user_id ON step_up_grants (user_id);
    CREATE UNIQUE INDEX IF NOT EXISTS ix_step_up_grants_token_hash ON step_up_grants (token_hash)
    """)


def downgrade() -> None:
    raise NotImplementedError("0003 is forward-only: PIN plaintext is intentionally unrecoverable.")
