"""Bring 0001 schema up to the schema the application has been running with.

The live database was built with ``Base.metadata.create_all`` rather than
Alembic, so it already has everything below. Every statement is idempotent
(IF NOT EXISTS / guarded DO blocks) so this revision is a no-op there and
builds the full schema on a database that only has 0001 applied.

Revision ID: 0002_sync_existing_schema
Revises: 0001_initial_schema
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0002_sync_existing_schema"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _fk(name: str, table: str, column: str, ref: str) -> str:
    return f"""
    DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '{name}') THEN
            ALTER TABLE {table} ADD CONSTRAINT {name} FOREIGN KEY ({column}) REFERENCES {ref};
        END IF;
    END $$;
    """


def _run(sql: str) -> None:
    """asyncpg rejects multi-statement strings; execute one statement at a time."""
    for stmt in sql.split(";"):
        if stmt.strip():
            op.execute(stmt)


def upgrade() -> None:
    _run("""
    CREATE TABLE IF NOT EXISTS asset_access_grants (
        id UUID PRIMARY KEY,
        asset_serial VARCHAR NOT NULL,
        grantee_did VARCHAR NOT NULL,
        granted_by_did VARCHAR NOT NULL,
        access_level INTEGER NOT NULL,
        max_views INTEGER,
        views_count INTEGER NOT NULL,
        is_active BOOLEAN NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_asset_access_grants_asset_serial ON asset_access_grants (asset_serial);
    CREATE INDEX IF NOT EXISTS ix_asset_access_grants_grantee_did ON asset_access_grants (grantee_did);

    CREATE TABLE IF NOT EXISTS maintenance_records (
        id UUID PRIMARY KEY,
        asset_serial VARCHAR NOT NULL,
        performed_by_did VARCHAR NOT NULL,
        action_description TEXT NOT NULL,
        notes TEXT,
        log_hash VARCHAR(64),
        tx_hash VARCHAR(66),
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_maintenance_records_asset_serial ON maintenance_records (asset_serial);
    CREATE INDEX IF NOT EXISTS ix_maintenance_records_performed_by_did ON maintenance_records (performed_by_did);

    ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(255);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS contact_number VARCHAR(255);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS organization VARCHAR(255) NOT NULL DEFAULT 'Bharat Electronics Limited (BEL)';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS department VARCHAR(255);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_pending BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS one_time_pin VARCHAR(64);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_expires_at TIMESTAMP;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_used BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_requested BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(64);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_factor2_secret VARCHAR(64);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_totp_factor2_enabled BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_factor3_secret VARCHAR(64);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_totp_factor3_enabled BOOLEAN NOT NULL DEFAULT FALSE;

    CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(id),
        credential_id VARCHAR(512) NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL,
        device_name VARCHAR(255),
        transports JSON,
        is_active BOOLEAN NOT NULL,
        factor_scope VARCHAR(20) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS ix_webauthn_credentials_credential_id ON webauthn_credentials (credential_id);

    ALTER TABLE assets ADD COLUMN IF NOT EXISTS name VARCHAR(255);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS asset_type VARCHAR(50) NOT NULL DEFAULT 'EQUIPMENT';
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS file_hash VARCHAR(64);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS custodian_id UUID;
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS custodian_did VARCHAR;
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS custodian_department VARCHAR;
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS lifecycle_status VARCHAR(30) NOT NULL DEFAULT 'CREATED';
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS parent_asset_id UUID;
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS action_id VARCHAR(64);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS action_type VARCHAR(20);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE';
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS watermark_metadata JSON;
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS is_physical BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS mac_address VARCHAR(64);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS device_unique_address VARCHAR(128);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS location VARCHAR(255);
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS department VARCHAR(255);
    CREATE UNIQUE INDEX IF NOT EXISTS ix_assets_action_id ON assets (action_id);
    CREATE INDEX IF NOT EXISTS ix_assets_action_type ON assets (action_type);
    CREATE UNIQUE INDEX IF NOT EXISTS ix_assets_device_unique_address ON assets (device_unique_address);
    CREATE UNIQUE INDEX IF NOT EXISTS ix_assets_mac_address ON assets (mac_address);
    """)
    op.execute(_fk("assets_custodian_id_fkey", "assets", "custodian_id", "users(id)"))
    op.execute(_fk("assets_parent_asset_id_fkey", "assets", "parent_asset_id", "assets(id)"))
    _run("""
    ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS client_ip VARCHAR(64);
    ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS risk_factors JSON;
    ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS alert_status VARCHAR NOT NULL DEFAULT 'OPEN';

    CREATE TABLE IF NOT EXISTS document_actions (
        id UUID PRIMARY KEY,
        action_id VARCHAR(64) NOT NULL,
        action_type VARCHAR(20) NOT NULL,
        asset_id UUID REFERENCES assets(id),
        asset_serial VARCHAR,
        actor_id UUID NOT NULL REFERENCES users(id),
        actor_did VARCHAR NOT NULL,
        approver_id UUID REFERENCES users(id),
        approver_did VARCHAR,
        status VARCHAR(20) NOT NULL,
        purpose TEXT,
        client_ip VARCHAR(64),
        download_token VARCHAR(128),
        token_expires_at TIMESTAMP,
        watermark_text TEXT,
        details JSON,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS ix_document_actions_action_id ON document_actions (action_id);
    CREATE INDEX IF NOT EXISTS ix_document_actions_action_type ON document_actions (action_type);
    CREATE INDEX IF NOT EXISTS ix_document_actions_actor_did ON document_actions (actor_did);
    CREATE INDEX IF NOT EXISTS ix_document_actions_asset_serial ON document_actions (asset_serial);
    CREATE UNIQUE INDEX IF NOT EXISTS ix_document_actions_download_token ON document_actions (download_token);
    """)


def downgrade() -> None:
    # Irreversible by design: dropping these columns would destroy data.
    raise NotImplementedError("0002 is a forward-only schema sync.")
