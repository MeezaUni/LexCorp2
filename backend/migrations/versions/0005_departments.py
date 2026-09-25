"""Departments as a server-side source of truth, and managers' extra scopes.

- departments: seeded ONLY from department names already present on users or
  assets (no invented values). Admins add new ones via the API.
- users.managed_departments: optional extra departments a MANAGER may manage
  in addition to users.department.

Revision ID: 0005_departments
Revises: 0004_wallet_wrap_secret
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0005_departments"
down_revision: Union[str, None] = "0004_wallet_wrap_secret"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS departments (
        id UUID PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    )""")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_departments_name ON departments (name)")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS managed_departments JSON")
    op.execute("""
    INSERT INTO departments (id, name, is_active, created_at, updated_at)
    SELECT gen_random_uuid(), d, TRUE, now(), now() FROM (
        SELECT DISTINCT btrim(department) AS d FROM users WHERE department IS NOT NULL AND btrim(department) <> ''
        UNION
        SELECT DISTINCT btrim(department) FROM assets WHERE department IS NOT NULL AND btrim(department) <> ''
    ) existing
    ON CONFLICT (name) DO NOTHING""")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS managed_departments")
    op.execute("DROP TABLE IF EXISTS departments")
