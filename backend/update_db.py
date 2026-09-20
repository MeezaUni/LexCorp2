import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "lexcorp.db")
if not os.path.exists(DB_PATH):
    # Try alternate location
    DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../lexcorp_demo.db"))

print(f"Migrating database: {DB_PATH}")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

def add_col_if_missing(table, column, col_type):
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type};")
        print(f"Added column {column} to {table}")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e) or "already exists" in str(e):
            pass
        else:
            print(f"Note on {table}.{column}: {e}")

# 1. Update Users table
add_col_if_missing("users", "organization", "VARCHAR(255) DEFAULT 'Bharat Electronics Limited (BEL)'")
add_col_if_missing("users", "department", "VARCHAR(255)")
add_col_if_missing("users", "totp_secret", "VARCHAR(64)")
add_col_if_missing("users", "is_totp_enabled", "BOOLEAN DEFAULT 0")

# 2. Update Assets table
add_col_if_missing("assets", "name", "VARCHAR(255)")
add_col_if_missing("assets", "asset_type", "VARCHAR(50) DEFAULT 'EQUIPMENT'")
add_col_if_missing("assets", "file_hash", "VARCHAR(64)")
add_col_if_missing("assets", "custodian_id", "UUID")
add_col_if_missing("assets", "custodian_did", "VARCHAR")
add_col_if_missing("assets", "custodian_department", "VARCHAR(255)")
add_col_if_missing("assets", "lifecycle_status", "VARCHAR(30) DEFAULT 'CREATED'")

# 3. Create WebAuthn table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    credential_id VARCHAR(512) UNIQUE,
    public_key TEXT NOT NULL,
    sign_count INTEGER DEFAULT 0,
    device_name VARCHAR(255) DEFAULT 'Biometric Authenticator',
    transports JSON,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
""")

# 4. Create Maintenance table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS maintenance_records (
    id VARCHAR(36) PRIMARY KEY,
    asset_serial VARCHAR(255) NOT NULL,
    performed_by_did VARCHAR(255) NOT NULL,
    action_description TEXT NOT NULL,
    notes TEXT,
    log_hash VARCHAR(64),
    tx_hash VARCHAR(66),
    created_at DATETIME,
    updated_at DATETIME
);
""")

conn.commit()
conn.close()
print("Database schema synchronization complete!")
