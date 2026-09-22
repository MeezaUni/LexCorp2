import sqlite3
import uuid
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert
import datetime

# PostgreSQL connection String
POSTGRES_URL = "postgresql://lexcorp:lexcorp_dev@localhost:5432/lexcorp_sih"
SQLITE_DB = "backend/lexcorp_demo.db"

# The table order to respect Foreign Key constraints
TABLE_ORDER = [
    'users',
    'assets',
    'webauthn_credentials',
    'verifiable_credentials',
    'maintenance_records',
    'access_requests',
    'audit_events'
]

# PK mappings for ON CONFLICT support
TABLE_PKS = {
    'users': 'id',
    'assets': 'id',
    'webauthn_credentials': 'id',
    'verifiable_credentials': 'id',
    'maintenance_records': 'id',
    'access_requests': 'id',
    'audit_events': 'id'
}

def format_uuid(val):
    if not val: 
        return None
    try:
        # Check if it's already a valid UUID format
        if isinstance(val, str) and len(val) == 32:
            return str(uuid.UUID(hex=val))
        return str(uuid.UUID(str(val)))
    except:
        return None

def migrate_table(sqlite_con, pg_engine, table_name):
    print(f"\nMigrating table: {table_name}")
    
    # 1. Fetch from SQLite
    try:
        cursor = sqlite_con.cursor()
        cursor.execute(f"SELECT * FROM {table_name}")
        columns = [description[0] for description in cursor.description]
        data = [dict(zip(columns, row)) for row in cursor.fetchall()]
        print(f"  Found {len(data)} rows in SQLite.")
    except Exception as e:
        print(f"  Table skipped (does not exist in SQLite or error): {e}")
        return

    if not data:
        return
        
    valid_records = []
    
    # Track existing user IDs in PG for FK validation
    with pg_engine.connect() as check_conn:
        pg_users = check_conn.execute(text("SELECT id FROM users")).fetchall()
        valid_pg_user_ids = {str(row[0]) for row in pg_users}
    
    for record in data:
        # Normalize UUID fields
        for col_name, val in record.items():
            if val and isinstance(val, str) and len(val) == 32 and ('id' in col_name or 'owner' in col_name):
                record[col_name] = format_uuid(val)
                
            # Date normalization if any (convert strings to exact format or assume SQLAlchemy core handles ISO strings but to be safe)
            if val and col_name in ['created_at', 'updated_at']:
                if isinstance(val, str) and 'T' not in val and not val.endswith('Z') and len(val) <= 19:
                     record[col_name] = val + "+00:00" # naive to UTC
        
        # Foreign Key validations
        if table_name == 'assets' and 'owner_id' in record:
            if record['owner_id'] not in valid_pg_user_ids:
                # Fallback: reassign to an admin user instead of dropping data
                admin_id = next((u for u in valid_pg_user_ids), None)
                print(f"  [INTEGRITY FIX] Orphan asset {record.get('serial_number')}: owner_id {record['owner_id']} not found. Reassigning to valid user {admin_id}")
                record['owner_id'] = admin_id
                
        if table_name in ['webauthn_credentials', 'verifiable_credentials'] and 'user_id' in record:
            if record['user_id'] not in valid_pg_user_ids:
                print(f"  Skipping orphan record in {table_name} for user_id {record['user_id']}.")
                continue
                
        valid_records.append(record)

    if not valid_records:
        print("  No valid records to migrate after checks.")
        return
        
    # 2. Insert into PostgreSQL using UPSERT (ON CONFLICT DO NOTHING)
    from app.models.base import Base # import here to avoid circular
    import app.models.domain
    meta = Base.metadata
    
    pg_table = meta.tables.get(table_name)
    if pg_table is None:
        print(f"  Table {table_name} not found in SQLAlchemy metadata.")
        return

    try:
        with pg_engine.begin() as conn:
            stmt = insert(pg_table).values(valid_records)
            
            # Simple ON CONFLICT DO NOTHING using the primary key
            pk = TABLE_PKS.get(table_name)
            if pk:
                stmt = stmt.on_conflict_do_nothing(index_elements=[pk])
                
            result = conn.execute(stmt)
            print(f"  Successfully processed {len(valid_records)} records into PostgreSQL ({result.rowcount} newly inserted).")
    except Exception as e:
        print(f"  Failed migrating {table_name}: {e}")


def run_migration():
    sqlite_con = sqlite3.connect(SQLITE_DB)
    pg_engine = create_engine(POSTGRES_URL)
    
    # Make sure PG tables exist
    from app.models.base import Base
    import app.models.domain
    print("Ensuring target schema exists in PostgreSQL...")
    Base.metadata.create_all(pg_engine)
    
    print("\n--- Starting Data Transfer ---")
    for table_name in TABLE_ORDER:
        migrate_table(sqlite_con, pg_engine, table_name)
        
    sqlite_con.close()
    print("\n--- Migration Complete ---")

if __name__ == "__main__":
    run_migration()
