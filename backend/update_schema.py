import asyncio
from sqlalchemy import text
from app.core.database import engine

async def update_schema():
    async with engine.begin() as conn:
        print("Checking users table...")
        cols_query = await conn.execute(text(
            "SELECT column_name FROM information_schema.columns WHERE table_name='users'"
        ))
        existing_cols = {row[0] for row in cols_query}

        new_user_cols = {
            "totp_factor2_secret": "VARCHAR(64)",
            "is_totp_factor2_enabled": "BOOLEAN DEFAULT False",
            "totp_factor3_secret": "VARCHAR(64)",
            "is_totp_factor3_enabled": "BOOLEAN DEFAULT False"
        }
        for col, type_def in new_user_cols.items():
            if col not in existing_cols:
                print(f"Adding users.{col}")
                await conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} {type_def}"))

        print("Checking assets table...")
        cols_query = await conn.execute(text(
            "SELECT column_name FROM information_schema.columns WHERE table_name='assets'"
        ))
        existing_cols = {row[0] for row in cols_query}

        new_asset_cols = {
            "parent_asset_id": "UUID",
            "action_id": "VARCHAR(64)",
            "action_type": "VARCHAR(20)",
            "approval_status": "VARCHAR(20) DEFAULT 'ACTIVE'",
            "watermark_metadata": "JSON",
            "is_physical": "BOOLEAN DEFAULT False",
            "mac_address": "VARCHAR(64)",
            "device_unique_address": "VARCHAR(128)",
            "location": "VARCHAR(255)",
            "department": "VARCHAR(255)"
        }
        for col, type_def in new_asset_cols.items():
            if col not in existing_cols:
                print(f"Adding assets.{col}")
                await conn.execute(text(f"ALTER TABLE assets ADD COLUMN {col} {type_def}"))

        print("Applying unique constraints and indexes...")
        try:
            await conn.execute(text("CREATE UNIQUE INDEX ix_assets_action_id ON assets (action_id) WHERE action_id IS NOT NULL"))
            await conn.execute(text("CREATE UNIQUE INDEX ix_assets_mac_address ON assets (mac_address) WHERE mac_address IS NOT NULL"))
            await conn.execute(text("CREATE UNIQUE INDEX ix_assets_device_unique_address ON assets (device_unique_address) WHERE device_unique_address IS NOT NULL"))
        except Exception as e:
            print(f"Index creation skipped/failed: {e}")

        # The new document_actions table will be created by Base.metadata.create_all on startup

    print("Schema updated successfully.")

if __name__ == "__main__":
    asyncio.run(update_schema())
