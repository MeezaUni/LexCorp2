import asyncio
from sqlalchemy import text
from app.core.database import async_session_factory

async def migrate():
    async with async_session_factory() as session:
        print("Migrating PostgreSQL tables...")
        try:
            await session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_pending BOOLEAN DEFAULT TRUE;"))
            await session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER DEFAULT 0;"))
            await session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS one_time_pin VARCHAR(64);"))
            await session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_expires_at TIMESTAMP;"))
            await session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_used BOOLEAN DEFAULT FALSE;"))
            await session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_requested BOOLEAN DEFAULT FALSE;"))
            print("Successfully checked/added User OTP and reset request columns.")
        except Exception as e:
            print(f"Error adding user OTP columns: {e}")

        try:
            await session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_factor2_secret VARCHAR(64);"))
            await session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_totp_factor2_enabled BOOLEAN DEFAULT FALSE;"))
            await session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_factor3_secret VARCHAR(64);"))
            await session.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_totp_factor3_enabled BOOLEAN DEFAULT FALSE;"))
            print("Successfully checked/added Factor 2 and Factor 3 columns.")
        except Exception as e:
            print(f"Error adding factor 2/3 columns: {e}")

        try:
            await session.execute(text("ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS factor_scope VARCHAR(20) DEFAULT 'login';"))
            await session.execute(text("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS client_ip VARCHAR(64);"))
            print("Successfully checked/added factor_scope/client_ip.")
        except Exception as e:
            print(f"Error adding factor_scope/client_ip: {e}")

        await session.commit()
        print("Migration committed.")

if __name__ == "__main__":
    asyncio.run(migrate())
