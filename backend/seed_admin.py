"""Seed an ADMIN user into the database."""

import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import async_session_factory
from app.models.domain import User
from app.core.config import settings

# Generated Admin Wallet
ADMIN_WALLET = "0x95ea9708BCf136d710A4b8e76FE20F895ecA003A"
ADMIN_NAME = "System Administrator"
ADMIN_CONTACT = "admin@lexcorp.local"

async def seed_admin():
    """Create or update the admin user."""
    async with async_session_factory() as db:
        try:
            # Check if admin already exists
            result = await db.execute(
                select(User).where(User.wallet_address == ADMIN_WALLET.lower())
            )
            existing_admin = result.scalar_one_or_none()

            admin_did = f"did:ethr:{settings.CHAIN_ID}:{ADMIN_WALLET.lower()}"

            if existing_admin:
                # Update existing admin
                existing_admin.role = "ADMIN"
                existing_admin.name = ADMIN_NAME
                existing_admin.contact_number = ADMIN_CONTACT
                existing_admin.is_active = True
                print(f"[OK] Updated existing admin user: {ADMIN_WALLET}")
            else:
                # Create new admin
                new_admin = User(
                    wallet_address=ADMIN_WALLET.lower(),
                    name=ADMIN_NAME,
                    contact_number=ADMIN_CONTACT,
                    did=admin_did,
                    role="ADMIN",
                    is_active=True
                )
                db.add(new_admin)
                print(f"[OK] Created new admin user: {ADMIN_WALLET}")

            await db.commit()

            print("\n" + "="*70)
            print("ADMIN USER SEEDED SUCCESSFULLY")
            print("="*70)
            print(f"Wallet Address: {ADMIN_WALLET}")
            print(f"Private Key:    0x74745bf7bdc8ae82687ac8ac993fd752130fe45ed8d126818414105b71244809")
            print(f"DID:            {admin_did}")
            print(f"Role:           ADMIN")
            print(f"Name:           {ADMIN_NAME}")
            print(f"Contact:        {ADMIN_CONTACT}")
            print("="*70)
            print("\nIMPORTANT: Import this private key into MetaMask or your wallet to login.")
            print("="*70)

        except Exception as e:
            print(f"[ERROR] Error seeding admin: {e}")
            await db.rollback()
            raise

if __name__ == "__main__":
    asyncio.run(seed_admin())
