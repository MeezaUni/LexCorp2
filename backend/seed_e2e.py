import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy import select, update
from app.models.domain import User
from app.core.config import settings

async def seed():
    engine = create_async_engine(settings.DATABASE_URL, echo=True)
    async with AsyncSession(engine) as session:
        # Hardhat admin signer (Account #0)
        admin_wallet = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".lower()
        admin_did = f"did:ethr:{settings.CHAIN_ID}:{admin_wallet}"

        # Insert or update to ADMIN
        result = await session.execute(select(User).where(User.wallet_address == admin_wallet))
        user = result.scalar_one_or_none()
        if user:
            user.role = "ADMIN"
            user.is_active = True
        else:
            session.add(User(wallet_address=admin_wallet, did=admin_did, role="ADMIN", name="Admin Manager", is_active=True))

        await session.commit()
        print("Successfully seeded E2E users into PostgreSQL.")
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(seed())
