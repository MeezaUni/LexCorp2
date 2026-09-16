import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select
import sys
import os

sys.path.append(os.getcwd() + '/backend')
from app.models.domain import User

async def main():
    engine = create_async_engine('sqlite+aiosqlite:///backend/lexcorp_demo.db')
    sessionmaker = async_sessionmaker(engine)
    async with sessionmaker() as session:
        result = await session.execute(select(User))
        users = result.scalars().all()
        for u in users:
            print(f"ID: {u.id}, Wallet: {u.wallet_address}, Active: {u.is_active}, Role: {u.role}")

asyncio.run(main())
