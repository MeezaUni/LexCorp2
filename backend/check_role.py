import asyncio
from app.core.database import async_session_factory
from app.models.domain import User
from sqlalchemy import select, update

async def run():
    async with async_session_factory() as session:
        addr = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
        res = await session.execute(select(User).where(User.wallet_address == addr))
        user = res.scalar_one_or_none()
        if user:
            print(f'User found: {user.wallet_address}, Role: {user.role}')
            if user.role != 'AUDITOR':
                user.role = 'AUDITOR'
                await session.commit()
                print('Updated role to AUDITOR')
        else:
            print('User not found in DB! Creating...')
            # Create user on the fly as AUDITOR since they will log in
            new_user = User(wallet_address=addr, role='AUDITOR')
            session.add(new_user)
            await session.commit()
            print('Created user as AUDITOR')

asyncio.run(run())
