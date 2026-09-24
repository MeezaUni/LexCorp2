import pytest
import pytest_asyncio
import httpx
from unittest.mock import patch
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import select, text
from app.main import app
from app.core.database import get_db
from app.core.config import settings
from app.models.domain import User

@pytest_asyncio.fixture(scope="function", autouse=True)
def mock_mfa_factors(request):
    """Bypass MFA assertions for regression tests not specifically testing WebAuthn/TOTP assertions."""
    if "test_passkey_factors.py" in str(request.node.fspath) or "test_approval_factor3_totp_enforcement" in request.node.name:
        yield
    else:
        with patch("app.api.assets.auth.is_assertion_valid", return_value=True):
            yield

TEST_USERS = [
    {
        "wallet_address": "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower(),
        "role": "ADMIN",
        "session_version": 5,
        "is_active": True,
        "department": "Avionics",
        "name": "Test Admin"
    },
    {
        "wallet_address": "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower(),
        "role": "MANAGER",
        "session_version": 8,
        "is_active": True,
        "department": "Avionics",
        "name": "Test Manager"
    },
    {
        "wallet_address": "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower(),
        "role": "USER",
        "session_version": 1,
        "is_active": True,
        "department": "Avionics",
        "name": "Test User"
    },
    {
        "wallet_address": "0xb8b8cf51335fa22e7967a9e72c16f738ddc7b5df".lower(),
        "role": "USER",
        "session_version": 0,
        "is_active": False,
        "department": "Cyber",
        "name": "Inactive User"
    },
    {
        "wallet_address": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".lower(),
        "role": "AUDITOR",
        "session_version": 1,
        "is_active": True,
        "department": "Cyber",
        "name": "Test Auditor"
    }
]

@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_database():
    """Ensure tables exist and have latest columns."""
    from app.core.database import engine
    from app.models.base import Base
    import app.models.domain  # Register models
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Ensure alert_status column exists
        await conn.execute(text("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS alert_status VARCHAR DEFAULT 'OPEN';"))
    await engine.dispose()
    yield

@pytest_asyncio.fixture(scope="session", autouse=True)
async def seed_test_users():
    """Ensure test users required for regression tests exist in the database."""
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        for u_data in TEST_USERS:
            res = await session.execute(
                select(User).where(User.wallet_address == u_data["wallet_address"])
            )
            existing = res.scalar_one_or_none()
            if not existing:
                u = User(
                    wallet_address=u_data["wallet_address"],
                    did=f"did:ethr:{settings.CHAIN_ID}:{u_data['wallet_address']}",
                    role=u_data["role"],
                    session_version=u_data["session_version"],
                    is_active=u_data["is_active"],
                    department=u_data["department"],
                    name=u_data["name"],
                    is_totp_enabled=True,
                    is_totp_factor2_enabled=True,
                    is_totp_factor3_enabled=True,
                    onboarding_pending=False
                )
                session.add(u)
            else:
                existing.role = u_data["role"]
                existing.session_version = u_data["session_version"]
                existing.is_active = u_data["is_active"]
                existing.department = u_data["department"]
                existing.is_totp_enabled = True
                existing.is_totp_factor2_enabled = True
                existing.is_totp_factor3_enabled = True
                existing.onboarding_pending = False
        await session.commit()
    await engine.dispose()

@pytest_asyncio.fixture(scope="function", autouse=True)
async def reset_user_mfa(db_session):
    """Ensure MFA is disabled except for 2FA tracking and simulate onboarded state for all test users before each test."""
    for u_data in TEST_USERS:
        res = await db_session.execute(
            select(User).where(User.wallet_address == u_data["wallet_address"])
        )
        user = res.scalar_one_or_none()
        if user:
            user.is_totp_enabled = True
            user.is_totp_factor2_enabled = True
            user.is_totp_factor3_enabled = True
            user.totp_factor2_secret = None
            user.totp_factor3_secret = None
            user.onboarding_pending = False
    await db_session.commit()

@pytest_asyncio.fixture(scope="function")
async def db_session():
    """Create a fresh async engine and session for each test to avoid event-loop closure conflicts."""
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()

@pytest_asyncio.fixture(scope="function")
async def client(db_session):
    """FastAPI test client with properly scoped database session dependency override."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()

@pytest_asyncio.fixture(scope="function")
async def async_client(client):
    """Alias for client fixture to ensure compatibility across existing test suites."""
    yield client
