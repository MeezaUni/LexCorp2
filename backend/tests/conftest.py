import pytest_asyncio
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.main import app
from app.core.database import get_db
from app.core.config import settings

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
