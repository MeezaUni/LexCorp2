import os
import base64 as _b64
import secrets as _secrets

# Tests run with ENVIRONMENT=test and freshly generated random secrets per run; the
# application has no built-in secret defaults to fall back on.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("JWT_SECRET", _secrets.token_urlsafe(48))
os.environ.setdefault("VC_SIGNING_SECRET", _secrets.token_urlsafe(48))
os.environ.setdefault("DATA_ENCRYPTION_KEYS", _b64.urlsafe_b64encode(_secrets.token_bytes(32)).decode())

# Tests must never touch the live lexcorp_sih database. Point the app at an
# isolated *_test database before app modules create their engines.
os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://lexcorp:lexcorp_dev@localhost:5432/lexcorp_sih_test"
)
os.environ.setdefault(
    "DATABASE_URL_SYNC", "postgresql://lexcorp:lexcorp_dev@localhost:5432/lexcorp_sih_test"
)
# Test file storage is isolated from the live off-chain vault.
os.environ.setdefault(
    "OFFCHAIN_STORAGE_DIR", os.path.join(os.path.dirname(__file__), ".test_storage")
)
# Contract calldata is built against an isolated deployment record generated from the
# compiled AssetNFT v3 ABI (a placeholder address; tests never send live transactions).
def _write_test_deployment() -> str:
    import json
    here = os.path.dirname(os.path.abspath(__file__))
    artifact = os.path.join(here, "..", "..", "contracts", "artifacts", "contracts", "AssetNFT.sol", "AssetNFT.json")
    with open(artifact, encoding="utf-8") as f:
        abi = json.load(f)["abi"]
    path = os.path.join(here, ".test_deployment.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"address": "0x" + "11" * 20, "chainId": 13371, "contractVersion": 3, "abi": abi,
                   "admin": "0x" + "22" * 20, "registrar": "0x" + "33" * 20}, f)
    return path


os.environ.setdefault("CONTRACT_DEPLOYMENT_PATH", _write_test_deployment())

if not os.environ["DATABASE_URL"].rstrip("/").endswith("_test"):
    raise RuntimeError("Refusing to run tests: DATABASE_URL must point at a *_test database.")

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

import pyotp
from app.core.crypto import encrypt_secret

# Deterministic per-user, per-purpose TOTP secrets for tests. No MFA bypass exists:
# tests must present a real TOTP code or a real step-up grant for the right purpose.
def totp_secret_for(wallet: str, purpose: str) -> str:
    import base64, hashlib
    raw = hashlib.sha256(f"{wallet.lower()}:{purpose}".encode()).digest()[:20]
    return base64.b32encode(raw).decode()


def totp_code(wallet: str, purpose: str) -> str:
    return pyotp.TOTP(totp_secret_for(wallet, purpose)).now()


async def mfa_headers(db, token: str, wallet: str, action: str) -> dict:
    """Authorization header plus a genuine step-up grant for one action."""
    return {"Authorization": f"Bearer {token}", "X-Step-Up-Token": await step_up_token(db, wallet, action)}


async def step_up_token(db, wallet: str, action: str) -> str:
    """Mint a genuine step-up grant (the same record a passkey assertion produces)."""
    from app.services import mfa
    user = (await db.execute(select(User).where(User.wallet_address == wallet.lower()))).scalar_one()
    grant = await mfa.issue_step_up(db, user, mfa.ACTION_PURPOSE[action], action, "PASSKEY")
    await db.commit()
    return grant["step_up_token"]

async def step_up_header(wallet: str, action: str) -> dict:
    """{'X-Step-Up-Token': ...} for one action, minted on a private connection."""
    from sqlalchemy.pool import NullPool
    engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
    try:
        async with async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)() as db:
            return {"X-Step-Up-Token": await step_up_token(db, wallet, action)}
    finally:
        await engine.dispose()


# Vault files referenced by test proposals. Their recorded hashes must be the real
# SHA-256 of these bytes (the API recomputes it), so each file holds exactly the
# content its test declares (empty = e3b0c442..., "Hello World" = a591a6d4...).
_VAULT_FIXTURES = {
    **{name: b"" for name in ("guidance.pdf", "guidance2.pdf", "auth.txt", "defective.pdf", "f2.pdf",
                              "pending.txt", "pk.txt", "spec.pdf", "view_test.png", "view_test_2.png", "view_test_3.png")},
    "cyber_doc.pdf": b"Hello World",
}


@pytest.fixture(autouse=True)
def vault_fixture_files():
    root = os.path.join(os.environ["OFFCHAIN_STORAGE_DIR"], "documents")
    os.makedirs(root, exist_ok=True)
    for name, content in _VAULT_FIXTURES.items():
        with open(os.path.join(root, name), "wb") as f:
            f.write(content)
    yield


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Rate limits stay active inside a test; counters just don't leak between tests."""
    from app.core.limiter import limiter
    limiter.reset()
    yield


class FakeRoleSync:
    """In-memory stand-in for the chain-operator transport (services.chain.RoleSync).
    It applies exactly the same role mapping, so tests assert WHICH on-chain roles the
    backend grants/revokes; live-Besu behaviour is covered by tests/test_besu_live.py."""
    roles: dict = {}

    def __init__(self):
        pass

    def sync(self, wallet, role, is_active):
        from app.services.chain import desired_roles
        want, have = desired_roles(role, is_active), FakeRoleSync.roles.get(wallet.lower(), set())
        FakeRoleSync.roles[wallet.lower()] = set(want)
        return {"wallet": wallet, "granted": sorted(want - have), "revoked": sorted(have - want),
                "roles": sorted(want), "tx_hashes": []}


@pytest.fixture(autouse=True)
def fake_chain_roles():
    """Tests never send live transactions from the app; they observe intended role changes."""
    FakeRoleSync.roles = {}
    with patch("app.services.chain.RoleSync", FakeRoleSync):
        yield FakeRoleSync.roles


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
    """Rebuild the isolated *_test schema from Alembic migrations (not create_all),
    so every test run also proves the migration chain produces the model schema."""
    import subprocess
    import sys
    from pathlib import Path
    from app.core.database import engine
    async with engine.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    await engine.dispose()
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=Path(__file__).resolve().parents[1],
        env=os.environ.copy(),
        check=True,
        capture_output=True,
    )
    yield

@pytest_asyncio.fixture(scope="session", autouse=True)
async def seed_test_users(setup_database):
    """Ensure test users required for regression tests exist in the database."""
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        from app.models.domain import Department
        for name in ("Avionics", "Cyber", "Radar", "Radar Dept"):
            if not (await session.execute(select(Department).where(Department.name == name))).scalar_one_or_none():
                session.add(Department(name=name, is_active=True))
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
                u.totp_secret = encrypt_secret(totp_secret_for(u_data["wallet_address"], "login"))
                u.totp_factor2_secret = encrypt_secret(totp_secret_for(u_data["wallet_address"], "factor2"))
                u.totp_factor3_secret = encrypt_secret(totp_secret_for(u_data["wallet_address"], "factor3"))
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
            user.totp_secret = encrypt_secret(totp_secret_for(u_data["wallet_address"], "login"))
            user.totp_factor2_secret = encrypt_secret(totp_secret_for(u_data["wallet_address"], "factor2"))
            user.totp_factor3_secret = encrypt_secret(totp_secret_for(u_data["wallet_address"], "factor3"))
            user.totp_last_step = None
            user.totp_factor2_last_step = None
            user.totp_factor3_last_step = None
            user.last_activity_at = None
            user.session_version = u_data["session_version"]
            user.is_active = u_data["is_active"]
            user.revoked_at = None
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
