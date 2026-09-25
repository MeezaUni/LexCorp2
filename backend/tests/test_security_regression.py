import pytest
import io
from datetime import datetime, timedelta, UTC
from jose import jwt
from app.services.auth import create_jwt
from tests.conftest import mfa_headers, totp_code
from app.core.config import settings

# Active Test Wallets mapped from PostgreSQL test DB
ACTIVE_ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
ACTIVE_ADMIN_VERSION = 5

ACTIVE_MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"
ACTIVE_MANAGER_VERSION = 8

ACTIVE_USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
ACTIVE_USER_VERSION = 1

INACTIVE_USER_WALLET = "0xb8b8cf51335fa22e7967a9e72c16f738ddc7b5df"
INACTIVE_USER_VERSION = 0

INACTIVE_AUDITOR_WALLET = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
INACTIVE_AUDITOR_VERSION = 0

def get_token(wallet: str, role: str, version: int) -> str:
    did = f"did:ethr:{settings.CHAIN_ID}:{wallet.lower()}"
    return create_jwt(wallet_address=wallet, did=did, role=role, session_version=version)


# ==============================================================================
# 1. JWT Authentication and Session Validation
# ==============================================================================

@pytest.mark.asyncio
async def test_unauthenticated_protected_endpoint(client):
    """Unauthenticated requests must be rejected with 401."""
    response = await client.get("/api/auth/me")
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]


@pytest.mark.asyncio
async def test_malformed_jwt_token(client):
    """Malformed tokens must return 401."""
    response = await client.get("/api/auth/me", headers={"Authorization": "Bearer not.a.valid.jwt"})
    assert response.status_code == 401
    assert "Session expired or invalid" in response.json()["detail"]


@pytest.mark.asyncio
async def test_expired_jwt_token(client):
    """Expired tokens must return 401."""
    now = datetime.now(UTC)
    payload = {
        "sub": ACTIVE_USER_WALLET.lower(),
        "did": f"did:ethr:{settings.CHAIN_ID}:{ACTIVE_USER_WALLET.lower()}",
        "role": "USER",
        "session_version": ACTIVE_USER_VERSION,
        "iat": now - timedelta(hours=2),
        "exp": now - timedelta(hours=1),
    }
    expired_token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    response = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401
    assert "Session expired or invalid" in response.json()["detail"]


@pytest.mark.asyncio
async def test_tampered_jwt_signature(client):
    """JWT signed with an unauthorized secret must fail with 401."""
    now = datetime.now(UTC)
    payload = {
        "sub": ACTIVE_ADMIN_WALLET.lower(),
        "did": f"did:ethr:{settings.CHAIN_ID}:{ACTIVE_ADMIN_WALLET.lower()}",
        "role": "ADMIN",
        "session_version": ACTIVE_ADMIN_VERSION,
        "iat": now,
        "exp": now + timedelta(minutes=30),
    }
    tampered_token = jwt.encode(payload, "wrong-secret-key-attacker-signature", algorithm=settings.JWT_ALGORITHM)
    response = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert response.status_code == 401


# ==============================================================================
# 2. Disabled Account & Session Revocation
# ==============================================================================

@pytest.mark.asyncio
async def test_disabled_account_rejection(client):
    """Disabled accounts (is_active=False) must be blocked with 403 Forbidden."""
    token = get_token(INACTIVE_USER_WALLET, "USER", INACTIVE_USER_VERSION)
    response = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert "Account is disabled" in response.json()["detail"]


@pytest.mark.asyncio
async def test_session_version_revocation(client):
    """Outdated session_version in JWT (due to new login elsewhere) must be rejected with 401."""
    # Active version is 1, pass 0
    stale_token = get_token(ACTIVE_USER_WALLET, "USER", 0)
    response = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {stale_token}"})
    assert response.status_code == 401
    assert "Session replaced" in response.json()["detail"]


# ==============================================================================
# 3. RBAC Enforcement (ADMIN, MANAGER, AUDITOR, USER)
# ==============================================================================

@pytest.mark.asyncio
async def test_user_cannot_transfer_assets(client):
    """USER role is forbidden from executing asset transfers."""
    token = get_token(ACTIVE_USER_WALLET, "USER", ACTIVE_USER_VERSION)
    response = await client.post(
        "/api/assets/transfer/prepare",
        headers={"Authorization": f"Bearer {token}"},
        json={"to_address": "0x1234567890123456789012345678901234567890", "token_id": 1, "new_owner_did": "did:ethr:13371:0x123"}
    )
    assert response.status_code == 403
    assert "is not permitted to transfer assets" in response.json()["detail"]


@pytest.mark.asyncio
async def test_user_cannot_mint_physical_defense_assets(client):
    """USER role cannot register physical defense hardware (only Manager & Admin)."""
    token = get_token(ACTIVE_USER_WALLET, "USER", ACTIVE_USER_VERSION)
    response = await client.post(
        "/api/assets/mint/prepare",
        headers={"Authorization": f"Bearer {token}"},
        json={"to_address": "0x1234567890123456789012345678901234567890", "token_id": 999, "serial_number": "SEC-PHY-001", "owner_did": "did:ethr:13371:0x123"}
    )
    assert response.status_code == 403
    assert "is not permitted to register physical defense hardware" in response.json()["detail"]


@pytest.mark.asyncio
async def test_manager_can_mint_physical_assets(client, db_session):
    """MANAGER may prepare the mint (Factor 3) of an APPROVED physical asset in their department,
    and never of an arbitrary / unregistered serial."""
    import uuid as _uuid
    from sqlalchemy import select as _select
    from app.models.domain import Asset, User as _User
    token = get_token(ACTIVE_MANAGER_WALLET, "MANAGER", ACTIVE_MANAGER_VERSION)
    body = {"to_address": "0x1234567890123456789012345678901234567890", "token_id": 999, "serial_number": "SEC-PHY-001", "owner_did": "did:ethr:13371:0x123"}
    arbitrary = await client.post("/api/assets/mint/prepare", headers=await mfa_headers(db_session, token, ACTIVE_MANAGER_WALLET, "asset.mint"), json=body)
    assert arbitrary.status_code == 409
    owner = (await db_session.execute(_select(_User).where(_User.wallet_address == ACTIVE_MANAGER_WALLET))).scalar_one()
    serial = f"SEC-PHY-{_uuid.uuid4().hex[:6]}"
    asset = Asset(token_id=_uuid.uuid4().int % 2_000_000_000, serial_number=serial, owner_id=owner.id, is_physical=True,
                  department="Avionics", approval_status="APPROVED", device_unique_address=f"UA-{_uuid.uuid4().hex[:8]}")
    db_session.add(asset)
    await db_session.commit()
    response = await client.post(
        "/api/assets/mint/prepare",
        headers=await mfa_headers(db_session, token, ACTIVE_MANAGER_WALLET, "asset.mint"),
        json={**body, "token_id": asset.token_id, "serial_number": serial}
    )
    assert response.status_code == 200
    assert "calldata" in response.json()


@pytest.mark.asyncio
async def test_admin_can_prepare_transfer(client):
    """ADMIN role is authorized to prepare asset transfers."""
    token = get_token(ACTIVE_ADMIN_WALLET, "ADMIN", ACTIVE_ADMIN_VERSION)
    response = await client.post(
        "/api/assets/transfer/prepare",
        headers={"Authorization": f"Bearer {token}"},
        json={"to_address": "0x1234567890123456789012345678901234567890", "token_id": 1, "new_owner_did": "did:ethr:13371:0x123"}
    )
    assert response.status_code == 200
    assert "calldata" in response.json()


# ==============================================================================
# 4. Custodian Assignment Authorization
# ==============================================================================

@pytest.mark.asyncio
async def test_user_cannot_reassign_custody(client):
    """USER role cannot reassign asset custody to divisions."""
    token = get_token(ACTIVE_USER_WALLET, "USER", ACTIVE_USER_VERSION)
    response = await client.post(
        "/api/assets/serial/BEL-RADAR-001/assign",
        headers={"Authorization": f"Bearer {token}"},
        json={"custodian_did": "did:ethr:13371:0x999", "custodian_department": "Radar Dept"}
    )
    assert response.status_code == 403
    assert "is not authorized to reassign asset custody" in response.json()["detail"]


@pytest.mark.asyncio
async def test_admin_can_reassign_custody(client, db_session):
    """ADMIN role is authorized to reassign custody of a registered asset."""
    from unittest.mock import patch
    import uuid as _uuid
    from sqlalchemy import select as _select
    from app.models.domain import Asset, User as _User
    token = get_token(ACTIVE_ADMIN_WALLET, "ADMIN", ACTIVE_ADMIN_VERSION)
    owner = (await db_session.execute(_select(_User).where(_User.wallet_address == ACTIVE_ADMIN_WALLET))).scalar_one()
    serial = f"BEL-RADAR-{_uuid.uuid4().hex[:6]}"
    db_session.add(Asset(token_id=_uuid.uuid4().int % 2_000_000_000, serial_number=serial, owner_id=owner.id, is_physical=True))
    await db_session.commit()

    with patch("app.api.assets.contract_service.get_token_by_serial", return_value=1):
        response = await client.post(
            f"/api/assets/serial/{serial}/assign",
            headers={"Authorization": f"Bearer {token}"},
            json={"custodian_did": "did:ethr:13371:0x95ea9708bcf136d710a4b8e76fe20f895eca003a", "custodian_department": "BEL Tactical Radar Div"}
        )
    assert response.status_code == 200
    assert response.json()["serial_number"] == serial
    assert response.json()["custodian_department"] == "BEL Tactical Radar Div"


# ==============================================================================
# 5. Off-chain Document Upload & Hash Verification
# ==============================================================================

@pytest.mark.asyncio
async def test_document_upload_and_sha256_hashing(client):
    """Authenticated users can securely upload documents and receive SHA-256 hash."""
    token = get_token(ACTIVE_USER_WALLET, "USER", ACTIVE_USER_VERSION)
    test_content = b"%PDF-1.4\n% DEFENSE-SPEC-CLASSIFIED-DOCUMENT-CONTENT-2026\n%%EOF\n"  # real PDF signature
    files = {"file": ("classified_spec.pdf", io.BytesIO(test_content), "application/pdf")}

    response = await client.post(
        "/api/assets/upload-document",
        headers={"Authorization": f"Bearer {token}"},
        files=files
    )
    assert response.status_code == 200
    data = response.json()
    assert "file_hash" in data
    assert "offchain_uri" in data
    assert len(data["file_hash"]) == 64  # Valid SHA-256 length
    import hashlib
    assert data["file_hash"] == hashlib.sha256(test_content).hexdigest()  # server-computed


# ==============================================================================
# 6. IDOR & Unauthorized Download Defense
# ==============================================================================

@pytest.mark.asyncio
async def test_unauthorized_document_download_blocked(client):
    """Direct vault downloads (bypassing request/approval/Factor 3/watermark) are disabled."""
    token = get_token(ACTIVE_USER_WALLET, "USER", ACTIVE_USER_VERSION)
    response = await client.get(
        "/api/assets/document/download/test_doc.pdf?token_id=9999",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 410
    anon = await client.get("/api/assets/document/download-token/dlt_anything")
    assert anon.status_code == 410  # URL-token downloads without a session are disabled too


# ==============================================================================
# 7. Audit Logging & Anomaly Endpoints
# ==============================================================================

@pytest.mark.asyncio
async def test_audit_stats_endpoint(client):
    """Audit summary requires a session and a non-USER role."""
    assert (await client.get("/api/audit/stats")).status_code == 401
    user = get_token("0xe1ced2305c7c75618eeb1450e18e2099c15b7d72", "USER", 1)
    assert (await client.get("/api/audit/stats", headers={"Authorization": f"Bearer {user}"})).status_code == 403
    auditor = get_token("0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "AUDITOR", 1)
    response = await client.get("/api/audit/stats", headers={"Authorization": f"Bearer {auditor}"})
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "latest_risk" in data


@pytest.mark.asyncio
async def test_audit_events_list(client):
    """Audit events require a session; results are scoped by role."""
    assert (await client.get("/api/audit/events?limit=5")).status_code == 401
    auditor = get_token("0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "AUDITOR", 1)
    response = await client.get("/api/audit/events?limit=5", headers={"Authorization": f"Bearer {auditor}"})
    assert response.status_code == 200
    assert isinstance(response.json(), list)

# 6. Production security constraints: moved to tests/test_secret_config.py (stricter).

# ==============================================================================
# 7. DID Migration & Auto-Repair (Phase 12)
# ==============================================================================
import uuid
from app.services.auth import report_legacy_dids
from app.models.domain import User

@pytest.mark.asyncio
async def test_legacy_dids_reported_not_rewritten(db_session):
    """Spec section 50: legacy/non-compliant DIDs are detected and reported, but
    historical identifiers are never silently rewritten."""
    legacy_wa = f"0x{uuid.uuid4().hex[:40]}"
    legacy_user = User(wallet_address=legacy_wa, role="USER", did=None)
    legacy_wa2 = f"0x{uuid.uuid4().hex[:40]}"
    legacy_user2 = User(wallet_address=legacy_wa2, role="USER", did=f"did:ethr:31337:{legacy_wa2}")
    db_session.add_all([legacy_user, legacy_user2])
    await db_session.commit()

    assert await report_legacy_dids(db_session) >= 2

    await db_session.refresh(legacy_user)
    await db_session.refresh(legacy_user2)
    assert legacy_user.did is None
    assert legacy_user2.did == f"did:ethr:31337:{legacy_wa2}"

    await db_session.delete(legacy_user)
    await db_session.delete(legacy_user2)
    await db_session.commit()
