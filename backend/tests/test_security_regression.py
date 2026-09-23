import pytest
import io
from datetime import datetime, timedelta, UTC
from jose import jwt
from app.services.auth import create_jwt
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
async def test_manager_can_mint_physical_assets(client):
    """MANAGER role is authorized to prepare physical defense hardware mints."""
    token = get_token(ACTIVE_MANAGER_WALLET, "MANAGER", ACTIVE_MANAGER_VERSION)
    response = await client.post(
        "/api/assets/mint/prepare",
        headers={"Authorization": f"Bearer {token}"},
        json={"to_address": "0x1234567890123456789012345678901234567890", "token_id": 999, "serial_number": "SEC-PHY-001", "owner_did": "did:ethr:13371:0x123"}
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
async def test_admin_can_reassign_custody(client):
    """ADMIN role is authorized to reassign asset custody."""
    from unittest.mock import patch
    token = get_token(ACTIVE_ADMIN_WALLET, "ADMIN", ACTIVE_ADMIN_VERSION)

    with patch("app.api.assets.contract_service.get_token_by_serial", return_value=1):
        response = await client.post(
            "/api/assets/serial/BEL-RADAR-001/assign",
            headers={"Authorization": f"Bearer {token}"},
            json={"custodian_did": "did:ethr:13371:0x95ea9708bcf136d710a4b8e76fe20f895eca003a", "custodian_department": "BEL Tactical Radar Div"}
        )
    assert response.status_code == 200
    assert response.json()["serial_number"] == "BEL-RADAR-001"
    assert response.json()["custodian_department"] == "BEL Tactical Radar Div"


# ==============================================================================
# 5. Off-chain Document Upload & Hash Verification
# ==============================================================================

@pytest.mark.asyncio
async def test_document_upload_and_sha256_hashing(client):
    """Authenticated users can securely upload documents and receive SHA-256 hash."""
    token = get_token(ACTIVE_USER_WALLET, "USER", ACTIVE_USER_VERSION)
    test_content = b"DEFENSE-SPEC-CLASSIFIED-DOCUMENT-CONTENT-2026"
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


# ==============================================================================
# 6. IDOR & Unauthorized Download Defense
# ==============================================================================

@pytest.mark.asyncio
async def test_unauthorized_document_download_blocked(client):
    """Unauthorized download attempts without smart-contract verification are rejected (403/404)."""
    token = get_token(ACTIVE_USER_WALLET, "USER", ACTIVE_USER_VERSION)
    response = await client.get(
        "/api/assets/document/download/test_doc.pdf?token_id=9999",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code in (403, 404)


# ==============================================================================
# 7. Audit Logging & Anomaly Endpoints
# ==============================================================================

@pytest.mark.asyncio
async def test_audit_stats_endpoint(client):
    """Audit summary endpoint returns valid aggregate statistics from PostgreSQL."""
    response = await client.get("/api/audit/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "latest_risk" in data


@pytest.mark.asyncio
async def test_audit_events_list(client):
    """Audit events list endpoint returns immutable trail data."""
    response = await client.get("/api/audit/events?limit=5")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

# ==============================================================================
# 6. Production Security Constraints (Phase 12)
# ==============================================================================
from app.core.config import Settings

@pytest.mark.asyncio
async def test_production_jwt_secret_validation():
    """In production, weak JWT_SECRET strings are rejected."""
    # Ensure a weak secret throws ValueError when DEBUG=False
    with pytest.raises(ValueError, match="In production, JWT_SECRET must be set to a secure value"):
        Settings(DEBUG=False, JWT_SECRET="weak", CORS_ORIGINS=["http://localhost:5173"], WEBAUTHN_ORIGINS=["https://localhost"])

@pytest.mark.asyncio
async def test_production_cors_wildcard_validation():
    """In production, wildcard '*' CORS origin is rejected."""
    with pytest.raises(ValueError, match=r"Wildcard '\*' is not allowed in CORS_ORIGINS in production."):
        Settings(DEBUG=False, JWT_SECRET="x" * 32, CORS_ORIGINS=["*", "http://localhost"], WEBAUTHN_ORIGINS=["https://localhost"])

@pytest.mark.asyncio
async def test_production_webauthn_insecure_validation():
    """In production, insecure HTTP WebAuthn origins (except localhost) are rejected."""
    with pytest.raises(ValueError, match="Insecure origin http://malicious.com not allowed for WebAuthn in production. Use HTTPS."):
        Settings(DEBUG=False, JWT_SECRET="x" * 32, CORS_ORIGINS=["https://test.com"], WEBAUTHN_ORIGINS=["https://test.com", "http://malicious.com"])

# ==============================================================================
# 7. DID Migration & Auto-Repair (Phase 12)
# ==============================================================================
import uuid
from app.services.auth import migrate_user_dids
from app.models.domain import User

@pytest.mark.asyncio
async def test_did_auto_migration_on_startup(db_session):
    """User without a DID or with a non-compliant DID is auto-repaired during migration."""
    # Create legacy user
    legacy_wa = f"0x{uuid.uuid4().hex[:40]}"
    legacy_user = User(
        wallet_address=legacy_wa,
        role="USER",
        did=None  # No DID
    )
    db_session.add(legacy_user)

    # Create another legacy user with wrong DID format
    legacy_wa2 = f"0x{uuid.uuid4().hex[:40]}"
    legacy_user2 = User(
        wallet_address=legacy_wa2,
        role="USER",
        did="did:ethr:wrongformat"
    )
    db_session.add(legacy_user2)
    await db_session.commit()

    # Run migration
    migrated_count = await migrate_user_dids(db_session)
    assert migrated_count >= 2

    # Verify repairs
    await db_session.refresh(legacy_user)
    await db_session.refresh(legacy_user2)

    expected_did1 = f"did:ethr:{settings.CHAIN_ID}:{legacy_wa.lower()}"
    assert legacy_user.did == expected_did1

    expected_did2 = f"did:ethr:{settings.CHAIN_ID}:{legacy_wa2.lower()}"
    assert legacy_user2.did == expected_did2


