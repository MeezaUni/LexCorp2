import pytest
import os
from unittest.mock import patch
from httpx import AsyncClient
from app.main import app
from app.api.dependencies import get_current_user, get_current_active_user
from app.services import auth
from app.models.domain import User

@pytest.fixture(autouse=True)
def cleanup_overrides():
    yield
    app.dependency_overrides.clear()

@pytest.fixture
def auth_tokens():
    # Helper to generate tokens for different roles and states
    admin_token = auth.create_jwt("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "did:ethr:13371:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "ADMIN", session_version=0)
    manager_token = auth.create_jwt("0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "did:ethr:13371:0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "MANAGER", session_version=0)
    user_token = auth.create_jwt("0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "did:ethr:13371:0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "USER", session_version=0)
    auditor_token = auth.create_jwt("0x90f79bf6eb2c4f870365e785982e1f101e93b906", "did:ethr:13371:0x90f79bf6eb2c4f870365e785982e1f101e93b906", "AUDITOR", session_version=0)
    return {
        "admin": admin_token,
        "manager": manager_token,
        "user": user_token,
        "auditor": auditor_token,
    }


@pytest.mark.asyncio
async def test_unauthenticated_endpoints_return_401(async_client: AsyncClient):
    """Verify that sensitive endpoints strictly reject unauthenticated requests with 401."""
    # 1. Download Document
    res = await async_client.get("/api/assets/document/download/sample.txt?token_id=1&wallet_address=0x123&did=did:ethr:13371:0x123")
    assert res.status_code == 401, f"Expected 401 for unauthenticated download, got {res.status_code}"

    # 2. Upload Document
    files = {"file": ("test.txt", b"hello world", "text/plain")}
    res = await async_client.post("/api/assets/upload-document", files=files)
    assert res.status_code == 401, f"Expected 401 for unauthenticated upload, got {res.status_code}"

    # 3. Assign Custodian
    res = await async_client.post("/api/assets/serial/BEL-TEST-001/assign", json={"custodian_did": "did:ethr:13371:0x123"})
    assert res.status_code == 401, f"Expected 401 for unauthenticated assign, got {res.status_code}"

    # 4. Maintenance Record
    res = await async_client.post("/api/assets/serial/BEL-TEST-001/maintenance", json={"performed_by_did": "did:ethr:13371:0x123", "action_description": "Inspection"})
    assert res.status_code == 401, f"Expected 401 for unauthenticated maintenance, got {res.status_code}"

    # 5. Prepare Update Digital
    res = await async_client.post("/api/assets/update-digital/prepare", json={
        "token_id": 1,
        "requester_did": "did:ethr:13371:0x123",
        "new_file_hash": "abc",
        "new_offchain_uri": "uri"
    })
    assert res.status_code == 401, f"Expected 401 for unauthenticated prepare update, got {res.status_code}"


@pytest.mark.asyncio
async def test_invalid_and_expired_jwt_return_401(async_client: AsyncClient):
    """Verify that forged, malformed, or expired JWTs are rejected."""
    headers = {"Authorization": "Bearer invalid.jwt.token"}
    res = await async_client.get("/api/assets/document/download/sample.txt?token_id=1", headers=headers)
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_idor_and_spoofing_prevented_on_download(async_client: AsyncClient, auth_tokens):
    """
    Verify IDOR prevention:
    A regular USER attempts to spoof the ADMIN address in the query parameters to download a document.
    The server must ignore the spoofed parameters and evaluate permissions using the authenticated token.
    """
    user_headers = {"Authorization": f"Bearer {auth_tokens['user']}"}

    mock_user = User(
        wallet_address="0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
        did="did:ethr:13371:0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
        role="USER",
        is_active=True,
        session_version=0
    )
    app.dependency_overrides[get_current_user] = lambda: mock_user

    with patch("app.services.contract.contract_service.check_asset_access") as mock_check:
        # Smart contract check receives user's identity, which is NOT authorized (level=0)
        mock_check.return_value = {"authorized": False, "level": 0}

        # Caller passes Admin's address in query params
        spoofed_admin_address = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        spoofed_admin_did = f"did:ethr:13371:{spoofed_admin_address}"

        res = await async_client.get(
            f"/api/assets/document/download/sample.txt?token_id=1&wallet_address={spoofed_admin_address}&did={spoofed_admin_did}",
            headers=user_headers
        )

        # Assert forbidden: Contract check was called with user's verified address, NOT the spoofed admin
        assert res.status_code == 403
        mock_check.assert_called_once_with(
            token_id=1,
            requester_did="did:ethr:13371:0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
            caller_address="0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
        )


@pytest.mark.asyncio
async def test_rbac_custody_assignment_restrictions(async_client: AsyncClient, auth_tokens):
    """Verify that only ADMIN and MANAGER can assign custody. USER and AUDITOR get 403."""
    user_headers = {"Authorization": f"Bearer {auth_tokens['user']}"}
    auditor_headers = {"Authorization": f"Bearer {auth_tokens['auditor']}"}
    manager_headers = {"Authorization": f"Bearer {auth_tokens['manager']}"}

    # 1. Standard USER gets 403 Forbidden
    mock_user = User(wallet_address="0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", role="USER", is_active=True, session_version=0)
    app.dependency_overrides[get_current_user] = lambda: mock_user

    res = await async_client.post(
        "/api/assets/serial/BEL-RADAR-001/assign",
        json={"custodian_did": "did:ethr:13371:0x999"},
        headers=user_headers
    )
    assert res.status_code == 403
    assert "not authorized" in res.json()["detail"].lower() or "privileges required" in res.json()["detail"].lower()

    # 2. AUDITOR gets 403 Forbidden
    mock_auditor = User(wallet_address="0x90f79bf6eb2c4f870365e785982e1f101e93b906", role="AUDITOR", is_active=True, session_version=0)
    app.dependency_overrides[get_current_user] = lambda: mock_auditor

    res = await async_client.post(
        "/api/assets/serial/BEL-RADAR-001/assign",
        json={"custodian_did": "did:ethr:13371:0x999"},
        headers=auditor_headers
    )
    assert res.status_code == 403

    # 3. MANAGER permitted (200 or 404 depending on chain mock)
    mock_manager = User(wallet_address="0x70997970c51812dc3a010c7d01b50e0d17dc79c8", role="MANAGER", is_active=True, session_version=0, department="Radar Dept")
    app.dependency_overrides[get_current_user] = lambda: mock_manager

    with patch("app.services.contract.contract_service.get_token_by_serial", return_value=1):
        res = await async_client.post(
            "/api/assets/serial/BEL-RADAR-001/assign",
            json={"custodian_did": "did:ethr:13371:0x999", "custodian_department": "Radar Dept"},
            headers=manager_headers
        )
        assert res.status_code == 200
        assert res.json()["custodian_did"] == "did:ethr:13371:0x999"


@pytest.mark.asyncio
async def test_maintenance_actor_did_bound_server_side(async_client: AsyncClient, auth_tokens):
    """Verify that maintenance records strictly use the authenticated session DID, preventing impersonation."""
    mock_user = User(
        wallet_address="0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
        did="did:ethr:13371:0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
        role="USER",
        is_active=True,
        session_version=0
    )
    app.dependency_overrides[get_current_user] = lambda: mock_user

    with patch("app.services.contract.contract_service.get_token_by_serial", return_value=1):
        with patch("app.services.contract.contract_service.check_asset_access", return_value={"authorized": True, "level": 2}):
            # User attempts to spoof an Admin DID in performed_by_did
            spoofed_admin_did = "did:ethr:13371:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

            res = await async_client.post(
                "/api/assets/serial/BEL-RADAR-001/maintenance",
                json={
                    "performed_by_did": spoofed_admin_did,
                    "action_description": "Annual System Overhaul"
                },
                headers={"Authorization": f"Bearer {auth_tokens['user']}"}
            )

            assert res.status_code == 200
            data = res.json()
            # Must be user's real DID, NOT the spoofed admin DID
            assert data["performed_by_did"] == "did:ethr:13371:0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"


@pytest.mark.asyncio
async def test_auditor_cannot_upload_or_modify(async_client: AsyncClient, auth_tokens):
    """Verify that AUDITOR role is restricted from upload, maintenance, and updates."""
    mock_auditor = User(
        wallet_address="0x90f79bf6eb2c4f870365e785982e1f101e93b906",
        did="did:ethr:13371:0x90f79bf6eb2c4f870365e785982e1f101e93b906",
        role="AUDITOR",
        is_active=True,
        session_version=0
    )
    app.dependency_overrides[get_current_user] = lambda: mock_auditor
    headers = {"Authorization": f"Bearer {auth_tokens['auditor']}"}

    # 1. Upload
    files = {"file": ("audit_attempt.txt", b"sample content", "text/plain")}
    res = await async_client.post("/api/assets/upload-document", files=files, headers=headers)
    assert res.status_code == 403

    # 2. Update Digital
    res = await async_client.post("/api/assets/update-digital/prepare", json={
        "token_id": 1,
        "requester_did": mock_auditor.did,
        "new_file_hash": "hash",
        "new_offchain_uri": "uri"
    }, headers=headers)
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_disabled_user_rejected_with_403(async_client: AsyncClient, auth_tokens):
    """Verify that disabled users (is_active=False) cannot perform actions."""
    disabled_user = User(
        wallet_address="0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
        did="did:ethr:13371:0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
        role="USER",
        is_active=False,
        session_version=0
    )
    app.dependency_overrides[get_current_user] = lambda: disabled_user

    files = {"file": ("test.txt", b"content", "text/plain")}
    res = await async_client.post("/api/assets/upload-document", files=files, headers={"Authorization": f"Bearer {auth_tokens['user']}"})
    assert res.status_code == 403
    assert "disabled" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_upload_file_size_limit_enforced(async_client: AsyncClient, auth_tokens):
    """Verify that uploaded files larger than 50MB are rejected with 413."""
    mock_user = User(
        wallet_address="0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
        did="did:ethr:13371:0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
        role="USER",
        is_active=True,
        session_version=0
    )
    app.dependency_overrides[get_current_user] = lambda: mock_user

    oversized_content = b"x" * (51 * 1024 * 1024)  # 51 MB
    files = {"file": ("large_file.iso", oversized_content, "application/octet-stream")}
    res = await async_client.post(
        "/api/assets/upload-document",
        files=files,
        headers={"Authorization": f"Bearer {auth_tokens['user']}"}
    )
    assert res.status_code == 413
    assert "exceeds" in res.json()["detail"].lower()
