"""Test suite for Phase 5: Digital Document Viewing, Dynamic Watermarking, & View Logging (VW-)."""

import pytest
from tests.conftest import mfa_headers
import uuid
import os
from PIL import Image
import io
from unittest.mock import patch
from app.services.auth import create_jwt
from app.models.domain import DocumentAction

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower()
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower()
USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower()

def get_token(wallet: str, role: str, session_version: int = 1) -> str:
    did = f"did:ethr:13371:{wallet}"
    return create_jwt(wallet, did, role, session_version, client_ip="testclient")

@pytest.mark.asyncio
async def test_view_digital_document_success(client, db_session):
    """Authorized user can securely view a document, applying watermarks dynamically."""
    token = get_token(USER_WALLET, "USER", 1)

    # 1. Propose and approve a doc to view
    serial = f"BEL-DOC-VIEW-{uuid.uuid4().hex[:6].upper()}"
    prop_res = await client.post(
        "/api/assets/document/propose",
        headers=await mfa_headers(db_session, token, USER_WALLET, "document.submit"),
        json={
            "name": "Secret Specs",
            "serial_number": serial,
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "offchain_uri": "secure-vault://documents/view_test.png",
        "recipient_address": "0x123abc",
            "purpose": "Viewing Test"
        }
    )
    assert prop_res.status_code == 200
    action_id = prop_res.json()["action_id"]

    # Manager approves it
    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x123", "data": "0xabc"}):
        appr_res = await client.post(
            f"/api/assets/document/approval/{action_id}",
            headers=await mfa_headers(db_session, mgr_token, MANAGER_WALLET, "asset.approve"),
            json={"decision": "APPROVE"}
        )
    assert appr_res.status_code == 200

    # Create dummy image in offchain_storage so the watermark can apply properly
    from app.api.assets import OFFCHAIN_STORAGE_DIR
    storage_dir = os.path.join(OFFCHAIN_STORAGE_DIR, "documents")
    os.makedirs(storage_dir, exist_ok=True)
    img_path = os.path.join(storage_dir, "view_test.png")
    img = Image.new('RGB', (800, 600), color=(255, 255, 255))
    img.save(img_path, format='PNG')

    # View Document
    view_res = await client.get(
        f"/api/assets/document/view/{action_id}",
        headers=await mfa_headers(db_session, token, USER_WALLET, "document.view")
    )
    assert view_res.status_code == 200
    assert view_res.headers["content-type"] == "application/octet-stream"

    # Can we open the returned bytes as an image?
    returned_img = Image.open(io.BytesIO(view_res.content))
    assert returned_img.format == "PNG"

@pytest.mark.asyncio
async def test_view_digital_document_unauthorized(client, db_session):
    """Users cannot view documents proposed by others."""
    # User 1 proposes doc
    token1 = get_token(USER_WALLET, "USER", 1)
    serial = f"BEL-DOC-VIEW-UNAUTH-{uuid.uuid4().hex[:6].upper()}"
    prop_res = await client.post(
        "/api/assets/document/propose",
        headers=await mfa_headers(db_session, token1, USER_WALLET, "document.submit"),
        json={
            "name": "Classified Doc",
            "serial_number": serial,
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "offchain_uri": "secure-vault://documents/view_test_2.png",
        "recipient_address": "0x123abc",
        }
    )
    assert prop_res.status_code == 200
    action_id = prop_res.json()["action_id"]

    # User 2 tries to view it
    another_wallet = "0xababcf51335fa22e7967a9e72c16f738ddc7b5df"
    token2 = get_token(another_wallet, "USER", 1)

    view_res = await client.get(
        f"/api/assets/document/view/{action_id}",
        headers={"Authorization": f"Bearer {token2}"}
    )
    assert view_res.status_code in [401, 403, 404]

@pytest.mark.asyncio
async def test_view_audit_logs(client, db_session):
    """Viewing a document correctly generates VW- audit logs."""
    token = get_token(USER_WALLET, "USER", 1)
    serial = f"BEL-DOC-LOGS-{uuid.uuid4().hex[:6].upper()}"

    prop_res = await client.post(
        "/api/assets/document/propose",
        headers=await mfa_headers(db_session, token, USER_WALLET, "document.submit"),
        json={
            "name": "Log Tracking Doc",
            "serial_number": serial,
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "offchain_uri": "secure-vault://documents/view_test_3.png",
        "recipient_address": "0x123abc",
        }
    )
    assert prop_res.status_code == 200
    action_id = prop_res.json()["action_id"]

    # The document must exist in the (isolated test) vault; missing files are never faked.
    from app.api.assets import OFFCHAIN_STORAGE_DIR
    os.makedirs(os.path.join(OFFCHAIN_STORAGE_DIR, "documents"), exist_ok=True)
    Image.new("RGB", (400, 300), color=(255, 255, 255)).save(os.path.join(OFFCHAIN_STORAGE_DIR, "documents", "view_test_3.png"), format="PNG")

    # View it multiple times
    await client.get(f"/api/assets/document/view/{action_id}", headers=await mfa_headers(db_session, token, USER_WALLET, "document.view"))
    await client.get(f"/api/assets/document/view/{action_id}", headers=await mfa_headers(db_session, token, USER_WALLET, "document.view"))

    # Retrieve logs (as admin)
    admin_token = get_token(ADMIN_WALLET, "ADMIN", 5)
    logs_res = await client.get(
        f"/api/assets/document/logs/{serial}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert logs_res.status_code == 200
    logs = logs_res.json()
    assert len(logs) >= 2
    assert all(log["action_type"] == "VIEW" for log in logs)
    assert all(log["asset_serial"] == serial for log in logs)
    assert all(log["action_id"].startswith("VW-") for log in logs)
