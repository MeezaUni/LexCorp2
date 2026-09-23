"""Test suite for Phase 4: Digital Document Approval & Creation Workflow (CRT-)."""

import pytest
import pyotp
import uuid
from unittest.mock import patch
from app.services.auth import create_jwt
from app.models.domain import User
from sqlalchemy import select

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower()
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower()
USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower()

def get_token(wallet: str, role: str, session_version: int = 1) -> str:
    did = f"did:ethr:13371:{wallet}"
    return create_jwt(wallet, did, role, session_version, client_ip="testclient")


@pytest.mark.asyncio
async def test_propose_document_success(client, db_session):
    """User can propose a digital document within their assigned department."""
    token = get_token(USER_WALLET, "USER", 1)
    serial = f"BEL-DOC-AVIONICS-{uuid.uuid4().hex[:6].upper()}"

    payload = {
        "name": "Radar Guidance Protocol Doc",
        "serial_number": serial,
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "offchain_uri": "secure-vault://documents/guidance.pdf",
        "purpose": "Avionics System Architecture Verification"
    }

    response = await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {token}"},
        json=payload
    )
    assert response.status_code == 200
    data = response.json()
    assert data["action_type"] == "CREATION"
    assert data["action_id"].startswith("CRT-")
    assert data["status"] == "PENDING"
    assert data["asset_serial"] == serial


@pytest.mark.asyncio
async def test_propose_document_department_violation(client):
    """USER cannot propose documents for departments other than their own."""
    token = get_token(USER_WALLET, "USER", 1)

    payload = {
        "name": "Cross Department Exploit Attempt",
        "serial_number": f"BEL-DOC-CYBER-{uuid.uuid4().hex[:6].upper()}",
        "file_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        "offchain_uri": "secure-vault://documents/cyber_doc.pdf",
        "department": "Cyber Warfare"  # User is in Avionics
    }

    response = await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {token}"},
        json=payload
    )
    assert response.status_code == 403
    assert "Users can only propose documents for their assigned department" in response.json()["detail"]


@pytest.mark.asyncio
async def test_propose_document_duplicate_serial(client):
    """Attempting to propose an asset with an already existing serial number is rejected."""
    token = get_token(USER_WALLET, "USER", 1)

    # First, create one
    serial = f"BEL-DOC-AVIONICS-{uuid.uuid4().hex[:6].upper()}"
    payload1 = {
        "name": "Original Tracker Spec",
        "serial_number": serial,
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "offchain_uri": "secure-vault://documents/guidance.pdf"
    }
    res1 = await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {token}"},
        json=payload1
    )
    assert res1.status_code == 200

    # Then attempt to create a duplicate
    payload2 = {
        "name": "Duplicate Tracker Spec",
        "serial_number": serial,
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "offchain_uri": "secure-vault://documents/guidance2.pdf"
    }

    response = await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {token}"},
        json=payload2
    )
    assert response.status_code == 400
    assert "Asset serial number already exists" in response.json()["detail"]


@pytest.mark.asyncio
async def test_pending_queue_department_scoping(client, db_session):
    """Pending queue is appropriately scoped by role and department."""

    # Propose a fresh doc so there's definitely a pending item
    token = get_token(USER_WALLET, "USER", 1)
    await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Pending Queue Scope Test Doc",
            "serial_number": f"BEL-DOC-AVIONICS-{uuid.uuid4().hex[:6].upper()}",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "offchain_uri": "secure-vault://documents/guidance.pdf"
        }
    )

    # 1. Check as USER - only sees their own
    res_user = await client.get("/api/assets/document/pending", headers={"Authorization": f"Bearer {token}"})
    assert res_user.status_code == 200
    user_items = res_user.json()
    assert len(user_items) >= 1
    assert all(item["actor_did"].endswith(USER_WALLET) for item in user_items)

    # 2. Check as MANAGER in Avionics - sees Avionics items
    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
    res_mgr = await client.get("/api/assets/document/pending", headers={"Authorization": f"Bearer {mgr_token}"})
    assert res_mgr.status_code == 200
    mgr_items = res_mgr.json()
    assert len(mgr_items) >= 1

    # 3. Check as ADMIN - sees all pending items
    admin_token = get_token(ADMIN_WALLET, "ADMIN", 5)
    res_admin = await client.get("/api/assets/document/pending", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200
    admin_items = res_admin.json()
    assert len(admin_items) >= len(mgr_items)


@pytest.mark.asyncio
async def test_user_cannot_approve_document(client):
    """Standard USER role is forbidden from approving documents."""
    token = get_token(USER_WALLET, "USER", 1)

    # Propose a fresh doc
    await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Approval scope fail doc",
            "serial_number": f"BEL-DOC-AVIONICS-{uuid.uuid4().hex[:6].upper()}",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "offchain_uri": "secure-vault://documents/guidance.pdf"
        }
    )

    # Get a pending action ID
    res = await client.get("/api/assets/document/pending", headers={"Authorization": f"Bearer {token}"})
    pending_list = res.json()
    assert len(pending_list) > 0
    action_id = pending_list[0]["action_id"]

    response = await client.post(
        f"/api/assets/document/approval/{action_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"decision": "APPROVE"}
    )
    assert response.status_code == 403
    assert "Only Managers and Admins can approve documents" in response.json()["detail"]


@pytest.mark.asyncio
async def test_approval_factor3_totp_enforcement(client, db_session):
    """Managers with Factor 3 enabled must provide valid TOTP token for approval."""
    # Propose a doc so we know there's one pending
    user_token = get_token(USER_WALLET, "USER", 1)
    await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "name": "MFA Test Document",
            "serial_number": f"BEL-DOC-MFA-{uuid.uuid4().hex[:6].upper()}",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "offchain_uri": "secure-vault://documents/guidance.pdf"
        }
    )

    # Enable Factor 3 on Manager
    res = await db_session.execute(select(User).where(User.wallet_address == MANAGER_WALLET))
    mgr_user = res.scalar_one()
    secret = pyotp.random_base32()
    mgr_user.totp_factor3_secret = secret
    mgr_user.is_totp_factor3_enabled = True
    await db_session.commit()

    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
    res_pending = await client.get("/api/assets/document/pending", headers={"Authorization": f"Bearer {mgr_token}"})
    pending_list = res_pending.json()
    action_id = pending_list[0]["action_id"]

    # Try approve without TOTP or wrong TOTP
    res_fail = await client.post(
        f"/api/assets/document/approval/{action_id}",
        headers={"Authorization": f"Bearer {mgr_token}"},
        json={"decision": "APPROVE", "totp_code": "000000"}
    )
    assert res_fail.status_code == 401
    assert "Invalid Factor 3 TOTP code" in res_fail.json()["detail"]

    # Approve with valid TOTP code
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x123", "data": "0xabc"}):
        res_success = await client.post(
            f"/api/assets/document/approval/{action_id}",
            headers={"Authorization": f"Bearer {mgr_token}"},
            json={"decision": "APPROVE", "totp_code": valid_code}
        )
    assert res_success.status_code == 200
    data = res_success.json()
    assert data["decision"] == "APPROVE"
    assert data["status"] == "APPROVED"
    assert "calldata" in data
    assert data["calldata"] is not None
    assert "data" in data["calldata"]
    assert "to" in data["calldata"]

    # Reset Factor 3 for cleanliness
    mgr_user.is_totp_factor3_enabled = False
    await db_session.commit()


@pytest.mark.asyncio
async def test_rejection_workflow(client, db_session):
    """Manager or Admin can reject a proposed document with reason."""
    # First propose a new document
    user_token = get_token(USER_WALLET, "USER", 1)
    prop_res = await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "name": "Defective Spec Document",
            "serial_number": f"BEL-DOC-REJECT-{uuid.uuid4().hex[:6].upper()}",
            "file_hash": "1111111111111111111111111111111111111111111111111111111111111111",
            "offchain_uri": "secure-vault://documents/defective.pdf",
            "purpose": "Needs review"
        }
    )
    assert prop_res.status_code == 200
    action_id = prop_res.json()["action_id"]

    # Reject via Admin
    admin_token = get_token(ADMIN_WALLET, "ADMIN", 5)
    reject_res = await client.post(
        f"/api/assets/document/approval/{action_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "decision": "REJECT",
            "rejection_reason": "Incomplete technical specifications and unverified hash integrity."
        }
    )
    assert reject_res.status_code == 200
    data = reject_res.json()
    assert data["decision"] == "REJECT"
    assert data["status"] == "REJECTED"
