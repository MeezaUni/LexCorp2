"""Test suite for Phase 9: Physical Asset Registration & Global Uniqueness Auditing."""

import pytest
import uuid
import random
from unittest.mock import patch
from app.services.auth import create_jwt
from app.models.domain import Asset, User, AuditEvent
from sqlalchemy import select

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower()
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower()
USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower()
AUDITOR_WALLET = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".lower()

def get_token(wallet: str, role: str, session_version: int = 1) -> str:
    did = f"did:ethr:13371:{wallet}"
    return create_jwt(wallet, did, role, session_version, client_ip="testclient")


@pytest.mark.asyncio
async def test_propose_physical_asset_success(client, db_session):
    """Manager can propose physical defense hardware within their department."""
    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
    serial = f"BEL-HW-RADAR-{uuid.uuid4().hex[:6].upper()}"
    mac = f"00:1A:2B:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}"
    dev_addr = f"DEV-ADDR-{uuid.uuid4().hex[:8].upper()}"

    payload = {
        "name": "Radar Transmitter Unit Mk-IV",
        "serial_number": serial,
        "asset_type": "EQUIPMENT",
        "mac_address": mac,
        "device_unique_address": dev_addr,
        "location": "Hangar 4, Bay C",
        "purpose": "Avionics Hardware Deployment"
    }

    response = await client.post(
        "/api/assets/physical/propose",
        headers={"Authorization": f"Bearer {mgr_token}"},
        json=payload
    )
    assert response.status_code == 200
    data = response.json()
    assert data["action_type"] == "CREATION"
    assert data["action_id"].startswith("CRT-")
    assert data["status"] == "PENDING"
    assert data["asset_serial"] == serial


@pytest.mark.asyncio
async def test_user_cannot_propose_physical_asset(client):
    """Standard USER role is forbidden from proposing physical hardware."""
    user_token = get_token(USER_WALLET, "USER", 1)
    payload = {
        "name": "Unauthorized Hardware Propose",
        "serial_number": f"BEL-HW-{uuid.uuid4().hex[:6].upper()}",
        "asset_type": "EQUIPMENT",
        "location": "Bay 1"
    }
    response = await client.post(
        "/api/assets/physical/propose",
        headers={"Authorization": f"Bearer {user_token}"},
        json=payload
    )
    assert response.status_code == 403
    assert "Only Managers and Administrators can propose physical assets" in response.json()["detail"]


@pytest.mark.asyncio
async def test_auditor_cannot_propose_physical_asset(client):
    """AUDITOR role is forbidden from proposing physical assets."""
    auditor_token = get_token(AUDITOR_WALLET, "AUDITOR", 1)
    payload = {
        "name": "Auditor Hardware Propose",
        "serial_number": f"BEL-HW-{uuid.uuid4().hex[:6].upper()}",
        "asset_type": "EQUIPMENT"
    }
    response = await client.post(
        "/api/assets/physical/propose",
        headers={"Authorization": f"Bearer {auditor_token}"},
        json=payload
    )
    assert response.status_code == 403
    assert "Auditors cannot propose assets" in response.json()["detail"]


@pytest.mark.asyncio
async def test_manager_cross_department_physical_proposal_rejected(client):
    """MANAGER cannot propose physical assets outside their assigned department."""
    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)  # Avionics manager
    payload = {
        "name": "Cross Department Hardware",
        "serial_number": f"BEL-HW-CYBER-{uuid.uuid4().hex[:6].upper()}",
        "asset_type": "EQUIPMENT",
        "department": "Cyber Warfare"
    }
    response = await client.post(
        "/api/assets/physical/propose",
        headers={"Authorization": f"Bearer {mgr_token}"},
        json=payload
    )
    assert response.status_code == 403
    assert "Managers can only propose physical assets for their assigned department" in response.json()["detail"]


@pytest.mark.asyncio
async def test_duplicate_mac_address_attempt_audited(client, db_session):
    """Proposing physical asset with existing MAC address generates high-risk AuditEvent and 409."""
    res = await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))
    admin_user = res.scalar_one()

    # Create existing physical asset with a known MAC
    dup_mac = f"AA:BB:CC:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}"
    existing_asset = Asset(
        token_id=random.randint(1000000, 9999999),
        serial_number=f"BEL-HW-EXISTING-{uuid.uuid4().hex[:6].upper()}",
        name="Existing Sensor Unit",
        asset_type="EQUIPMENT",
        is_physical=True,
        mac_address=dup_mac,
        department="Avionics",
        lifecycle_status="ACTIVE",
        owner_id=admin_user.id
    )
    db_session.add(existing_asset)
    await db_session.commit()

    # Attempt to propose new asset with the same MAC address
    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
    serial_attempt = f"BEL-HW-CLONE-{uuid.uuid4().hex[:6].upper()}"
    payload = {
        "name": "Cloned MAC Asset",
        "serial_number": serial_attempt,
        "asset_type": "EQUIPMENT",
        "mac_address": dup_mac,
        "location": "Unknown"
    }

    response = await client.post(
        "/api/assets/physical/propose",
        headers={"Authorization": f"Bearer {mgr_token}"},
        json=payload
    )
    assert response.status_code == 400
    assert "MAC address is already registered" in response.json()["detail"]

    # Verify high-risk AuditEvent was recorded in DB
    audit_res = await db_session.execute(
        select(AuditEvent).where(
            AuditEvent.asset_serial == serial_attempt,
            AuditEvent.event_type == "DUPLICATE_PHYSICAL_ASSET_ATTEMPT"
        )
    )
    audit_event = audit_res.scalar_one_or_none()
    assert audit_event is not None
    assert audit_event.risk_score == 0.85
    assert audit_event.risk_label == "HIGH"
    assert audit_event.risk_factors["mac_address"] == dup_mac


@pytest.mark.asyncio
async def test_duplicate_device_unique_address_attempt_audited(client, db_session):
    """Proposing physical asset with duplicate device unique address generates high-risk AuditEvent and 409."""
    res = await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))
    admin_user = res.scalar_one()

    # Create existing physical asset with a known device address
    dup_dev = f"SECURE-CHIP-ID-{uuid.uuid4().hex[:8].upper()}"
    existing_asset = Asset(
        token_id=random.randint(1000000, 9999999),
        serial_number=f"BEL-HW-EXISTING-{uuid.uuid4().hex[:6].upper()}",
        name="Existing Crypto Chip",
        asset_type="EQUIPMENT",
        is_physical=True,
        device_unique_address=dup_dev,
        department="Avionics",
        lifecycle_status="ACTIVE",
        owner_id=admin_user.id
    )
    db_session.add(existing_asset)
    await db_session.commit()

    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
    serial_attempt = f"BEL-HW-CLONE-DEV-{uuid.uuid4().hex[:6].upper()}"
    payload = {
        "name": "Cloned Device Unique Address Asset",
        "serial_number": serial_attempt,
        "asset_type": "EQUIPMENT",
        "device_unique_address": dup_dev,
        "location": "Unknown"
    }

    response = await client.post(
        "/api/assets/physical/propose",
        headers={"Authorization": f"Bearer {mgr_token}"},
        json=payload
    )
    assert response.status_code == 400
    assert "Device unique address is already registered" in response.json()["detail"]

    # Verify AuditEvent
    audit_res = await db_session.execute(
        select(AuditEvent).where(
            AuditEvent.asset_serial == serial_attempt,
            AuditEvent.event_type == "DUPLICATE_PHYSICAL_ASSET_ATTEMPT"
        )
    )
    audit_event = audit_res.scalar_one_or_none()
    assert audit_event is not None
    assert audit_event.risk_score == 0.85
    assert audit_event.risk_label == "HIGH"
    assert audit_event.risk_factors["device_unique_address"] == dup_dev


@pytest.mark.asyncio
async def test_physical_pending_queue_scoping(client, db_session):
    """Physical pending queue is correctly scoped for managers and admins."""
    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
    serial = f"BEL-HW-PENDING-{uuid.uuid4().hex[:6].upper()}"
    await client.post(
        "/api/assets/physical/propose",
        headers={"Authorization": f"Bearer {mgr_token}"},
        json={
            "name": "Pending Hardware Test",
            "serial_number": serial,
            "asset_type": "EQUIPMENT"
        }
    )

    # Check Manager sees it
    res_mgr = await client.get("/api/assets/physical/pending", headers={"Authorization": f"Bearer {mgr_token}"})
    assert res_mgr.status_code == 200
    mgr_items = res_mgr.json()
    assert any(item["asset_serial"] == serial for item in mgr_items)

    # Check Admin sees it
    admin_token = get_token(ADMIN_WALLET, "ADMIN", 5)
    res_admin = await client.get("/api/assets/physical/pending", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200
    admin_items = res_admin.json()
    assert any(item["asset_serial"] == serial for item in admin_items)


@pytest.mark.asyncio
async def test_physical_asset_approval_calldata(client, db_session):
    """Approving physical asset proposal prepares physical mint calldata."""
    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
    serial = f"BEL-HW-APPROVE-{uuid.uuid4().hex[:6].upper()}"
    prop_res = await client.post(
        "/api/assets/physical/propose",
        headers={"Authorization": f"Bearer {mgr_token}"},
        json={
            "name": "Flight Computer Alpha",
            "serial_number": serial,
            "asset_type": "EQUIPMENT",
            "location": "Avionics Lab"
        }
    )
    assert prop_res.status_code == 200
    action_id = prop_res.json()["action_id"]

    # Admin approves
    admin_token = get_token(ADMIN_WALLET, "ADMIN", 5)
    with patch("app.services.contract.contract_service.prepare_mint_calldata", return_value={"to": "0xContract", "data": "0xPhysicalMintData"}):
        res_approve = await client.post(
            f"/api/assets/physical/approval/{action_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"decision": "APPROVE"}
        )
    assert res_approve.status_code == 200
    data = res_approve.json()
    assert data["decision"] == "APPROVE"
    assert data["status"] == "APPROVED"
    assert data["calldata"]["data"] == "0xPhysicalMintData"

@pytest.mark.asyncio
async def test_duplicate_serial_number_attempt_audited(client, db_session):
    """Proposing physical asset with duplicate serial number generates high-risk AuditEvent and 400."""
    res = await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))
    admin_user = res.scalar_one()

    # Create existing physical asset with a known serial
    dup_serial = f"BEL-HW-DUP-SERIAL-{uuid.uuid4().hex[:6].upper()}"
    existing_asset = Asset(
        token_id=random.randint(1000000, 9999999),
        serial_number=dup_serial,
        name="Existing Sensor Unit By Serial",
        asset_type="EQUIPMENT",
        is_physical=True,
        department="Avionics",
        lifecycle_status="ACTIVE",
        owner_id=admin_user.id
    )
    db_session.add(existing_asset)
    await db_session.commit()

    # Attempt to propose new asset with the same Serial Number
    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
    payload = {
        "name": "Cloned Serial Asset",
        "serial_number": dup_serial,
        "asset_type": "EQUIPMENT",
        "location": "Unknown"
    }

    response = await client.post(
        "/api/assets/physical/propose",
        headers={"Authorization": f"Bearer {mgr_token}"},
        json=payload
    )
    assert response.status_code == 400
    assert "Asset serial number already exists" in response.json()["detail"]

    # Verify high-risk AuditEvent was recorded in DB
    audit_res = await db_session.execute(
        select(AuditEvent).where(
            AuditEvent.asset_serial == dup_serial,
            AuditEvent.event_type == "DUPLICATE_PHYSICAL_ASSET_ATTEMPT"
        )
    )
    audit_event = audit_res.scalar_one_or_none()
    assert audit_event is not None
    assert audit_event.risk_score == 0.85
    assert audit_event.risk_label == "HIGH"
    assert audit_event.risk_factors["serial_number"] == dup_serial

