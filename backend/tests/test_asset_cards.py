"""Test suite for Phase 10: Physical Asset QR/NFT Cards & Authenticated Verification Views."""

import pytest
import uuid
import random
from unittest.mock import patch, PropertyMock
from app.services.auth import create_jwt
from app.models.domain import Asset, User, MaintenanceRecord
from sqlalchemy import select

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower()
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower()
USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower()
AUDITOR_WALLET = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".lower()

def get_token(wallet: str, role: str, session_version: int = 1) -> str:
    did = f"did:ethr:13371:{wallet}"
    return create_jwt(wallet, did, role, session_version, client_ip="testclient")


@pytest.mark.asyncio
async def test_asset_certificate_svg_card_success(client, db_session):
    """Generate high-resolution printable SVG Defense Asset Certificate for registered asset."""
    res = await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))
    admin_user = res.scalar_one()

    serial = f"BEL-HW-RADAR-{uuid.uuid4().hex[:6].upper()}"
    token_id = random.randint(1000000, 9999999)
    mac = f"00:1A:2B:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}"
    dev_addr = f"DEV-ADDR-{uuid.uuid4().hex[:8].upper()}"

    asset = Asset(
        token_id=token_id,
        serial_number=serial,
        name="Tactical Radar Processing Unit",
        asset_type="EQUIPMENT",
        is_physical=True,
        mac_address=mac,
        device_unique_address=dev_addr,
        department="Avionics",
        lifecycle_status="ACTIVE",
        owner_id=admin_user.id
    )
    db_session.add(asset)
    await db_session.commit()

    with patch("app.services.contract.contract_service.get_token_by_serial", return_value=token_id), \
         patch("app.services.contract.contract_service.get_asset", return_value={
             "token_id": token_id,
             "serial_number": serial,
             "owner_did": f"did:ethr:13371:{ADMIN_WALLET}",
             "is_digital": False
         }):
        anon = await client.get(f"/api/assets/serial/{serial}/card")
        assert anon.status_code == 401
        response = await client.get(f"/api/assets/serial/{serial}/card", headers={"Authorization": f"Bearer {get_token(ADMIN_WALLET, 'ADMIN', 5)}"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    svg_text = response.text
    assert "<svg" in svg_text
    # Spec 35: ONLY Serial Number, NFT / Token ID, Creation Date, Department and a QR code
    assert serial in svg_text and f"#{token_id}" in svg_text and "Avionics" in svg_text
    assert "SERIAL NUMBER" in svg_text and "NFT / TOKEN ID" in svg_text and "CREATION DATE" in svg_text and "DEPARTMENT" in svg_text
    assert "data:image/png;base64," in svg_text  # Embedded QR Code
    import re as _re
    visible = _re.sub(r'data:image/png;base64,[^"]+', "", svg_text)  # ignore the QR image bytes
    for forbidden in (mac, dev_addr, "Tactical Radar Processing Unit", ADMIN_WALLET, "did:ethr", "CRT-", "0x"):
        assert forbidden not in visible, forbidden


@pytest.mark.asyncio
async def test_asset_certificate_svg_card_not_found(client):
    """Requesting SVG certificate for non-existent serial returns 404."""
    with patch("app.services.contract.contract_service.get_token_by_serial", return_value=None):
        response = await client.get("/api/assets/serial/NON-EXISTENT-SERIAL/card", headers={"Authorization": f"Bearer {get_token(ADMIN_WALLET, 'ADMIN', 5)}"})
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_serial_qr_code_generation(client, db_session):
    """QR code endpoint generates PNG image for a registered asset's verification URL."""
    serial = f"BEL-HW-OPTIC-{uuid.uuid4().hex[:6].upper()}"
    token_id = random.randint(1000000, 9999999)
    admin_user = (await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))).scalar_one()
    db_session.add(Asset(token_id=token_id, serial_number=serial, is_physical=True, department="Avionics", owner_id=admin_user.id))
    await db_session.commit()

    with patch("app.services.contract.contract_service.get_token_by_serial", return_value=token_id):
        assert (await client.get(f"/api/assets/serial/{serial}/qr")).status_code == 401
        response = await client.get(f"/api/assets/serial/{serial}/qr", headers={"Authorization": f"Bearer {get_token(ADMIN_WALLET, 'ADMIN', 5)}"})

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert len(response.content) > 0


@pytest.mark.asyncio
async def test_token_id_qr_code_generation(client, db_session):
    """QR code endpoint generates PNG image for token ID verification URL."""
    token_id = random.randint(1000000, 9999999)
    admin_user = (await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))).scalar_one()
    db_session.add(Asset(token_id=token_id, serial_number=f"QR-TOK-{token_id}", is_physical=True, department="Avionics", owner_id=admin_user.id))
    await db_session.commit()

    with patch("app.services.contract.contract_service.get_asset", return_value={"token_id": token_id, "is_digital": False}):
        response = await client.get(f"/api/assets/token/{token_id}/qr", headers={"Authorization": f"Bearer {get_token(ADMIN_WALLET, 'ADMIN', 5)}"})

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert len(response.content) > 0


@pytest.mark.asyncio
async def test_token_id_qr_code_not_found(client):
    """QR code for unknown token ID returns 404."""
    with patch("app.services.contract.contract_service.get_digital_asset", return_value=None), \
         patch("app.services.contract.contract_service.get_asset", return_value=None):
        response = await client.get("/api/assets/token/99999999/qr", headers={"Authorization": f"Bearer {get_token(ADMIN_WALLET, 'ADMIN', 5)}"})
    assert response.status_code == 404
    assert "Asset not found" in response.json()["detail"]


@pytest.mark.asyncio
async def test_verify_data_endpoints(client, db_session):
    """Full verification data endpoints by serial and token return comprehensive on-chain & off-chain records."""
    res = await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))
    admin_user = res.scalar_one()

    serial = f"BEL-HW-SEC-{uuid.uuid4().hex[:6].upper()}"
    token_id = random.randint(1000000, 9999999)
    asset = Asset(
        token_id=token_id,
        serial_number=serial,
        name="Secure Comm Transceiver",
        asset_type="EQUIPMENT",
        is_physical=True,
        department="Avionics",
        lifecycle_status="ACTIVE",
        owner_id=admin_user.id
    )
    db_session.add(asset)

    # Add a maintenance record
    maint = MaintenanceRecord(
        asset_serial=serial,
        performed_by_did=f"did:ethr:13371:{ADMIN_WALLET}",
        action_description="Annual Firmware Calibration & Cryptographic Key Re-seed",
        notes="All diagnostics passed nominal levels.",
        log_hash="0xabcdef1234567890"
    )
    db_session.add(maint)
    await db_session.commit()

    with patch("app.services.contract.contract_service.get_token_by_serial", return_value=token_id), \
         patch("app.services.contract.contract_service.get_asset", return_value={
             "token_id": token_id,
             "serial_number": serial,
             "owner_address": ADMIN_WALLET,
             "owner_did": f"did:ethr:13371:{ADMIN_WALLET}",
             "is_digital": False
         }), \
         patch("app.services.contract.ContractService.contract_address", new_callable=PropertyMock, return_value="0xContract"), \
         patch("web3.eth.Eth.chain_id", new_callable=PropertyMock, return_value=13371):
        # Anyone scanning the QR: public fields only
        public = (await client.get(f"/api/assets/serial/{serial}/verify-data")).json()
        assert public["detail_level"] == "PUBLIC"
        assert public["serial_number"] == serial and public["token_id"] == token_id and public["department"] == "Avionics"
        for hidden in ("name", "owner_address", "owner_did", "maintenance_history", "mac_address", "device_unique_address", "file_hash"):
            assert hidden not in public, hidden

        res_serial = await client.get(f"/api/assets/serial/{serial}/verify-data", headers={"Authorization": f"Bearer {get_token(ADMIN_WALLET, 'ADMIN', 5)}"})
        assert res_serial.status_code == 200
        data = res_serial.json()
        assert data["detail_level"] == "AUTHORIZED"
        assert data["serial_number"] == serial
        assert data["token_id"] == token_id
        assert data["on_chain_verified"] is True
        assert data["name"] == "Secure Comm Transceiver"
        assert len(data["maintenance_history"]) == 1
        assert data["maintenance_history"][0]["action_description"] == "Annual Firmware Calibration & Cryptographic Key Re-seed"

        # Also test by token ID
        res_token = await client.get(f"/api/assets/token/{token_id}/verify-data", headers={"Authorization": f"Bearer {get_token(ADMIN_WALLET, 'ADMIN', 5)}"})
        assert res_token.status_code == 200
        token_data = res_token.json()
        assert token_data["serial_number"] == serial
        assert token_data["token_id"] == token_id


@pytest.mark.asyncio
async def test_physical_asset_verification_role_redaction(client, db_session):
    """Physical asset QR verification views enforce departmental and role-based data redaction."""
    res = await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))
    admin_user = res.scalar_one()

    serial = f"BEL-HW-PHY-{uuid.uuid4().hex[:6].upper()}"
    token_id = random.randint(1000000, 9999999)
    mac = f"AA:00:11:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}"
    dev_addr = f"SECURE-CHIP-{uuid.uuid4().hex[:8].upper()}"

    # Asset belongs to Cyber department
    asset = Asset(
        token_id=token_id,
        serial_number=serial,
        name="Cyber EW Hardware Node",
        asset_type="EQUIPMENT",
        is_physical=True,
        mac_address=mac,
        device_unique_address=dev_addr,
        location="Cyber Operations Center Bunker",
        department="Cyber",
        lifecycle_status="ACTIVE",
        owner_id=admin_user.id
    )
    db_session.add(asset)
    await db_session.commit()

    # 1. User from Avionics (Cross-department) -> Redacted
    user_token = get_token(USER_WALLET, "USER", 1)  # Avionics user
    res_user = await client.get(f"/api/assets/verify/{serial}", headers={"Authorization": f"Bearer {user_token}"})
    assert res_user.status_code == 200
    user_data = res_user.json()
    assert user_data["name"] == "Cyber EW Hardware Node"
    assert user_data["serial_number"] == serial
    assert user_data["is_physical"] is True
    # Verify sensitive physical identifiers are redacted
    assert "mac_address" not in user_data or user_data["mac_address"] is None
    assert "device_unique_address" not in user_data or user_data["device_unique_address"] is None
    assert "location" not in user_data or user_data["location"] is None

    # 2. Auditor (Cyber / Read-All) -> Sees Full Details
    auditor_token = get_token(AUDITOR_WALLET, "AUDITOR", 1)
    res_auditor = await client.get(f"/api/assets/verify/{serial}", headers={"Authorization": f"Bearer {auditor_token}"})
    assert res_auditor.status_code == 200
    auditor_data = res_auditor.json()
    assert auditor_data["mac_address"] == mac
    assert auditor_data["device_unique_address"] == dev_addr
    assert auditor_data["location"] == "Cyber Operations Center Bunker"
    assert auditor_data["token_id"] == token_id

    # 3. Admin -> Sees Full Details
    admin_token = get_token(ADMIN_WALLET, "ADMIN", 5)
    res_admin = await client.get(f"/api/assets/verify/{serial}", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200
    admin_data = res_admin.json()
    assert admin_data["mac_address"] == mac
    assert admin_data["device_unique_address"] == dev_addr
    assert admin_data["location"] == "Cyber Operations Center Bunker"
