"""Physical NFT card, verification redaction, lifecycle and mint confirmation (spec 35-38, 58)."""

import random
import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.domain import Asset, AuditEvent, DocumentAction, User
from app.services.auth import create_jwt
from tests.conftest import mfa_headers

ADMIN = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
MANAGER = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"   # Avionics
USER = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
AUDITOR = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
V = {ADMIN: ("ADMIN", 5), MANAGER: ("MANAGER", 8), USER: ("USER", 1), AUDITOR: ("AUDITOR", 1)}


def h(w):
    role, ver = V[w]
    return {"Authorization": f"Bearer {create_jwt(w, f'did:ethr:13371:{w}', role, ver, client_ip='127.0.0.1')}"}


async def registered(client, db, department="Avionics", mac=True):
    """Register + approve a physical asset through the API. Returns the Asset."""
    serial = f"PL-{uuid.uuid4().hex[:8].upper()}"
    ident = {"has_mac_address": True, "mac_address": f"02:00:00:{random.randint(16,99)}:{random.randint(16,99)}:{random.randint(16,99)}"} if mac \
        else {"has_mac_address": False, "device_unique_address": f"UA-{uuid.uuid4().hex[:10]}"}
    t = h(ADMIN)["Authorization"].split()[1]
    # An Administrator registers directly (Factor 3): approved at once, ready for their wallet to record
    with patch("app.services.contract.contract_service.prepare_mint_calldata", return_value={"to": "0x1", "data": "0x2"}):
        r = await client.post("/api/assets/physical/propose", headers=await mfa_headers(db, t, ADMIN, "asset.mint"),
                              json={"name": "Radar Unit", "serial_number": serial, "recipient_address": ADMIN, "department": department, **ident})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "APPROVED"
    return (await db.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()


@pytest.mark.asyncio
async def test_card_has_only_allowed_fields_and_scope(client, db_session):
    a = await registered(client, db_session)
    svg = (await client.get(f"/api/assets/serial/{a.serial_number}/card", headers=h(MANAGER))).text
    for present in (a.serial_number, f"#{a.token_id}", "Avionics", "data:image/png;base64,"):
        assert present in svg
    import re as _re
    visible = _re.sub(r'data:image/png;base64,[^"]+', "", svg)  # ignore the QR image bytes
    for absent in (a.mac_address, a.action_id, ADMIN, "did:ethr", "Radar Unit", "0x"):
        assert absent not in visible, absent
    # USER without scope cannot fetch; digital assets have no card
    assert (await client.get(f"/api/assets/serial/{a.serial_number}/card", headers=h(USER))).status_code == 404
    assert (await client.get(f"/api/assets/serial/{a.serial_number}/card")).status_code == 401


@pytest.mark.asyncio
async def test_verification_public_minimal_authorized_detailed(client, db_session):
    a = await registered(client, db_session, mac=False)
    with patch("app.services.contract.contract_service.get_token_by_serial", return_value=a.token_id), \
         patch("app.services.contract.contract_service.get_digital_asset", return_value=None), \
         patch("app.services.contract.contract_service.get_asset", return_value={"is_digital": False}):
        public = (await client.get(f"/api/assets/serial/{a.serial_number}/verify-data")).json()
        mgr = (await client.get(f"/api/assets/serial/{a.serial_number}/verify-data", headers=h(MANAGER))).json()
        aud = (await client.get(f"/api/assets/serial/{a.serial_number}/verify-data", headers=h(AUDITOR))).json()
        usr = (await client.get(f"/api/assets/serial/{a.serial_number}/verify-data", headers=h(USER))).json()
    assert public["detail_level"] == "PUBLIC" and public["serial_number"] == a.serial_number and public["department"] == "Avionics"
    assert "device_unique_address" not in public and "creation_id" not in public
    assert usr["detail_level"] == "PUBLIC"  # signed in but no scope: still redacted
    for d in (mgr, aud):
        assert d["detail_level"] == "AUTHORIZED"
        assert d["device_unique_address"] == a.device_unique_address and d["creation_id"] == a.action_id
        assert d["approval"]["approved_by"].endswith(ADMIN)  # the Administrator registered and recorded it directly
        assert [e["event"] for e in d["lifecycle"]][:2] == ["PHYSICAL_ASSET_CREATED", "PHYSICAL_ASSET_APPROVED"]
    verified = (await db_session.execute(select(AuditEvent).where(AuditEvent.asset_serial == a.serial_number,
                                                                  AuditEvent.event_type == "ASSET_VERIFIED"))).scalars().all()
    assert {v.risk_factors["detail_level"] for v in verified} == {"PUBLIC", "AUTHORIZED"}


@pytest.mark.asyncio
async def test_status_change_requires_factor3_and_scope(client, db_session):
    a = await registered(client, db_session)
    cyber = await registered(client, db_session, department="Cyber")
    no_factor = await client.post(f"/api/assets/physical/{a.serial_number}/status", headers=h(MANAGER), json={"status": "MAINTENANCE"})
    assert no_factor.status_code == 401
    mt = h(MANAGER)["Authorization"].split()[1]
    bad = await client.post(f"/api/assets/physical/{a.serial_number}/status", headers=await mfa_headers(db_session, mt, MANAGER, "asset.manage"),
                            json={"status": "EXPLODED"})
    assert bad.status_code == 400
    other = await client.post(f"/api/assets/physical/{cyber.serial_number}/status", headers=await mfa_headers(db_session, mt, MANAGER, "asset.manage"),
                              json={"status": "RETIRED"})
    assert other.status_code == 403
    ok = await client.post(f"/api/assets/physical/{a.serial_number}/status", headers=await mfa_headers(db_session, mt, MANAGER, "asset.manage"),
                           json={"status": "retired", "reason": "end of life"})
    assert ok.status_code == 200 and ok.json()["lifecycle_status"] == "RETIRED"
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.asset_serial == a.serial_number,
                                                           AuditEvent.event_type == "ASSET_STATUS_CHANGED"))).scalar_one()
    assert ev.risk_factors["to"] == "RETIRED"


@pytest.mark.asyncio
async def test_custody_and_maintenance_audited(client, db_session):
    a = await registered(client, db_session)
    with patch("app.services.contract.contract_service.get_token_by_serial", return_value=a.token_id):
        r = await client.post(f"/api/assets/serial/{a.serial_number}/assign", headers=h(MANAGER),
                              json={"custodian_did": f"did:ethr:13371:{USER}", "custodian_department": "Avionics"})
        assert r.status_code == 200
        m = await client.post(f"/api/assets/serial/{a.serial_number}/maintenance", headers=h(MANAGER),
                              json={"performed_by_did": "ignored", "action_description": "calibration"})
        assert m.status_code == 200
    kinds = {e.event_type for e in (await db_session.execute(select(AuditEvent).where(AuditEvent.asset_serial == a.serial_number))).scalars()}
    assert {"ASSET_CUSTODIAN_CHANGED", "ASSET_MAINTENANCE_RECORDED"} <= kinds


@pytest.mark.asyncio
async def test_mint_confirm_requires_matching_chain_state(client, db_session):
    a = await registered(client, db_session)
    from app.services.contract import contract_service
    good = {"status": 1, "to": contract_service.contract_address, "blockNumber": 4242}
    cases = [
        ({"status": 0, "to": contract_service.contract_address, "blockNumber": 1}, a.token_id, 409),   # reverted
        ({"status": 1, "to": "0x" + "9" * 40, "blockNumber": 1}, a.token_id, 409),                     # other contract
        (good, a.token_id + 1, 409),                                                                     # chain shows another token
        (good, a.token_id, 200),
    ]
    for receipt, chain_token, expected in cases:
        with patch.object(contract_service.w3.eth, "get_transaction_receipt", MagicMock(return_value=receipt)), \
             patch("app.services.contract.contract_service.get_token_by_serial", return_value=chain_token):
            r = await client.post(f"/api/assets/physical/{a.serial_number}/mint-confirm", headers=h(MANAGER), json={"tx_hash": "0x" + "ab" * 32})
        assert r.status_code == expected, (receipt, chain_token, r.text)
    await db_session.refresh(a)
    assert a.lifecycle_status == "MINTED"
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.asset_serial == a.serial_number,
                                                           AuditEvent.event_type == "PHYSICAL_ASSET_MINTED"))).scalar_one()
    assert ev.risk_factors["tx_hash"] == "0x" + "ab" * 32 and ev.risk_factors["block_number"] == 4242


@pytest.mark.asyncio
async def test_mint_confirm_against_real_besu_rejects_fabricated_tx(client, db_session):
    """Read-only query of the live Besu node: an invented tx hash is never recorded as a mint."""
    a = await registered(client, db_session)
    r = await client.post(f"/api/assets/physical/{a.serial_number}/mint-confirm", headers=h(MANAGER), json={"tx_hash": "0x" + "cd" * 32})
    assert r.status_code == 409
    await db_session.refresh(a)
    assert a.lifecycle_status != "MINTED"
