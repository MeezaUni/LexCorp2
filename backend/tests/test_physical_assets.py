"""Physical asset registration, global uniqueness and duplicate auditing (spec 32-34, 58)."""

import pytest
from tests.conftest import mfa_headers
import uuid
import random
from unittest.mock import patch
from app.services.auth import create_jwt
from app.services.physical import fingerprint
from app.models.domain import Asset, User, AuditEvent
from sqlalchemy import select

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower()
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower()
USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower()
AUDITOR_WALLET = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".lower()


def get_token(wallet: str, role: str, session_version: int = 1) -> str:
    did = f"did:ethr:13371:{wallet}"
    return create_jwt(wallet, did, role, session_version, client_ip="testclient")


def rand_mac(prefix="00:1A:2B"):
    return f"{prefix}:{random.randint(16, 99)}:{random.randint(16, 99)}:{random.randint(16, 99)}"


async def propose(client, db, body, wallet=MANAGER_WALLET, role="MANAGER", version=8):
    with patch("app.services.contract.contract_service.prepare_mint_calldata", return_value={"to": "0x1", "data": "0x2"}):
        return await _post_propose(client, db, body, wallet, role, version)


async def _post_propose(client, db, body, wallet, role, version):
    return await client.post("/api/assets/physical/propose",
                             headers=await mfa_headers(db, get_token(wallet, role, version), wallet, "asset.mint"),
                             json={"name": "HW", "asset_type": "EQUIPMENT", "recipient_address": "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72", **body})


async def existing(db, **fields):
    admin = (await db.execute(select(User).where(User.wallet_address == ADMIN_WALLET))).scalar_one()
    a = Asset(token_id=random.randint(1000000, 9999999), serial_number=f"BEL-HW-EXISTING-{uuid.uuid4().hex[:6].upper()}",
              name="Existing", asset_type="EQUIPMENT", is_physical=True, department="Avionics", lifecycle_status="ACTIVE",
              owner_id=admin.id, **fields)
    db.add(a)
    await db.commit()
    return a


async def duplicate_audits(db, serial):
    rows = (await db.execute(select(AuditEvent).where(AuditEvent.asset_serial == serial))).scalars().all()
    return {r.event_type: r for r in rows}


@pytest.mark.asyncio
async def test_propose_physical_asset_success(client, db_session):
    """Manager registers hardware with Serial + MAC (MAC stored in canonical form)."""
    serial = f"BEL-HW-RADAR-{uuid.uuid4().hex[:6].upper()}"
    mac = rand_mac("00-1A-2B").replace(":", "-")
    response = await propose(client, db_session, {"serial_number": serial, "has_mac_address": True, "mac_address": mac,
                                                  "location": "Hangar 4, Bay C", "purpose": "Avionics Hardware Deployment"})
    assert response.status_code == 200, response.text
    data = response.json()
    # Managers/Admins register physical assets directly: approved at once, their wallet records it
    assert data["action_type"] == "CREATION" and data["action_id"].startswith("CRT-") and data["status"] == "APPROVED"
    assert data["calldata"] and data["contract_address"]
    assert data["asset_serial"] == serial
    assert "mac_address" not in (data.get("details") or {})  # identifiers are not echoed into action details
    stored = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    assert stored.mac_address == mac.replace("-", ":").lower() and stored.device_unique_address is None
    assert "PHYSICAL_ASSET_CREATED" in await duplicate_audits(db_session, serial)


@pytest.mark.asyncio
async def test_identifier_rules_mac_xor_unique_address(client, db_session):
    s = lambda: f"BEL-HW-RULE-{uuid.uuid4().hex[:6].upper()}"
    # Unique Address path
    ok = await propose(client, db_session, {"serial_number": s(), "has_mac_address": False, "device_unique_address": f"UA-{uuid.uuid4().hex[:8]}"})
    assert ok.status_code == 200
    # YES without MAC / NO without unique address / both / malformed MAC / missing serial
    assert (await propose(client, db_session, {"serial_number": s(), "has_mac_address": True})).status_code == 400
    assert (await propose(client, db_session, {"serial_number": s(), "has_mac_address": False})).status_code == 400
    assert (await propose(client, db_session, {"serial_number": s(), "mac_address": rand_mac(), "device_unique_address": "UA-x"})).status_code == 400
    assert (await propose(client, db_session, {"serial_number": s(), "has_mac_address": False, "mac_address": rand_mac(), "device_unique_address": "UA-y"})).status_code == 400
    assert (await propose(client, db_session, {"serial_number": s(), "has_mac_address": True, "mac_address": "ZZ:00:11:22:33:44"})).status_code == 400
    assert (await propose(client, db_session, {"serial_number": "   ", "has_mac_address": False, "device_unique_address": "UA-z"})).status_code == 400


@pytest.mark.asyncio
async def test_admin_can_register_user_and_auditor_cannot(client, db_session):
    body = {"serial_number": f"BEL-HW-ADM-{uuid.uuid4().hex[:6].upper()}", "has_mac_address": False, "device_unique_address": f"UA-{uuid.uuid4().hex[:8]}"}
    assert (await propose(client, db_session, body, ADMIN_WALLET, "ADMIN", 5)).status_code == 200


@pytest.mark.asyncio
async def test_user_cannot_propose_physical_asset(client):
    """Standard USER role is forbidden from proposing physical hardware."""
    user_token = get_token(USER_WALLET, "USER", 1)
    response = await client.post("/api/assets/physical/propose", headers={"Authorization": f"Bearer {user_token}"},
                                 json={"name": "x", "serial_number": f"BEL-HW-{uuid.uuid4().hex[:6].upper()}",
                                       "recipient_address": "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72", "has_mac_address": False, "device_unique_address": "UA-u"})
    assert response.status_code == 403
    assert "Only Managers and Administrators can propose physical assets" in response.json()["detail"]


@pytest.mark.asyncio
async def test_auditor_cannot_propose_physical_asset(client):
    """AUDITOR role is forbidden from proposing physical assets."""
    auditor_token = get_token(AUDITOR_WALLET, "AUDITOR", 1)
    response = await client.post("/api/assets/physical/propose", headers={"Authorization": f"Bearer {auditor_token}"},
                                 json={"name": "x", "serial_number": f"BEL-HW-{uuid.uuid4().hex[:6].upper()}", "recipient_address": "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"})
    assert response.status_code == 403
    assert "Auditors cannot propose assets" in response.json()["detail"]


@pytest.mark.asyncio
async def test_manager_cross_department_physical_proposal_rejected(client):
    """MANAGER cannot propose physical assets outside their assigned department."""
    mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
    response = await client.post("/api/assets/physical/propose", headers={"Authorization": f"Bearer {mgr_token}"},
                                 json={"name": "x", "serial_number": f"BEL-HW-CYBER-{uuid.uuid4().hex[:6].upper()}",
                                       "recipient_address": "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72", "department": "Cyber Warfare"})
    assert response.status_code == 403
    assert "Managers can only propose physical assets for their assigned department" in response.json()["detail"]


@pytest.mark.asyncio
async def test_duplicate_mac_address_attempt_audited(client, db_session):
    """Existing MAC (in any notation) -> rejected, audited with a fingerprint (raw value never logged), nothing created."""
    dup_mac = rand_mac("AA:BB:CC")
    await existing(db_session, mac_address=dup_mac)
    variant = dup_mac.replace(":", "").lower()  # same MAC, different notation
    serial_attempt = f"BEL-HW-CLONE-{uuid.uuid4().hex[:6].upper()}"
    response = await propose(client, db_session, {"serial_number": serial_attempt, "has_mac_address": True, "mac_address": variant})
    assert response.status_code == 400
    assert "MAC address is already registered" in response.json()["detail"]
    events = await duplicate_audits(db_session, serial_attempt)
    # One alert per attempt: the specific event is HIGH; the generic category row is audit-only.
    assert events["DUPLICATE_MAC_ATTEMPT"].risk_score == 0.85 and events["DUPLICATE_MAC_ATTEMPT"].risk_label == "HIGH"
    assert events["DUPLICATE_PHYSICAL_ASSET_ATTEMPT"].risk_label is None
    assert events["DUPLICATE_PHYSICAL_ASSET_ATTEMPT"].risk_factors["specific_event"] == "DUPLICATE_MAC_ATTEMPT"
    from app.models.domain import SecurityAlert
    alerts = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.asset_serial == serial_attempt))).scalars().all()
    assert len(alerts) == 1 and alerts[0].event_type == "DUPLICATE_MAC_ATTEMPT"
    for kind in ("DUPLICATE_PHYSICAL_ASSET_ATTEMPT", "DUPLICATE_MAC_ATTEMPT"):
        ev = events[kind]
        assert ev.risk_factors["duplicate_field"] == "mac"
        assert ev.risk_factors["value_fingerprint"] == fingerprint(dup_mac.lower())
        assert dup_mac.lower() not in str(ev.risk_factors).lower() and variant not in str(ev.risk_factors)
    assert (await db_session.execute(select(Asset).where(Asset.serial_number == serial_attempt))).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_duplicate_device_unique_address_attempt_audited(client, db_session):
    """Existing Unique Address (case/whitespace-insensitive) -> rejected and audited, nothing created."""
    dup_dev = f"SECURE-CHIP-ID-{uuid.uuid4().hex[:8].upper()}"
    await existing(db_session, device_unique_address=dup_dev)
    serial_attempt = f"BEL-HW-CLONE-DEV-{uuid.uuid4().hex[:6].upper()}"
    response = await propose(client, db_session, {"serial_number": serial_attempt, "has_mac_address": False,
                                                  "device_unique_address": f"  {dup_dev.lower()} "})
    assert response.status_code == 400
    assert "Device unique address is already registered" in response.json()["detail"]
    events = await duplicate_audits(db_session, serial_attempt)
    assert events["DUPLICATE_UNIQUE_ADDRESS_ATTEMPT"].risk_label == "HIGH"
    assert dup_dev.lower() not in str(events["DUPLICATE_PHYSICAL_ASSET_ATTEMPT"].risk_factors).lower()
    assert (await db_session.execute(select(Asset).where(Asset.serial_number == serial_attempt))).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_duplicate_serial_number_attempt_audited(client, db_session):
    """Duplicate serial (case-insensitive, global) -> rejected, audited, nothing created, no mint calldata."""
    dup = await existing(db_session, device_unique_address=f"UA-{uuid.uuid4().hex[:8]}")
    response = await propose(client, db_session, {"serial_number": f" {dup.serial_number.lower()} ", "has_mac_address": False,
                                                  "device_unique_address": f"UA-{uuid.uuid4().hex[:8]}"})
    assert response.status_code == 400
    assert "Asset serial number already exists" in response.json()["detail"]
    events = await duplicate_audits(db_session, dup.serial_number.lower())
    assert events["DUPLICATE_SERIAL_ATTEMPT"].risk_score == 0.85
    assert events["DUPLICATE_SERIAL_ATTEMPT"].risk_label == "HIGH"
    assert events["DUPLICATE_PHYSICAL_ASSET_ATTEMPT"].risk_factors["specific_event"] == "DUPLICATE_SERIAL_ATTEMPT"
    count = (await db_session.execute(select(Asset).where(Asset.serial_number.ilike(dup.serial_number)))).scalars().all()
    assert len(count) == 1


@pytest.mark.asyncio
async def test_uniqueness_is_global_across_departments(client, db_session):
    """A MAC registered in Cyber blocks the same MAC in Avionics (not department-scoped)."""
    mac = rand_mac("0C:0C:0C")
    admin = (await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))).scalar_one()
    db_session.add(Asset(token_id=random.randint(1000000, 9999999), serial_number=f"CY-{uuid.uuid4().hex[:6]}", is_physical=True,
                         department="Cyber", mac_address=mac, owner_id=admin.id))
    await db_session.commit()
    r = await propose(client, db_session, {"serial_number": f"AV-{uuid.uuid4().hex[:6]}", "has_mac_address": True, "mac_address": mac})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_database_rejects_normalised_duplicates_directly(db_session):
    """The normalised unique indexes hold even for writes that bypass the API."""
    from sqlalchemy.exc import IntegrityError
    mac = rand_mac("0D:0D:0D")
    a = await existing(db_session, mac_address=mac)
    existing_serial = a.serial_number
    admin_id = (await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))).scalar_one().id
    db_session.add(Asset(token_id=random.randint(1000000, 9999999), serial_number=f"DIRECT-{uuid.uuid4().hex[:6]}",
                         is_physical=True, mac_address=mac.replace(":", "-").upper(), owner_id=admin_id))
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()
    db_session.add(Asset(token_id=random.randint(1000000, 9999999), serial_number=existing_serial.lower(), is_physical=True, owner_id=admin_id))
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_physical_registration_is_direct_and_never_queued(client, db_session):
    """Only Managers/Admins register physical assets, so there is no approval step: the
    registration is approved at once and never waits in anyone's pending queue."""
    serial = f"BEL-HW-DIRECT-{uuid.uuid4().hex[:6].upper()}"
    weak = await client.post("/api/assets/physical/propose",
                             headers=await mfa_headers(db_session, get_token(MANAGER_WALLET, "MANAGER", 8), MANAGER_WALLET, "document.submit"),
                             json={"name": "HW", "asset_type": "EQUIPMENT", "serial_number": serial, "has_mac_address": False,
                                   "device_unique_address": f"UA-{uuid.uuid4().hex[:8]}", "recipient_address": USER_WALLET})
    assert weak.status_code == 401  # recording on the ledger needs Factor 3, not Factor 2
    r = await propose(client, db_session, {"serial_number": serial, "has_mac_address": False, "device_unique_address": f"UA-{uuid.uuid4().hex[:8]}"})
    assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    for wallet, role, version in ((MANAGER_WALLET, "MANAGER", 8), (ADMIN_WALLET, "ADMIN", 5)):
        pending = await client.get("/api/assets/physical/pending", headers={"Authorization": f"Bearer {get_token(wallet, role, version)}"})
        assert pending.status_code == 200 and not any(item["asset_serial"] == serial for item in pending.json())


@pytest.mark.asyncio
async def test_physical_asset_approval_calldata(client, db_session):
    """A Manager's registration returns the physical mint calldata for their wallet and audits the approval."""
    serial = f"BEL-HW-APPROVE-{uuid.uuid4().hex[:6].upper()}"
    with patch("app.services.contract.contract_service.prepare_mint_calldata", return_value={"to": "0xContract", "data": "0xPhysicalMintData"}) as mint:
        prop_res = await _post_propose(client, db_session, {"serial_number": serial, "has_mac_address": True, "mac_address": rand_mac(),
                                                            "location": "Avionics Lab"}, MANAGER_WALLET, "MANAGER", 8)
    assert prop_res.status_code == 200, prop_res.text
    data = prop_res.json()
    assert data["status"] == "APPROVED" and data["calldata"]["data"] == "0xPhysicalMintData"
    assert "PHYSICAL_ASSET_APPROVED" in await duplicate_audits(db_session, serial)
    # The named recipient is the registry owner, the mint recipient and the owner DID.
    recipient = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
    kwargs = mint.call_args.kwargs
    assert kwargs["to_address"].lower() == recipient and kwargs["owner_did"] == f"did:ethr:13371:{recipient}"
    asset = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    await db_session.refresh(asset)
    owner = (await db_session.execute(select(User).where(User.id == asset.owner_id))).scalar_one()
    assert owner.wallet_address == recipient


@pytest.mark.asyncio
async def test_asset_for_unregistered_recipient_is_refused(client, db_session):
    """Registry owner, on-chain holder and owner DID must agree: recipients must be registered identities."""
    serial = f"PHY-RCPT-{uuid.uuid4().hex[:6].upper()}"
    r = await propose(client, db_session, {"serial_number": serial, "has_mac_address": False,
                                           "device_unique_address": f"UA-{uuid.uuid4().hex[:8]}",
                                           "recipient_address": "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]})
    assert r.status_code == 400 and "registered, active" in r.json()["detail"]
