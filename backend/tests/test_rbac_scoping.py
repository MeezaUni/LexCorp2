"""Server-side RBAC and department scoping (spec sections 6, 7, 37, 52, 57, 70).

Filtering must happen in the backend query: a caller can never retrieve other
departments' rows by editing requests, IDs or department fields.
"""

import random
import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.models.domain import Asset, AuditEvent, User
from app.services.auth import create_jwt

ADMIN = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
MANAGER = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"   # Avionics
USER = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"      # Avionics
AUDITOR = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"   # Cyber
VERSIONS = {ADMIN: 5, MANAGER: 8, USER: 1, AUDITOR: 1}
ROLES = {ADMIN: "ADMIN", MANAGER: "MANAGER", USER: "USER", AUDITOR: "AUDITOR"}


def h(wallet: str) -> dict:
    token = create_jwt(wallet, f"did:ethr:13371:{wallet}", ROLES[wallet], VERSIONS[wallet], client_ip="127.0.0.1")
    return {"Authorization": f"Bearer {token}"}


async def hf3(wallet: str, action: str = "identity.provision") -> dict:
    from tests.conftest import step_up_header
    return {**h(wallet), **(await step_up_header(wallet, action))}


async def uid(db, wallet):
    return (await db.execute(select(User).where(User.wallet_address == wallet))).scalar_one()


async def make_asset(db, owner_wallet, department, *, physical=True, mac=True):
    owner = await uid(db, owner_wallet)
    serial = f"RBAC-{department}-{uuid.uuid4().hex[:8]}"
    a = Asset(
        token_id=random.randint(10_000_000, 2_000_000_000), serial_number=serial, owner_id=owner.id,
        department=department, is_physical=physical, asset_type="EQUIPMENT" if physical else "DOCUMENT",
        mac_address=f"02:00:{uuid.uuid4().hex[:2]}:{uuid.uuid4().hex[:2]}:{uuid.uuid4().hex[:2]}:{uuid.uuid4().hex[:2]}" if mac else None,
    )
    db.add(a)
    await db.commit()
    return a


@pytest.fixture
async def dept_assets(db_session):
    return {
        "avionics": await make_asset(db_session, ADMIN, "Avionics"),
        "cyber": await make_asset(db_session, ADMIN, "Cyber"),
        "radar": await make_asset(db_session, ADMIN, "Radar"),
        "user_own": await make_asset(db_session, USER, "Avionics"),
    }


@pytest.mark.asyncio
async def test_previously_public_endpoints_require_session(client, dept_assets):
    s = dept_assets["cyber"].serial_number
    t = dept_assets["cyber"].token_id
    endpoints = [
        ("get", "/api/assets/registry"), ("get", f"/api/assets/by-owner/{ADMIN}"),
        ("get", f"/api/assets/serial/{s}"), ("get", f"/api/assets/{t}"),
        ("get", f"/api/assets/serial/{s}/card"), ("get", f"/api/assets/serial/{s}/qr"),
        ("get", f"/api/assets/token/{t}/qr"), ("get", f"/api/assets/serial/{s}/maintenance"),
        ("post", "/api/assets/check-access"), ("get", "/api/audit/stats"), ("get", "/api/audit/events"),
        ("get", f"/api/audit/user-permissions/{ADMIN}"), ("get", "/api/audit/events/by-tx/0x1"),
        ("get", "/api/indexer/status"), ("post", "/api/indexer/catch-up"), ("get", "/api/users"),
        ("get", "/api/users/departments"), ("post", "/api/auth/vc/issue?subject_did=x"),
    ]
    for method, url in endpoints:
        kwargs = {"json": {"token_id": t, "requester_did": "x", "caller_address": ADMIN}} if url.endswith("check-access") else {}
        r = await getattr(client, method)(url, **kwargs)
        assert r.status_code == 401, (url, r.status_code)


@pytest.mark.asyncio
async def test_registry_scoped_by_role(client, db_session, dept_assets):
    def serials(res):
        assert res.status_code == 200, res.text
        return {a["serial_number"]: a for a in res.json()}

    admin = serials(await client.get("/api/assets/registry", headers=h(ADMIN)))
    auditor = serials(await client.get("/api/assets/registry", headers=h(AUDITOR)))
    manager = serials(await client.get("/api/assets/registry", headers=h(MANAGER)))
    user = serials(await client.get("/api/assets/registry", headers=h(USER)))

    for a in dept_assets.values():
        assert a.serial_number in admin and a.serial_number in auditor
    assert dept_assets["avionics"].serial_number in manager
    assert dept_assets["cyber"].serial_number not in manager
    assert dept_assets["radar"].serial_number not in manager
    assert set(user) >= {dept_assets["user_own"].serial_number}
    assert dept_assets["avionics"].serial_number not in user  # same department but not owned/granted
    # Sensitive identifiers: visible to admin/auditor/in-scope manager, redacted for USER
    assert admin[dept_assets["cyber"].serial_number]["mac_address"]
    assert manager[dept_assets["avionics"].serial_number]["mac_address"]
    assert user[dept_assets["user_own"].serial_number]["mac_address"] is None


@pytest.mark.asyncio
async def test_manager_direct_api_bypass_rejected(client, db_session, dept_assets):
    cyber = dept_assets["cyber"]
    with patch("app.services.contract.contract_service.get_digital_asset", return_value={"is_digital": False, "serial_number": cyber.serial_number}), \
         patch("app.services.contract.contract_service.get_token_by_serial", return_value=cyber.token_id):
        assert (await client.get(f"/api/assets/{cyber.token_id}", headers=h(MANAGER))).status_code == 404
        assert (await client.get(f"/api/assets/serial/{cyber.serial_number}", headers=h(MANAGER))).status_code == 404
        assert (await client.get(f"/api/assets/serial/{cyber.serial_number}/maintenance", headers=h(MANAGER))).status_code == 404
        assert (await client.get(f"/api/assets/document/lineage/{cyber.serial_number}", headers=h(MANAGER))).status_code == 404
    # Revoke / transfer calldata for another department's asset
    assert (await client.delete(f"/api/assets/{cyber.token_id}", headers=h(MANAGER))).status_code == 403
    assert (await client.delete(f"/api/assets/{cyber.token_id}", headers=h(USER))).status_code == 403
    # A cyber user's assets via by-owner
    auditor_assets = await client.get(f"/api/assets/by-owner/{AUDITOR}", headers=h(MANAGER))
    assert auditor_assets.status_code == 403
    # Custody reassignment into / of another department
    r = await client.post(f"/api/assets/serial/{cyber.serial_number}/assign", headers=h(MANAGER),
                          json={"custodian_did": "did:x", "custodian_department": "Avionics"})
    assert r.status_code in (403, 404)


@pytest.mark.asyncio
async def test_managed_departments_extend_manager_scope(client, db_session, dept_assets):
    mgr = await uid(db_session, MANAGER)
    r = await client.put(f"/api/users/{mgr.id}/managed-departments", headers=h(MANAGER), json={"departments": ["Cyber"]})
    assert r.status_code == 403  # only ADMIN may grant scope
    r = await client.put(f"/api/users/{mgr.id}/managed-departments", headers=h(ADMIN), json={"departments": ["Nope"]})
    assert r.status_code == 400
    r = await client.put(f"/api/users/{mgr.id}/managed-departments", headers=h(ADMIN), json={"departments": ["Cyber"]})
    assert r.status_code == 200
    try:
        reg = {a["serial_number"] for a in (await client.get("/api/assets/registry", headers=h(MANAGER))).json()}
        assert dept_assets["cyber"].serial_number in reg
        assert dept_assets["radar"].serial_number not in reg
        depts = (await client.get("/api/users/departments", headers=h(MANAGER))).json()["departments"]
        assert set(depts) == {"Avionics", "Cyber"}
    finally:
        await db_session.refresh(mgr)
        mgr.managed_departments = None
        await db_session.commit()


@pytest.mark.asyncio
async def test_user_creation_department_validated_server_side(client, db_session):
    def body(dept):
        return {"wallet_address": "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8], "role": "USER", "department": dept}

    assert (await client.get("/api/users/departments", headers=h(MANAGER))).json()["departments"] == ["Avionics"]
    assert set((await client.get("/api/users/departments", headers=h(ADMIN))).json()["departments"]) >= {"Avionics", "Cyber", "Radar"}
    assert (await client.get("/api/users/departments", headers=h(USER))).json()["departments"] == []

    # Manager manipulates department_id -> rejected
    assert (await client.post("/api/users", headers=await hf3(MANAGER), json=body("Cyber"))).status_code == 403
    assert (await client.post("/api/users", headers=await hf3(MANAGER), json=body("Invented Dept"))).status_code == 400
    ok = await client.post("/api/users", headers=await hf3(MANAGER), json=body("Avionics"))
    assert ok.status_code == 200 and ok.json()["department"] == "Avionics"
    # Admin: any active department, but not unknown ones
    assert (await client.post("/api/users", headers=await hf3(ADMIN), json=body("Radar"))).status_code == 200
    assert (await client.post("/api/users", headers=await hf3(ADMIN), json=body("Invented Dept"))).status_code == 400
    assert (await client.post("/api/users", headers=await hf3(ADMIN), json=body(None))).status_code == 400
    # USER / AUDITOR cannot create users
    assert (await client.post("/api/users", headers=h(USER), json=body("Avionics"))).status_code == 403
    assert (await client.post("/api/users", headers=h(AUDITOR), json=body("Cyber"))).status_code == 403


@pytest.mark.asyncio
async def test_user_list_scoped(client, db_session):
    user_view = (await client.get("/api/users", headers=h(USER))).json()
    assert [u["wallet_address"] for u in user_view] == [USER]
    mgr_view = (await client.get("/api/users", headers=h(MANAGER))).json()
    assert all(u["department"] == "Avionics" for u in mgr_view)
    assert AUDITOR not in {u["wallet_address"] for u in mgr_view}
    admin_view = {u["wallet_address"] for u in (await client.get("/api/users", headers=h(ADMIN))).json()}
    assert {ADMIN, MANAGER, USER, AUDITOR} <= admin_view


@pytest.mark.asyncio
async def test_audit_events_scoped(client, db_session, dept_assets):
    marker = uuid.uuid4().hex[:10]
    db_session.add_all([
        AuditEvent(event_type=f"SCOPE_{marker}", tx_hash=f"0xscope_cyber_{marker}", block_number=0,
                   actor_did=f"did:ethr:13371:{AUDITOR}", asset_serial=dept_assets["cyber"].serial_number),
        AuditEvent(event_type=f"SCOPE_{marker}", tx_hash=f"0xscope_user_{marker}", block_number=0,
                   actor_did=f"did:ethr:13371:{USER}", asset_serial=dept_assets["user_own"].serial_number),
    ])
    await db_session.commit()

    def hashes(res):
        assert res.status_code == 200
        return {e["tx_hash"] for e in res.json()}

    q = f"/api/audit/events?event_type=SCOPE_{marker}"
    assert hashes(await client.get(q, headers=h(AUDITOR))) == {f"0xscope_cyber_{marker}", f"0xscope_user_{marker}"}
    assert hashes(await client.get(q, headers=h(USER))) == {f"0xscope_user_{marker}"}
    assert hashes(await client.get(q, headers=h(MANAGER))) == {f"0xscope_user_{marker}"}
    r = await client.get(f"/api/audit/events/by-tx/0xscope_cyber_{marker}", headers=h(MANAGER))
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_indexer_catch_up_admin_only(client):
    assert (await client.post("/api/indexer/catch-up", headers=h(MANAGER))).status_code == 403
    assert (await client.post("/api/indexer/catch-up", headers=h(AUDITOR))).status_code == 403


@pytest.mark.asyncio
async def test_check_access_uses_session_identity(client):
    with patch("app.services.contract.contract_service.check_asset_access", return_value={"authorized": False, "level": 0}) as m:
        r = await client.post("/api/assets/check-access", headers=h(USER),
                              json={"token_id": 1, "requester_did": f"did:ethr:13371:{ADMIN}", "caller_address": ADMIN})
    assert r.status_code == 200
    called_did, called_addr = m.call_args[0][1], m.call_args[0][2]
    assert called_did.endswith(USER) and called_addr == USER


@pytest.mark.asyncio
async def test_public_verification_is_minimal_and_authorized_detail_is_scoped(client, db_session, dept_assets):
    cyber = dept_assets["cyber"]
    with patch("app.services.contract.contract_service.get_token_by_serial", return_value=cyber.token_id), \
         patch("app.services.contract.contract_service.get_digital_asset", return_value=None), \
         patch("app.services.contract.contract_service.get_asset", return_value={"is_digital": False, "owner_address": ADMIN, "owner_did": "did:x"}):
        public = (await client.get(f"/api/assets/serial/{cyber.serial_number}/verify-data")).json()
        mgr = (await client.get(f"/api/assets/serial/{cyber.serial_number}/verify-data", headers=h(MANAGER))).json()
        aud = (await client.get(f"/api/assets/serial/{cyber.serial_number}/verify-data", headers=h(AUDITOR))).json()
    assert set(public) == {"serial_number", "token_id", "on_chain_verified", "chain_id", "is_digital", "department",
                           "lifecycle_status", "approval_status", "created_at", "detail_level"}
    assert mgr["detail_level"] == "PUBLIC"  # Avionics manager, Cyber asset
    assert aud["detail_level"] == "AUTHORIZED" and aud["mac_address"] == cyber.mac_address


@pytest.mark.asyncio
async def test_audit_stats_are_scoped_like_events(client, db_session):
    """A Manager's dashboard statistics count only events they may read."""
    import hashlib
    outsider = "did:ethr:13371:0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    before_mgr = (await client.get("/api/audit/stats", headers=h(MANAGER))).json()
    before_admin = (await client.get("/api/audit/stats", headers=h(ADMIN))).json()
    db_session.add(AuditEvent(event_type="AuthenticationFailed", tx_hash="0x" + hashlib.sha256(outsider.encode()).hexdigest(),
                              block_number=0, actor_did=outsider, risk_label="HIGH"))
    await db_session.commit()
    after_mgr = (await client.get("/api/audit/stats", headers=h(MANAGER))).json()
    after_admin = (await client.get("/api/audit/stats", headers=h(ADMIN))).json()
    assert after_admin["total_events"] >= before_admin["total_events"] + 1
    assert after_admin["high_risk_7d"] >= before_admin["high_risk_7d"] + 1
    assert after_mgr["total_events"] == before_mgr["total_events"]
    assert after_mgr["high_risk_7d"] == before_mgr["high_risk_7d"]
    from app.models.domain import SecurityAlert
    for a in (await db_session.execute(select(SecurityAlert).where(SecurityAlert.state == "AUDITOR_REVIEW"))).scalars().all():
        a.state = "DISMISSED"
    await db_session.commit()
