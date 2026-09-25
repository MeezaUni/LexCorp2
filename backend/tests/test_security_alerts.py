"""AI high-risk alert escalation chain (spec 39-43, 59)."""

import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.core.crypto import encrypt_secret
from app.models.domain import AuditEvent, SecurityAlert, SecurityAlertAction, User
from app.services.auth import create_jwt
from tests import flows
from tests.conftest import mfa_headers, totp_code, totp_secret_for

ADMIN, MANAGER, AUDITOR = flows.ADMIN, flows.MANAGER, "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
V = {ADMIN: ("ADMIN", 5), MANAGER: ("MANAGER", 8), AUDITOR: ("AUDITOR", 1)}


def h(w, version=None, role=None):
    r, v = V.get(w, ("USER", 1))
    return {"Authorization": f"Bearer {create_jwt(w, f'did:ethr:13371:{w}', role or r, version or v, client_ip='127.0.0.1')}"}


async def new_user(db, department="Avionics", role="USER"):
    w = "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    db.add(User(wallet_address=w, did=f"did:ethr:13371:{w}", role=role, department=department, name="Suspicious Sam",
                is_active=True, onboarding_pending=False, session_version=1, is_totp_enabled=True,
                is_totp_factor2_enabled=True, totp_factor2_secret=encrypt_secret(totp_secret_for(w, "factor2"))))
    await db.commit()
    return w


async def ai_flagged_view(client, db, subject_wallet, approver=MANAGER):
    """The subject views their own document; the local AI (patched to HIGH) raises an alert."""
    serial = await flows.approved_document(client, db, b"alert doc " + subject_wallet.encode(), "al.txt",
                                           owner=subject_wallet, approver=approver)
    fake = {"risk_label": "HIGH", "risk_score": 88.0, "ai": {"anomaly_score": -0.31, "model": "IsolationForest(local)"}}
    with patch("app.api.assets.ai_score", return_value=fake):
        r = await client.get(f"/api/assets/document/view/{serial}",
                             headers=await mfa_headers(db, flows.token_for(subject_wallet), subject_wallet, "document.view"))
    assert r.status_code == 200, r.text
    ev = (await db.execute(select(AuditEvent).where(AuditEvent.event_type == "DOCUMENT_VIEWED",
                                                    AuditEvent.actor_did == f"did:ethr:13371:{subject_wallet}"))).scalar_one()
    alert = (await db.execute(select(SecurityAlert).where(SecurityAlert.source_event_id == ev.id))).scalar_one()
    return alert


@pytest.mark.asyncio
async def test_ai_high_risk_raises_alert_with_subject_details(client, db_session):
    sam = await new_user(db_session)
    alert = await ai_flagged_view(client, db_session, sam)
    assert alert.source == "AI" and alert.state == "AUDITOR_REVIEW" and alert.alert_id.startswith("ALT-")
    assert alert.subject_wallet == sam and alert.subject_role == "USER" and alert.department == "Avionics"
    assert alert.risk_level == "HIGH" and alert.client_ip == "127.0.0.1" and alert.asset_serial
    assert alert.related_action_id and alert.related_action_id.startswith("VW-")
    listed = (await client.get("/api/alerts?state=AUDITOR_REVIEW", headers=h(AUDITOR))).json()
    row = next(a for a in listed if a["alert_id"] == alert.alert_id)
    assert row["subject"]["name"] == "Suspicious Sam" and row["subject"]["wallet"].startswith(sam[:6]) and "..." in row["subject"]["wallet"]


@pytest.mark.asyncio
async def test_rule_based_high_event_raises_alert(client, db_session):
    serial = await flows.approved_document(client, db_session, b"tamper alert doc", "ta.txt")
    view = await client.get(f"/api/assets/document/view/{serial}", headers=await mfa_headers(db_session, flows.token_for(flows.USER), flows.USER, "document.view"))
    vw = view.headers["x-lexcorp-action-id"]
    await client.post(f"/api/verify/action/{vw}/compare", json={"fields": {"View ID": "VW-00000000-0000"}})
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "WATERMARK_TAMPER_DETECTED")
                                   .order_by(AuditEvent.created_at.desc()))).scalars().first()
    alert = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.source_event_id == ev.id))).scalar_one()
    assert alert.source == "RULE" and alert.state == "AUDITOR_REVIEW"


@pytest.mark.asyncio
async def test_full_chain_to_identity_revocation(client, db_session):
    sam = await new_user(db_session)
    sam_token_headers = {"Authorization": f"Bearer {flows.token_for(sam)}"}
    assert (await client.get("/api/auth/me", headers=sam_token_headers)).status_code == 200
    alert = await ai_flagged_view(client, db_session, sam)
    aid = alert.alert_id

    # Manager cannot see it yet; auditor forwards
    assert (await client.get(f"/api/alerts/{aid}", headers=h(MANAGER))).status_code == 404
    assert (await client.post(f"/api/alerts/{aid}/forward", headers=h(ADMIN), json={})).status_code == 403
    f1 = await client.post(f"/api/alerts/{aid}/forward", headers=h(AUDITOR), json={"note": "pattern needs review"})
    assert f1.status_code == 200 and f1.json()["state"] == "MANAGER_REVIEW"
    # Auditor can no longer act; manager of Avionics forwards to admin
    assert (await client.post(f"/api/alerts/{aid}/dismiss", headers=h(AUDITOR), json={"note": "x"})).status_code == 403
    f2 = await client.post(f"/api/alerts/{aid}/forward", headers=h(MANAGER), json={"note": "confirmed unusual"})
    assert f2.status_code == 200 and f2.json()["state"] == "ADMIN_REVIEW"

    # Admin revocation needs Factor 3
    assert (await client.post(f"/api/alerts/{aid}/revoke-identity", headers=h(ADMIN), json={"note": "revoke"})).status_code == 401
    r = await client.post(f"/api/alerts/{aid}/revoke-identity", headers=h(ADMIN),
                          json={"note": "Confirmed insider exfiltration", "totp_code": totp_code(ADMIN, "factor3")})
    assert r.status_code == 200 and r.json()["state"] == "IDENTITY_REVOKED"

    user = (await db_session.execute(select(User).where(User.wallet_address == sam))).scalar_one()
    await db_session.refresh(user)
    assert user.is_active is False and user.revoked_at is not None and user.session_version == 2
    assert (await client.get("/api/auth/me", headers=sam_token_headers)).status_code in (401, 403)  # live session killed
    assert (await client.post("/api/auth/login/totp", json={"wallet_address": sam, "token": "123456"})).status_code == 401

    detail = (await client.get(f"/api/alerts/{aid}", headers=h(ADMIN))).json()
    assert [x["action"] for x in detail["history"]] == ["RAISED", "FORWARDED_TO_MANAGER", "FORWARDED_TO_ADMIN", "IDENTITY_REVOKED"]
    assert [x["actor_role"] for x in detail["history"][1:]] == ["AUDITOR", "MANAGER", "ADMIN"]
    kinds = {e.event_type for e in (await db_session.execute(select(AuditEvent).where(AuditEvent.target_did == f"did:ethr:13371:{sam}"))).scalars()}
    assert {"ALERT_FORWARDED_TO_MANAGER", "ALERT_FORWARDED_TO_ADMIN", "ALERT_IDENTITY_REVOKED", "IDENTITY_REVOKED"} <= kinds


@pytest.mark.asyncio
async def test_dismissal_at_each_level(client, db_session):
    for stage in ("AUDITOR", "MANAGER", "ADMIN"):
        sam = await new_user(db_session)
        alert = await ai_flagged_view(client, db_session, sam)
        aid = alert.alert_id
        if stage in ("MANAGER", "ADMIN"):
            await client.post(f"/api/alerts/{aid}/forward", headers=h(AUDITOR), json={})
        if stage == "ADMIN":
            await client.post(f"/api/alerts/{aid}/forward", headers=h(MANAGER), json={})
        actor = {"AUDITOR": AUDITOR, "MANAGER": MANAGER, "ADMIN": ADMIN}[stage]
        assert (await client.post(f"/api/alerts/{aid}/dismiss", headers=h(actor), json={})).status_code == 400  # reason required
        d = await client.post(f"/api/alerts/{aid}/dismiss", headers=h(actor), json={"note": "false alarm: scheduled audit"})
        assert d.status_code == 200 and d.json()["state"] == "DISMISSED", (stage, d.text)
        user = (await db_session.execute(select(User).where(User.wallet_address == sam))).scalar_one()
        await db_session.refresh(user)
        assert user.is_active is True


@pytest.mark.asyncio
async def test_scope_and_role_guards(client, db_session):
    cyber_sam = await new_user(db_session, department="Cyber")
    alert = await ai_flagged_view(client, db_session, cyber_sam, approver=ADMIN)  # Avionics manager is out of scope
    aid = alert.alert_id
    await client.post(f"/api/alerts/{aid}/forward", headers=h(AUDITOR), json={})
    # Avionics manager cannot see a Cyber alert; USER cannot use the queue
    assert (await client.get(f"/api/alerts/{aid}", headers=h(MANAGER))).status_code == 404
    assert (await client.get("/api/alerts", headers=h(flows.USER, role="USER"))).status_code == 403
    # No manager covers Cyber here, so the Admin may take it forward instead of it being stuck
    fa = await client.post(f"/api/alerts/{aid}/forward", headers=h(ADMIN), json={"note": "no cyber manager"})
    assert fa.status_code == 200 and fa.json()["state"] == "ADMIN_REVIEW"


async def _raise_for(db, wallet):
    from app.services.alerts import raise_alert
    ev = AuditEvent(event_type="MANUAL_TEST_HIGH", tx_hash="0xhi" + uuid.uuid4().hex, block_number=0,
                    actor_did=f"did:ethr:13371:{wallet}", risk_label="HIGH", risk_score=90.0)
    db.add(ev)
    alert = await raise_alert(db, ev, source="RULE")
    await db.commit()
    return alert.alert_id


@pytest.mark.asyncio
async def test_alert_about_the_only_department_manager_is_not_stuck(client, db_session):
    from app.models.domain import Department
    dept = f"AlertDept-{uuid.uuid4().hex[:6]}"
    db_session.add(Department(name=dept, is_active=True))
    await db_session.commit()
    mgr = await new_user(db_session, department=dept, role="MANAGER")
    aid = await _raise_for(db_session, mgr)
    await client.post(f"/api/alerts/{aid}/forward", headers=h(AUDITOR), json={})
    own = await client.post(f"/api/alerts/{aid}/forward", headers=h(mgr, version=1, role="MANAGER"), json={})
    assert own.status_code == 403 and "yourself" in own.json()["detail"]
    fa = await client.post(f"/api/alerts/{aid}/forward", headers=h(ADMIN), json={"note": "subject is the only manager"})
    assert fa.status_code == 200 and fa.json()["state"] == "ADMIN_REVIEW"


@pytest.mark.asyncio
async def test_subject_cannot_act_and_escalated_alert_gates_sensitive_ops(client, db_session):
    """The test ADMIN is the subject: they cannot handle their own alert, and while it sits in
    ADMIN_REVIEW their sensitive operations (transfer) are blocked."""
    aid = await _raise_for(db_session, ADMIN)
    try:
        await client.post(f"/api/alerts/{aid}/forward", headers=h(AUDITOR), json={})
        own = await client.post(f"/api/alerts/{aid}/forward", headers=h(ADMIN), json={})
        assert own.status_code == 403 and "yourself" in own.json()["detail"]
        f2 = await client.post(f"/api/alerts/{aid}/forward", headers=h(MANAGER), json={})
        assert f2.status_code == 200 and f2.json()["state"] == "ADMIN_REVIEW"
        blocked = await client.post("/api/assets/transfer/prepare", headers=h(ADMIN),
                                    json={"to_address": "0x" + "1" * 40, "token_id": 1, "new_owner_did": "did:x"})
        assert blocked.status_code == 403 and aid in blocked.json()["detail"]
        assert (await client.post(f"/api/alerts/{aid}/dismiss", headers=h(ADMIN), json={"note": "mine"})).status_code == 403
    finally:
        # No second admin exists in the test data to close it; close it directly so the gate
        # does not leak into later tests.
        row = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.alert_id == aid))).scalar_one()
        row.state = "DISMISSED"
        await db_session.commit()


@pytest.mark.asyncio
async def test_legacy_triage_endpoint_retired(client, db_session):
    r = await client.patch(f"/api/audit/alerts/{uuid.uuid4()}/status", headers=h(AUDITOR), json={"alert_status": "DISMISSED"})
    assert r.status_code == 410


@pytest.mark.asyncio
async def test_user_delete_endpoint_uses_same_revocation(client, db_session):
    sam = await new_user(db_session)
    user = (await db_session.execute(select(User).where(User.wallet_address == sam))).scalar_one()
    # Without Factor 3 the revocation is refused and nothing changes.
    r = await client.delete(f"/api/users/{user.id}", headers=h(ADMIN))
    assert r.status_code == 401
    await db_session.refresh(user)
    assert user.is_active is True
    from tests.conftest import step_up_header
    r = await client.delete(f"/api/users/{user.id}", headers={**h(ADMIN), **(await step_up_header(ADMIN, "identity.revoke"))})
    assert r.status_code == 204
    await db_session.refresh(user)
    assert user.is_active is False and user.revoked_at is not None and user.session_version == 2
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "IDENTITY_REVOKED", AuditEvent.target_did == user.did))).scalar_one()
    assert ev.actor_did.endswith(ADMIN)
