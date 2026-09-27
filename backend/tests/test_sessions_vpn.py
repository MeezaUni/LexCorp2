"""Sessions and the VPN: each VPN connection gets a new address, so a reconnect ends the session
(recorded as an expected event, not an alert); the page's background session check never counts
as activity; reviewers are told where Forward sends an alert."""

import uuid
from datetime import datetime, timedelta, UTC

import pytest
from sqlalchemy import select

from app.models.domain import AuditEvent, SecurityAlert, User
from app.services.alerts import raise_alert
from app.services.auth import create_jwt

AUDITOR = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
AUDITOR_H = {"Authorization": f"Bearer {create_jwt(AUDITOR, f'did:ethr:13371:{AUDITOR}', 'AUDITOR', 1, client_ip='127.0.0.1')}"}


async def person(db_session, department="Avionics"):
    wallet = "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    u = User(wallet_address=wallet, did=f"did:ethr:13371:{wallet}", name=f"Session {wallet[-6:]}", role="USER",
             department=department, onboarding_pending=False, session_version=1, last_activity_at=datetime.now(UTC))
    db_session.add(u)
    await db_session.commit()
    return u


@pytest.mark.asyncio
async def test_vpn_reconnect_ends_the_session_without_an_alert(client, db_session):
    u = await person(db_session)
    token = create_jwt(u.wallet_address, u.did, "USER", 1, client_ip="10.8.0.5")
    ok = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "10.8.0.5"})
    assert ok.status_code == 200, ok.text
    r = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "10.8.0.9"})
    assert r.status_code == 401 and "VPN connection was renewed" in r.json()["detail"]
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.actor_did == u.did,
                                                            AuditEvent.event_type == "SESSION_ENDED_VPN_RECONNECT"))).scalar_one()
    assert ev.risk_label == "MEDIUM"
    assert (await db_session.execute(select(SecurityAlert).where(SecurityAlert.subject_did == u.did))).first() is None
    # the old token is dead even from its own address
    again = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "10.8.0.5"})
    assert again.status_code == 401


@pytest.mark.asyncio
async def test_other_address_changes_are_still_high_risk(client, db_session):
    u = await person(db_session)
    token = create_jwt(u.wallet_address, u.did, "USER", 1, client_ip="10.8.0.5")
    r = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "203.0.113.9"})
    assert r.status_code == 401 and "IP address changed" in r.json()["detail"]
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.actor_did == u.did,
                                                            AuditEvent.event_type == "SESSION_TERMINATED_IP_CHANGE"))).scalar_one()
    assert ev.risk_label == "HIGH"


@pytest.mark.asyncio
async def test_session_check_is_not_activity(client, db_session):
    u = await person(db_session)
    idle_since = datetime.now(UTC) - timedelta(minutes=5)
    u.last_activity_at = idle_since
    await db_session.commit()
    token = create_jwt(u.wallet_address, u.did, "USER", 1, client_ip="127.0.0.1")
    client.cookies.set("session", token)
    try:
        st = await client.get("/api/auth/session")
    finally:
        client.cookies.clear()
    assert st.json()["authenticated"] is True
    await db_session.refresh(u)
    assert abs((u.last_activity_at - idle_since).total_seconds()) < 1


@pytest.mark.asyncio
async def test_reviewer_is_told_where_forward_goes(client, db_session):
    for department, expected in (("Avionics", "MANAGER"), (f"Nowhere-{uuid.uuid4().hex[:6]}", "ADMIN")):
        u = await person(db_session, department)
        ev = AuditEvent(event_type="DOCUMENT_VIEWED", tx_hash=f"0x{uuid.uuid4().hex}", block_number=0, actor_did=u.did,
                        risk_label="HIGH", risk_factors={"reason": "test"})
        db_session.add(ev)
        await db_session.flush()
        alert = await raise_alert(db_session, ev, source="RULE")
        await db_session.commit()
        r = await client.get(f"/api/alerts/{alert.alert_id}", headers=AUDITOR_H)
        assert r.status_code == 200, r.text
        assert r.json()["forward_to"] == expected, department
