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


@pytest.mark.asyncio
async def test_signing_in_elsewhere_is_recorded_on_both_sides(client, db_session):
    import pyotp
    from app.core.crypto import encrypt_secret
    from app.models.domain import WebAuthnCredential
    secret = pyotp.random_base32()
    u = await person(db_session)
    u.totp_secret, u.is_totp_enabled, u.session_version = encrypt_secret(secret), True, 3
    db_session.add(WebAuthnCredential(user_id=u.id, credential_id=uuid.uuid4().hex, public_key="00", factor_scope="login"))
    db_session.add(AuditEvent(event_type="AuthenticationSucceeded", tx_hash=f"0x{uuid.uuid4().hex}", block_number=0,
                              actor_did=u.did, client_ip="10.8.0.5", created_at=datetime.now(UTC) - timedelta(minutes=5)))
    await db_session.commit()
    laptop = create_jwt(u.wallet_address, u.did, "USER", 3, client_ip="10.8.0.5")      # the session in use

    phone = await client.post("/api/auth/login/totp", headers={"X-Forwarded-For": "10.8.0.9"},
                              json={"wallet_address": u.wallet_address, "token": pyotp.TOTP(secret).now()})
    assert phone.status_code == 200, phone.text
    replaced = (await db_session.execute(select(AuditEvent).where(
        AuditEvent.actor_did == u.did, AuditEvent.event_type == "SESSION_REPLACED_BY_NEW_LOGIN"))).scalar_one()
    assert replaced.client_ip == "10.8.0.9" and replaced.risk_factors["previous_session_ip"] == "10.8.0.5"
    assert replaced.risk_label == "MEDIUM"
    signin = (await db_session.execute(select(AuditEvent).where(
        AuditEvent.actor_did == u.did, AuditEvent.event_type == "AuthenticationSucceeded",
        AuditEvent.client_ip == "10.8.0.9"))).scalar_one()
    assert signin.risk_label is not None          # scored by the AI (or its baseline without a model)

    for _ in range(2):                            # the laptop's next requests: signed out, recorded once
        r = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {laptop}", "X-Forwarded-For": "10.8.0.5"})
        assert r.status_code == 401 and "signed in on another device" in r.json()["detail"]
    ended = (await db_session.execute(select(AuditEvent).where(
        AuditEvent.actor_did == u.did, AuditEvent.event_type == "SESSION_ENDED_REPLACED"))).scalars().all()
    assert len(ended) == 1 and ended[0].risk_factors["session_ip"] == "10.8.0.5"


@pytest.mark.asyncio
async def test_unscored_events_get_their_baseline_level(db_session):
    from app.api.dependencies import record_audit
    u = await person(db_session)
    await record_audit(db_session, "LOGOUT", actor_did=u.did)
    await record_audit(db_session, "PROVISIONING_PIN_REISSUED", actor_did=u.did)
    await record_audit(db_session, "DOCUMENT_VIEWED", actor_did=u.did, risk_label="LOW", risk_score=12.0)   # scored: kept
    await db_session.commit()
    rows = {e.event_type: e for e in (await db_session.execute(select(AuditEvent).where(AuditEvent.actor_did == u.did))).scalars()}
    assert rows["LOGOUT"].risk_label == "LOW" and "not scored by the AI" in rows["LOGOUT"].risk_factors["risk_basis"]
    assert rows["PROVISIONING_PIN_REISSUED"].risk_label == "MEDIUM"
    assert rows["DOCUMENT_VIEWED"].risk_score == 12.0 and "risk_basis" not in (rows["DOCUMENT_VIEWED"].risk_factors or {})
