"""Server-side audit filters (spec 44)."""

import uuid
from datetime import datetime, UTC

import pytest

from app.models.domain import AuditEvent
from app.services.alerts import raise_alert
from app.services.auth import create_jwt

AUDITOR = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
USER = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"      # "Test User", Avionics
MANAGER = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"   # "Test Manager", Avionics
H = {"Authorization": f"Bearer {create_jwt(AUDITOR, f'did:ethr:13371:{AUDITOR}', 'AUDITOR', 1, client_ip='127.0.0.1')}"}


@pytest.fixture
async def seeded(db_session):
    tag = uuid.uuid4().hex[:8]
    serial = f"FLT-{tag}"
    rows = [
        ("DOCUMENT_VIEWED", USER, "LOW", datetime(2026, 3, 1, 9, 15, tzinfo=UTC)),
        ("DOCUMENT_DOWNLOADED", USER, "MEDIUM", datetime(2026, 3, 2, 23, 30, tzinfo=UTC)),
        ("ACCESS_DENIED_NO_GRANT", USER, "MEDIUM", datetime(2026, 3, 3, 2, 5, tzinfo=UTC)),
        ("PHYSICAL_ASSET_CREATED", MANAGER, "LOW", datetime(2026, 3, 4, 14, 0, tzinfo=UTC)),
        ("DUPLICATE_MAC_ATTEMPT", MANAGER, "HIGH", datetime(2026, 3, 5, 15, 45, tzinfo=UTC)),
    ]
    events = []
    for etype, actor, risk, at in rows:
        e = AuditEvent(event_type=etype, tx_hash=f"0xflt{tag}{etype}", block_number=0, actor_did=f"did:ethr:13371:{actor}",
                       asset_serial=serial, risk_label=risk, created_at=at, updated_at=at)
        db_session.add(e)
        events.append(e)
    await db_session.flush()
    alert = await raise_alert(db_session, events[-1], source="RULE")
    alert.state = "MANAGER_REVIEW"
    await db_session.commit()
    return serial


async def types(client, serial, **params):
    r = await client.get("/api/audit/events", params={"asset_serial": serial, **params}, headers=H)
    assert r.status_code == 200, r.text
    return sorted(e["event_type"] for e in r.json())


@pytest.mark.asyncio
async def test_filters(client, seeded):
    s = seeded
    assert await types(client, s, category="VIEW") == ["DOCUMENT_VIEWED"]
    assert await types(client, s, category="DOWNLOAD") == ["DOCUMENT_DOWNLOADED"]
    assert set(await types(client, s, category="PHYSICAL")) == {"PHYSICAL_ASSET_CREATED", "DUPLICATE_MAC_ATTEMPT"}
    assert set(await types(client, s, category="DIGITAL")) == {"DOCUMENT_VIEWED", "DOCUMENT_DOWNLOADED"}
    assert await types(client, s, event_type="DOCUMENT_VIEWED,PHYSICAL_ASSET_CREATED") == ["DOCUMENT_VIEWED", "PHYSICAL_ASSET_CREATED"]
    assert set(await types(client, s, result="DENIED")) == {"ACCESS_DENIED_NO_GRANT", "DUPLICATE_MAC_ATTEMPT"}
    assert len(await types(client, s, result="SUCCESS")) == 3
    assert await types(client, s, risk_label="HIGH") == ["DUPLICATE_MAC_ATTEMPT"]
    assert set(await types(client, s, role="MANAGER")) == {"PHYSICAL_ASSET_CREATED", "DUPLICATE_MAC_ATTEMPT"}
    assert set(await types(client, s, identity="Test User")) == {"DOCUMENT_VIEWED", "DOCUMENT_DOWNLOADED", "ACCESS_DENIED_NO_GRANT"}
    assert len(await types(client, s, department="Avionics")) == 5
    assert await types(client, s, department="Cyber") == []
    assert len(await types(client, s, actor_did=MANAGER)) == 2
    assert await types(client, s, escalation_state="MANAGER_REVIEW") == ["DUPLICATE_MAC_ATTEMPT"]
    assert await types(client, s, from_date="2026-03-02", to_date="2026-03-03T23:59:59Z") == ["ACCESS_DENIED_NO_GRANT", "DOCUMENT_DOWNLOADED"]
    assert await types(client, s, from_time="09:00", to_time="15:00") == ["DOCUMENT_VIEWED", "PHYSICAL_ASSET_CREATED"]
    # Window across midnight (22:00 - 03:00 UTC)
    assert await types(client, s, from_time="22:00", to_time="03:00") == ["ACCESS_DENIED_NO_GRANT", "DOCUMENT_DOWNLOADED"]


@pytest.mark.asyncio
async def test_invalid_filters_rejected(client):
    for params in ({"from_date": "yesterday"}, {"from_time": "25:99"}, {"category": "NOPE"}, {"result": "MAYBE"}):
        r = await client.get("/api/audit/events", params=params, headers=H)
        assert r.status_code == 400, params


@pytest.mark.asyncio
async def test_filters_never_widen_role_scope(client, seeded):
    """A USER applying filters still sees only their own events."""
    uh = {"Authorization": f"Bearer {create_jwt(USER, f'did:ethr:13371:{USER}', 'USER', 1, client_ip='127.0.0.1')}"}
    r = await client.get("/api/audit/events", params={"asset_serial": seeded, "role": "MANAGER"}, headers=uh)
    assert r.status_code == 200 and r.json() == []
