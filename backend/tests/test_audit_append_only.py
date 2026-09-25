"""Audit history is append-only at the database level (not only by API convention)."""

import uuid

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError

from app.models.domain import AuditEvent, SecurityAlert, SecurityAlertAction
from app.services.auth import create_jwt


async def _event(db, label="LOW"):
    ev = AuditEvent(event_type="APPEND_ONLY_PROBE", tx_hash="0x" + uuid.uuid4().hex * 2, block_number=0,
                    risk_label=label, risk_factors={"probe": True})
    db.add(ev)
    await db.commit()
    return ev


@pytest.mark.asyncio
async def test_audit_rows_cannot_be_deleted(db_session):
    ev_id = (await _event(db_session)).id
    with pytest.raises(DBAPIError, match="append-only"):
        await db_session.execute(delete(AuditEvent).where(AuditEvent.id == ev_id))
    await db_session.rollback()
    assert (await db_session.execute(select(AuditEvent).where(AuditEvent.id == ev_id))).scalar_one()


@pytest.mark.asyncio
async def test_audit_rows_cannot_be_modified(db_session):
    ev = await _event(db_session)
    with pytest.raises(DBAPIError, match="append-only"):
        await db_session.execute(update(AuditEvent).where(AuditEvent.id == ev.id).values(risk_label="LOW", actor_did="did:forged"))
    await db_session.rollback()


@pytest.mark.asyncio
async def test_audit_table_cannot_be_truncated(db_session):
    with pytest.raises(DBAPIError, match="append-only"):
        await db_session.execute(text("TRUNCATE audit_events CASCADE"))
    await db_session.rollback()


@pytest.mark.asyncio
async def test_alert_history_cannot_be_rewritten(db_session):
    ev = await _event(db_session, "HIGH")
    from app.services.alerts import raise_alert
    alert_id = (await raise_alert(db_session, ev, source="RULE")).id
    await db_session.commit()
    with pytest.raises(DBAPIError, match="append-only"):
        await db_session.execute(delete(SecurityAlertAction).where(SecurityAlertAction.alert_id == alert_id))
    await db_session.rollback()
    row = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.id == alert_id))).scalar_one()
    row.state = "DISMISSED"  # the alert's current state may change; its history may not
    await db_session.commit()


@pytest.mark.asyncio
async def test_no_api_route_deletes_audit_history(client):
    from app.main import app
    for route in app.routes:
        methods = getattr(route, "methods", set()) or set()
        path = getattr(route, "path", "")
        if path.startswith("/api/audit"):
            assert "DELETE" not in methods, path
    token = create_jwt("0x95ea9708bcf136d710a4b8e76fe20f895eca003a",
                       "did:ethr:13371:0x95ea9708bcf136d710a4b8e76fe20f895eca003a", "ADMIN", 5, client_ip="127.0.0.1")
    r = await client.patch(f"/api/audit/alerts/{uuid.uuid4()}/status", headers={"Authorization": f"Bearer {token}"},
                           json={"alert_status": "DISMISSED"})
    assert r.status_code == 410
