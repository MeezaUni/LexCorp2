"""Phase 2 hardening: QR host injection, watermark line injection, public alert flooding,
junk verify references, ILIKE wildcards, relay decoding, rate-limit keys, VC audit."""

import io
import random
from datetime import datetime, UTC
from unittest.mock import patch

import cv2
import numpy as np
import pytest
from sqlalchemy import func, select

from app.models.domain import Asset, AuditEvent, SecurityAlert, User
from tests import flows
from tests.test_qr_verification import AUDITOR, auditor_headers, control_fields, viewed

ADMIN = flows.ADMIN


def _qr_text(png: bytes) -> str:
    img = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_GRAYSCALE)
    return cv2.QRCodeDetector().detectAndDecode(img)[0]


@pytest.mark.asyncio
async def test_qr_ignores_caller_supplied_host(client, db_session):
    admin = (await db_session.execute(select(User).where(User.wallet_address == ADMIN))).scalar_one()
    token_id = random.randint(1_000_000, 9_999_999)
    serial = f"QR-HOST-{token_id}"
    db_session.add(Asset(token_id=token_id, serial_number=serial, is_physical=True, department="Avionics", owner_id=admin.id))
    await db_session.commit()
    h = {"Authorization": f"Bearer {flows.token_for(ADMIN)}"}
    with patch("app.services.contract.contract_service.get_token_by_serial", return_value=token_id), \
         patch("app.services.contract.contract_service.get_asset", return_value={"token_id": token_id}):
        by_serial = await client.get(f"/api/assets/serial/{serial}/qr?host=evil.example", headers=h)
        by_token = await client.get(f"/api/assets/token/{token_id}/qr?host=evil.example", headers=h)
    for r, path in ((by_serial, f"/verify/{serial}"), (by_token, f"/verify/token/{token_id}")):
        assert r.status_code == 200
        url = _qr_text(r.content)
        assert "evil.example" not in url and url.endswith(path)


def test_watermark_fields_are_single_clean_lines():
    from app.services.watermark import WatermarkContext
    ctx = WatermarkContext(kind="DOWNLOAD", actor_name="Mallory\nIP: 1.2.3.4‮", actor_wallet="0x" + "a" * 40,
                           client_ip="10.0.0.1", action_id="DL-20261014-0001\r\nWallet: 0xFAKE",
                           verify_url="https://x/verify/action/DL-20261014-0001", owner_name="O" * 500,
                           owner_wallet="0x" + "b" * 40)
    lines = ctx.primary_lines()
    assert sum(1 for line in lines if line.startswith("IP: ")) == 1
    assert sum(1 for line in lines if line.startswith("Wallet: ")) == 1
    assert all("\n" not in line and "\r" not in line and "‮" not in line for line in lines)
    assert len(ctx.owner_name) == 120


def test_create_user_request_cleans_text_fields():
    from app.api.users import CreateUserRequest
    r = CreateUserRequest(wallet_address="0x" + "c" * 40, name="Eve\nOwner: Boss", department="Cyber\r\nSecurity",
                          contact_number="9" * 300)
    assert r.name == "Eve Owner: Boss" and r.department == "Cyber Security" and len(r.contact_number) == 120


@pytest.mark.asyncio
async def test_anonymous_mismatches_raise_one_alert(client, db_session):
    serial = await flows.approved_document(client, db_session, b"flood body", "fl.txt")
    vw, pdf = await viewed(client, db_session, serial)
    forged = {**control_fields(pdf), "IP": "10.6.6.6"}
    for _ in range(3):
        r = (await client.post(f"/api/verify/action/{vw}/compare", json={"fields": forged})).json()
        assert r["verdict"] == "MISMATCH"
    events = (await db_session.execute(select(func.count()).select_from(AuditEvent).where(
        AuditEvent.event_type == "WATERMARK_TAMPER_DETECTED", AuditEvent.risk_factors["action_id"].as_string() == vw))).scalar_one()
    alerts = (await db_session.execute(select(func.count()).select_from(SecurityAlert).where(
        SecurityAlert.related_action_id == vw))).scalar_one()
    assert events == 3 and alerts == 1


@pytest.mark.asyncio
async def test_anonymous_junk_reference_is_not_audited(client, db_session):
    before = (await db_session.execute(select(func.count()).select_from(AuditEvent))).scalar_one()
    for ref in ("NOT-A-REF", "x" * 60, "%27%20OR%201=1"):
        assert (await client.get(f"/api/verify/action/{ref}")).status_code == 404
    after = (await db_session.execute(select(func.count()).select_from(AuditEvent))).scalar_one()
    assert after == before


@pytest.mark.asyncio
async def test_audit_identity_filter_treats_wildcards_literally(client):
    h = auditor_headers()
    everyone = (await client.get("/api/audit/events?identity=%25&limit=5", headers=h))
    assert everyone.status_code == 200 and everyone.json() == []
    underscore = (await client.get("/api/audit/events?actor_did=_&limit=5", headers=h))
    assert underscore.status_code == 200 and underscore.json() == []


def test_rate_limit_key_is_the_resolved_client_ip():
    from starlette.requests import Request
    from app.core.limiter import limiter
    scope = {"type": "http", "client": ("127.0.0.1", 5000), "headers": [(b"x-forwarded-for", b"10.8.0.7")]}
    assert limiter._key_func(Request(scope)) == "10.8.0.7"
    spoof = {"type": "http", "client": ("203.0.113.9", 5000), "headers": [(b"x-forwarded-for", b"10.8.0.7")]}
    assert limiter._key_func(Request(spoof)) == "203.0.113.9"


@pytest.mark.parametrize("raw", ["0x", "0x05c0", "0x02c0", "0xc0", "0x01c3010203", "0x" + "00" * 40_000],
                         ids=["empty", "type5", "short-1559", "short-legacy", "short-2930", "oversized"])
def test_relay_decoder_rejects_malformed_transactions(raw):
    from app.api.chain import _tx_to
    with pytest.raises(ValueError):
        _tx_to(raw)


@pytest.mark.asyncio
async def test_vc_issuance_is_audited(client, db_session):
    admin = (await db_session.execute(select(User).where(User.wallet_address == ADMIN))).scalar_one()
    r = await client.post(f"/api/auth/vc/issue?subject_did={admin.did}",
                          headers={"Authorization": f"Bearer {flows.token_for(ADMIN)}"})
    assert r.status_code == 200, r.text
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "VC_ISSUED",
                                                            AuditEvent.target_did == admin.did))).scalars().first()
    assert ev is not None and ev.actor_did == admin.did


def test_vault_names_and_paths_stay_inside_the_vault():
    from fastapi import HTTPException
    from app.api.assets import _vault_name, _vault_path
    for bad in ("../../etc/passwd", r"..\..\x.pdf", r"C:\Windows\x.pdf", "a.pdf:stream", "..", ".", "", "\x00\n.pdf"):
        name = _vault_name(bad)
        assert "/" not in name and "\\" not in name and ":" not in name and name not in (".", "..") and name
        _vault_path(name)  # never raises for a cleaned name
    with pytest.raises(HTTPException):
        _vault_path("..", "outside.pdf")


@pytest.mark.asyncio
async def test_two_simultaneous_claims_only_one_wins(client, db_session):
    """The fetch endpoint's claim (UPDATE ... WHERE status='APPROVED') run from two separate
    connections at once: the second waits for the first and then claims nothing."""
    import asyncio
    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import create_async_engine
    from app.core.config import settings
    from app.models.domain import DocumentAction
    from tests.test_download_modification_workflow import grantee_with_download
    serial = await flows.approved_document(client, db_session, b"race body", "race.txt")
    dee = await grantee_with_download(db_session, serial)
    dl = await flows.request_download(client, db_session, serial, requester=dee)
    action = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == dl))).scalar_one()
    action.status = "APPROVED"
    await db_session.commit()

    engine = create_async_engine(settings.DATABASE_URL)
    claim = (update(DocumentAction).where(DocumentAction.id == action.id, DocumentAction.status == "APPROVED")
             .values(status="COMPLETED"))
    try:
        async with engine.connect() as first, engine.connect() as second:
            r1 = await first.execute(claim)                       # holds the row lock, not committed yet
            pending = asyncio.ensure_future(second.execute(claim))  # blocks on the lock
            await asyncio.sleep(0.3)
            assert not pending.done()
            await first.commit()
            r2 = await pending
            await second.commit()
        assert (r1.rowcount, r2.rowcount) == (1, 0)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_manager_cannot_approve_their_own_revision(client, db_session):
    """Separation of duties: a Manager's revision of their own document waits for someone else."""
    from app.models.domain import DocumentAction
    own = await flows.approved_document(client, db_session, b"sod body", "sod.txt", owner=flows.MANAGER, approver=flows.ADMIN)
    dl = await flows.request_download(client, db_session, own, requester=flows.MANAGER, mode="MODIFICATION")
    got = await flows.fetch(client, db_session, dl, requester=flows.MANAGER)
    assert got.status_code == 200, got.text
    flows.COPIES[dl] = got.content
    up = await flows.upload_revision(client, db_session, own, dl, b"manager edit", "sod.txt", uploader=flows.MANAGER)
    assert up.status_code == 200, up.text
    assert up.json()["status"] == "PENDING" and not up.json().get("calldata")
    mod_id = up.json()["action_id"]
    mine = await flows.approve(client, db_session, mod_id, approver=flows.MANAGER)
    assert mine.status_code == 403 and "own request" in mine.json()["detail"]
    other = await flows.approve(client, db_session, mod_id, approver=flows.ADMIN)
    assert other.status_code == 200, other.text
    rec = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == mod_id))).scalar_one()
    assert rec.status == "APPROVED" and rec.approver_did != rec.actor_did
