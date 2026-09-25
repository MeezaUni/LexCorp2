"""Digital QR verification and tamper detection (spec 31, 46, 62)."""

import io

import pytest
from pypdf import PdfReader
from sqlalchemy import select

from app.models.domain import AuditEvent, User
from tests import flows
from tests.conftest import mfa_headers


async def viewed(client, db, serial, viewer=flows.USER):
    r = await client.get(f"/api/assets/document/view/{serial}",
                         headers=await mfa_headers(db, flows.token_for(viewer), viewer, "document.view"))
    assert r.status_code == 200, r.text
    return r.headers["x-lexcorp-action-id"], r.content


def control_fields(pdf: bytes) -> dict:
    text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf)).pages)
    block = text[text.index("LexCorp Document Control"):]
    out = {}
    for line in block.splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            out.setdefault(k.strip(), v.strip())
    return {k: out[k] for k in ("Viewed by", "Wallet", "IP", "Date", "View ID") if k in out}


@pytest.mark.asyncio
async def test_public_qr_resolution_is_minimal(client, db_session):
    serial = await flows.approved_document(client, db_session, b"qr body", "q.txt")
    vw, _ = await viewed(client, db_session, serial)
    client.cookies.clear()
    r = await client.get(f"/api/verify/action/{vw}")
    assert r.status_code == 200
    data = r.json()
    assert data["valid"] is True and data["detail_level"] == "PUBLIC" and data["action_type"] == "VIEW"
    assert data["document_version"] == 1 and data["is_latest_approved_version"] is True
    for hidden in ("creator", "creator_wallet", "action_client_ip", "recorded_watermark", "modification_trail", "asset_serial"):
        assert hidden not in data


@pytest.mark.asyncio
async def test_invalid_and_unknown_references_rejected(client):
    for ref in ("not-an-id", "VW-2026", "DL-20260101-0001x", "../../etc/passwd"):
        assert (await client.get(f"/api/verify/action/{ref}")).status_code == 404
    assert (await client.get("/api/verify/action/VW-19990101-0001")).status_code == 404


@pytest.mark.asyncio
async def test_authorized_detail_trail_and_ip_scoping(client, db_session):
    serial = await flows.approved_document(client, db_session, b"trail v1", "t.txt")
    dl, _ = await flows.modification_download(client, db_session, serial)
    rev = await flows.upload_revision(client, db_session, serial, dl, b"trail v2", "t.txt")
    mod = rev.json()["action_id"]
    await flows.approve(client, db_session, mod)
    vw, _ = await viewed(client, db_session, rev.json()["asset_serial"])

    owner = (await client.get(f"/api/verify/action/{vw}", headers={"Authorization": f"Bearer {flows.token_for(flows.USER)}"})).json()
    assert owner["detail_level"] == "AUTHORIZED"
    assert owner["creation_id"].startswith("CRT-") and owner["creator_wallet"] == flows.USER
    assert [m["modification_id"] for m in owner["modification_trail"]] == [mod]
    assert owner["modification_trail"][0]["modifier_wallet"] == flows.USER and owner["modification_trail"][0]["download_id"] == dl
    assert [v["version"] for v in owner["versions"]] == [1, 2]
    assert "action_client_ip" not in owner  # IP only for Admin/Auditor/in-scope Manager
    mgr = (await client.get(f"/api/verify/action/{vw}", headers={"Authorization": f"Bearer {flows.token_for(flows.MANAGER)}"})).json()
    assert mgr["action_client_ip"] == "127.0.0.1"
    # An invalid session is treated as anonymous: public view only
    anon = (await client.get(f"/api/verify/action/{vw}", headers={"Authorization": "Bearer garbage"})).json()
    assert anon["detail_level"] == "PUBLIC"


@pytest.mark.asyncio
async def test_tampered_watermark_fields_detected_and_audited(client, db_session):
    serial = await flows.approved_document(client, db_session, b"tamper body", "tb.txt")
    vw, pdf = await viewed(client, db_session, serial)
    fields = control_fields(pdf)
    assert set(fields) == {"Viewed by", "Wallet", "IP", "Date", "View ID"}

    ok = (await client.post(f"/api/verify/action/{vw}/compare", json={"fields": fields})).json()
    assert ok["verdict"] == "MATCH" and ok["fields_checked"] == 5

    forged = {**fields, "Viewed by": "Someone Else", "IP": "10.0.0.99"}
    bad = (await client.post(f"/api/verify/action/{vw}/compare", json={"fields": forged})).json()
    assert bad["verdict"] == "MISMATCH" and set(bad["mismatches"]) == {"Viewed by", "IP"}
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "WATERMARK_TAMPER_DETECTED"))).scalars().all()
    assert any(e.risk_factors.get("action_id") == vw for e in ev)

    wrong_ctx = (await client.post(f"/api/verify/action/{vw}/compare",
                                   json={"fields": fields, "asset_serial": "SOMETHING-ELSE", "version": 7})).json()
    assert set(wrong_ctx["mismatches"]) == {"asset_serial", "version"}


@pytest.mark.asyncio
async def test_compare_uploaded_copy(client, db_session):
    serial = await flows.approved_document(client, db_session, b"file compare body", "fc.txt")
    vw, pdf = await viewed(client, db_session, serial)
    genuine = await client.post(f"/api/verify/action/{vw}/compare-file", files={"file": ("copy.pdf", pdf, "application/pdf")})
    assert genuine.json()["verdict"] == "MATCH"

    # A doctored copy: same layout, but the viewer's name and wallet were edited
    fields = control_fields(pdf)
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    y = 800
    for line in ["LexCorp Document Control", "CONFIDENTIAL", "Viewed by: Innocent Person", "Wallet: 0x0000...0000",
                 f"IP: {fields['IP']}", f"Date: {fields['Date']}", f"View ID: {vw}"]:
        c.drawString(40, y, line)
        y -= 14
    c.showPage()
    c.save()
    doctored = await client.post(f"/api/verify/action/{vw}/compare-file", files={"file": ("copy.pdf", buf.getvalue(), "application/pdf")})
    body = doctored.json()
    assert body["verdict"] == "MISMATCH" and set(body["mismatches"]) == {"Viewed by", "Wallet"}
