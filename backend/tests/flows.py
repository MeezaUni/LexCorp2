"""Reusable end-to-end steps through the real API (no bypasses): every step presents
the purpose-specific factor its action requires."""

import os
import uuid
from unittest.mock import patch

from app.services.auth import create_jwt
from tests.conftest import mfa_headers

USER = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
MANAGER = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"
ADMIN = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
_ROLE = {USER: ("USER", 1), MANAGER: ("MANAGER", 8), ADMIN: ("ADMIN", 5)}


def token_for(wallet, role=None, version=None, ip="127.0.0.1"):
    r, v = _ROLE.get(wallet, ("USER", 1))
    return create_jwt(wallet, f"did:ethr:13371:{wallet}", role or r, v if version is None else version, client_ip=ip)


async def approve(client, db, action_id, approver=MANAGER, **body):
    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x1", "data": "0x2"}), \
         patch("app.services.contract.contract_service.prepare_update_digital_asset_calldata", return_value={"to": "0x1", "data": "0x3"}):
        return await client.post(f"/api/assets/document/approval/{action_id}",
                                 headers=await mfa_headers(db, token_for(approver), approver, "asset.approve"),
                                 json={"decision": "APPROVE", **body})


async def approved_document(client, db, content: bytes, filename: str, owner=USER, approver=MANAGER):
    """Upload -> propose (Factor 2) -> approve (Factor 3). Returns the serial."""
    t = token_for(owner)
    up = await client.post("/api/assets/upload-document", headers={"Authorization": f"Bearer {t}"},
                           files={"file": (filename, content, "application/octet-stream")})
    assert up.status_code == 200, up.text
    info = up.json()
    serial = f"FLOW-{uuid.uuid4().hex[:8]}"
    direct = owner in (MANAGER, ADMIN)  # Managers/Admins register and record directly
    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x1", "data": "0x2"}):
        prop = await client.post("/api/assets/document/propose",
                                 headers=await mfa_headers(db, t, owner, "asset.mint" if direct else "document.submit"),
                                 json={"name": filename, "serial_number": serial, "file_hash": info["file_hash"],
                                       "offchain_uri": info["offchain_uri"], "recipient_address": owner})
    assert prop.status_code == 200, prop.text
    if direct:
        assert prop.json()["status"] == "APPROVED" and prop.json()["calldata"]
        return serial
    r = await approve(client, db, prop.json()["action_id"], approver)
    assert r.status_code == 200, r.text
    return serial


async def request_download(client, db, serial, requester=USER, mode="STANDARD"):
    r = await client.post("/api/assets/document/download/request",
                          headers=await mfa_headers(db, token_for(requester), requester, "download.request"),
                          json={"asset_serial": serial, "purpose": "flow", "mode": mode})
    assert r.status_code == 200, r.text
    return r.json()["action_id"]


async def owner_consent(client, db, dl_id, owner=USER):
    """The document's owner consents (Factor 3) to someone else's download request."""
    r = await client.post(f"/api/assets/document/download/{dl_id}/owner-approval",
                          headers=await mfa_headers(db, token_for(owner), owner, "asset.approve"), json={"decision": "APPROVE"})
    assert r.status_code == 200, r.text
    return r


async def owner_download(client, db, serial, owner=USER):
    """The owner's own watermarked copy: Factor 3, no approval, new Download ID."""
    return await client.post(f"/api/assets/document/{serial}/owner-download",
                             headers=await mfa_headers(db, token_for(owner), owner, "document.download"))


async def fetch(client, db, dl_id, requester=USER):
    return await client.post(f"/api/assets/document/download/{dl_id}/fetch",
                             headers=await mfa_headers(db, token_for(requester), requester, "document.download"), json={})


# Modification copies fetched in this test session, by Download ID: a revision is made the way a
# person makes one, by editing the watermarked copy they were given.
COPIES: dict = {}
LAST_UPLOAD: dict = {}


async def modification_download(client, db, serial, requester=USER, approver=MANAGER):
    """Request (MODIFICATION) -> approve -> fetch. Returns (dl_id, fetched response)."""
    dl = await request_download(client, db, serial, requester, mode="MODIFICATION")
    r = await approve(client, db, dl, approver)
    assert r.status_code == 200, r.text
    got = await fetch(client, db, dl, requester)
    assert got.status_code == 200, got.text
    COPIES[dl] = got.content
    return dl, got


def edited_copy(copy_pdf: bytes, new_text: bytes) -> bytes:
    """The watermarked PDF copy with one page of new content added (the watermark, QR and
    Document Control page stay as issued)."""
    import io
    from pypdf import PdfReader, PdfWriter
    from reportlab.pdfgen import canvas
    page = io.BytesIO()
    c = canvas.Canvas(page)
    y = 780
    for line in new_text.decode("utf-8", "replace").splitlines() or [""]:
        c.drawString(72, y, line)
        y -= 16
    c.save()
    writer = PdfWriter()
    for p in PdfReader(io.BytesIO(copy_pdf)).pages:
        writer.add_page(p)
    writer.add_page(PdfReader(io.BytesIO(page.getvalue())).pages[0])
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


async def upload_revision(client, db, parent_serial, dl_id, content: bytes, filename: str, uploader=USER, raw=False):
    """Upload a revision. By default the file is the modification copy of `dl_id` with `content`
    added; raw=True uploads `content` exactly as given (to test refusals)."""
    if not raw and dl_id in COPIES:
        content = edited_copy(COPIES[dl_id], content)
        filename = os.path.splitext(filename)[0] + ".pdf"
    LAST_UPLOAD[dl_id] = content
    return await client.post(
        "/api/assets/document/revise/upload",
        headers=await mfa_headers(db, token_for(uploader), uploader, "document.modify"),
        files={"file": (filename, content, "application/octet-stream")},
        data={"parent_asset_serial": parent_serial, "modification_download_id": dl_id, "purpose": "edit"},
    )
