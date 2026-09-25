"""Protected copies through the real API (spec 23, 24, 29, 48): the watermark names the
actual viewer (never the owner on views), carries the effective client IP and the
backend View ID, and the vault original stays byte-identical."""

import hashlib
import io
import os
import uuid
from unittest.mock import patch

import pytest
from pypdf import PdfReader
from sqlalchemy import select

from app.api.assets import OFFCHAIN_STORAGE_DIR
from app.core.crypto import encrypt_secret
from app.models.domain import AssetAccessGrant, DocumentAction, User
from app.services.auth import create_jwt
from app.services.watermark import short_wallet
from tests.conftest import mfa_headers, totp_secret_for

OWNER = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"     # "Test User"
MANAGER = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"


def tok(wallet, role, v, ip="127.0.0.1"):
    return create_jwt(wallet, f"did:ethr:13371:{wallet}", role, v, client_ip=ip)


def pdf_bytes(marker):
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.drawString(72, 750, marker)
    c.showPage()
    c.save()
    return buf.getvalue()


async def upload_and_approve(client, db, data, filename):
    owner_t = tok(OWNER, "USER", 1)
    up = await client.post("/api/assets/upload-document", headers={"Authorization": f"Bearer {owner_t}"},
                           files={"file": (filename, data, "application/octet-stream")})
    assert up.status_code == 200, up.text
    info = up.json()
    assert info["file_hash"] == hashlib.sha256(data).hexdigest()
    serial = f"PC-{uuid.uuid4().hex[:8]}"
    prop = await client.post("/api/assets/document/propose", headers=await mfa_headers(db, owner_t, OWNER, "document.submit"),
                             json={"name": filename, "serial_number": serial, "file_hash": info["file_hash"],
                                   "offchain_uri": info["offchain_uri"], "recipient_address": OWNER})
    assert prop.status_code == 200, prop.text
    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x1", "data": "0x2"}):
        ok = await client.post(f"/api/assets/document/approval/{prop.json()['action_id']}",
                               headers=await mfa_headers(db, tok(MANAGER, "MANAGER", 8), MANAGER, "asset.approve"), json={"decision": "APPROVE"})
    assert ok.status_code == 200, ok.text
    # Uploads are stored at the vault root as <sha256>_<name> (resolved the same way as the app)
    rel = info["offchain_uri"].replace("secure-vault://", "")
    stored = os.path.join(OFFCHAIN_STORAGE_DIR, rel)
    if not os.path.exists(stored):
        stored = os.path.join(OFFCHAIN_STORAGE_DIR, os.path.basename(rel))
    return serial, stored


async def make_grantee(db, name="Grantee Person"):
    w = "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    u = User(wallet_address=w, did=f"did:ethr:13371:{w}", role="USER", department="Avionics", name=name,
             is_active=True, onboarding_pending=False, session_version=1, is_totp_enabled=True,
             is_totp_factor2_enabled=True, totp_factor2_secret=encrypt_secret(totp_secret_for(w, "factor2")))
    db.add(u)
    await db.commit()
    return u


@pytest.mark.asyncio
async def test_view_watermark_names_viewer_not_owner_and_original_unchanged(client, db_session):
    data = pdf_bytes("TOP SECRET BODY")
    serial, stored = await upload_and_approve(client, db_session, data, "brief.pdf")
    original_sha = hashlib.sha256(open(stored, "rb").read()).hexdigest()
    assert original_sha == hashlib.sha256(data).hexdigest()

    grantee = await make_grantee(db_session)
    await db_session.refresh(grantee)
    from app.models.domain import Asset
    asset = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    db_session.add(AssetAccessGrant(asset_id=asset.id, asset_serial=serial, grantee_did=grantee.did,
                                    granted_by_did=f"did:ethr:13371:{MANAGER}", can_view=True, max_views=1))
    await db_session.commit()

    g_token = tok(grantee.wallet_address, "USER", 1, ip="203.0.113.77")
    h = await mfa_headers(db_session, g_token, grantee.wallet_address, "document.view")
    h["X-Forwarded-For"] = "203.0.113.77"
    r = await client.get(f"/api/assets/document/view/{serial}", headers=h)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    vw = r.headers["x-lexcorp-action-id"]
    text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(r.content)).pages)
    assert "TOP SECRET BODY" in text
    assert "Viewed by: Grantee Person" in text
    assert f"Wallet: {short_wallet(grantee.wallet_address)}" in text and grantee.wallet_address not in text
    assert "IP: 203.0.113.77" in text and f"View ID: {vw}" in text
    owner = (await db_session.execute(select(User).where(User.wallet_address == OWNER))).scalar_one()
    assert (owner.name or "Test User") not in text and short_wallet(OWNER) not in text  # owner never on a view

    rec = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == vw))).scalar_one()
    assert rec.client_ip == "203.0.113.77" and "Viewed by: Grantee Person" in rec.watermark_text

    # Owner's own view names the owner; the vault original is still byte-identical
    oh = await mfa_headers(db_session, tok(OWNER, "USER", 1), OWNER, "document.view")
    r2 = await client.get(f"/api/assets/document/view/{serial}", headers=oh)
    assert r2.status_code == 200
    assert hashlib.sha256(open(stored, "rb").read()).hexdigest() == original_sha


@pytest.mark.asyncio
async def test_unsupported_type_refused_without_consuming_view(client, db_session):
    serial, stored = await upload_and_approve(client, db_session, b"MZ\x90\x00 not a document", "tool.exe")
    grantee = await make_grantee(db_session, "Limited Viewer")
    grantee_did, grantee_wallet = grantee.did, grantee.wallet_address
    from app.models.domain import Asset
    asset = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    db_session.add(AssetAccessGrant(asset_id=asset.id, asset_serial=serial, grantee_did=grantee.did,
                                    granted_by_did=f"did:ethr:13371:{MANAGER}", can_view=True, max_views=1))
    await db_session.commit()
    h = await mfa_headers(db_session, tok(grantee_wallet, "USER", 1), grantee_wallet, "document.view")
    r = await client.get(f"/api/assets/document/view/{serial}", headers=h)
    assert r.status_code == 415
    g = (await db_session.execute(select(AssetAccessGrant).where(AssetAccessGrant.grantee_did == grantee_did))).scalar_one()
    await db_session.refresh(g)
    assert g.views_count == 0
