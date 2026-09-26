"""Controlled download and modification/revision workflow (spec 24-29, 57, 61)."""

import hashlib
import io
import os
import uuid
from datetime import datetime, timedelta, UTC
from unittest.mock import patch

import pytest
from pypdf import PdfReader
from sqlalchemy import select

from app.api.assets import OFFCHAIN_STORAGE_DIR
from app.core.crypto import encrypt_secret
from app.models.domain import Asset, AssetAccessGrant, DocumentAction, User
from app.services.watermark import short_wallet
from tests import flows
from tests.conftest import mfa_headers, totp_secret_for


def pdf_text(content: bytes) -> str:
    return "".join(p.extract_text() for p in PdfReader(io.BytesIO(content)).pages)


async def grantee_with_download(db, serial):
    w = "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    u = User(wallet_address=w, did=f"did:ethr:13371:{w}", role="USER", department="Avionics", name="Downloader Dee",
             is_active=True, onboarding_pending=False, session_version=1, is_totp_enabled=True,
             is_totp_factor2_enabled=True, is_totp_factor3_enabled=True,
             totp_factor2_secret=encrypt_secret(totp_secret_for(w, "factor2")),
             totp_factor3_secret=encrypt_secret(totp_secret_for(w, "factor3")))
    db.add(u)
    asset = (await db.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    db.add(AssetAccessGrant(asset_id=asset.id, asset_serial=serial, grantee_did=u.did, granted_by_did="did:x",
                            can_view=True, can_download=True))
    await db.commit()
    return w


@pytest.mark.asyncio
async def test_non_owner_download_needs_owner_consent_then_manager(client, db_session):
    serial = await flows.approved_document(client, db_session, b"owner consent body", "c.txt")
    dee = await grantee_with_download(db_session, serial)
    dl = await flows.request_download(client, db_session, serial, requester=dee)

    early = await flows.approve(client, db_session, dl)
    assert early.status_code == 409 and "owner" in early.json()["detail"].lower()
    # Only the owner may consent, with Factor 3
    not_owner = await client.post(f"/api/assets/document/download/{dl}/owner-approval",
                                  headers=await mfa_headers(db_session, flows.token_for(flows.MANAGER), flows.MANAGER, "asset.approve"),
                                  json={"decision": "APPROVE"})
    assert not_owner.status_code == 404
    no_factor = await client.post(f"/api/assets/document/download/{dl}/owner-approval",
                                  headers={"Authorization": f"Bearer {flows.token_for(flows.USER)}"}, json={"decision": "APPROVE"})
    assert no_factor.status_code == 401
    ok = await client.post(f"/api/assets/document/download/{dl}/owner-approval",
                           headers=await mfa_headers(db_session, flows.token_for(flows.USER), flows.USER, "asset.approve"),
                           json={"decision": "APPROVE"})
    assert ok.status_code == 200 and ok.json()["owner_approved"] is True
    assert (await flows.approve(client, db_session, dl)).status_code == 200
    got = await flows.fetch(client, db_session, dl, requester=dee)
    assert got.status_code == 200
    text = pdf_text(got.content)
    assert "Downloaded by: Downloader Dee" in text and f"Download ID: {dl}" in text
    owner = (await db_session.execute(select(User).where(User.wallet_address == flows.USER))).scalar_one()
    assert f"({short_wallet(owner.wallet_address)})" in text  # owner shown on DOWNLOAD watermark


@pytest.mark.asyncio
async def test_download_cannot_bypass_approval_or_expiry(client, db_session):
    serial = await flows.approved_document(client, db_session, b"expiry body", "e.txt")
    dee = await grantee_with_download(db_session, serial)
    dl = await flows.request_download(client, db_session, serial, requester=dee)
    assert (await flows.fetch(client, db_session, dl, requester=dee)).status_code == 403
    await flows.owner_consent(client, db_session, dl)
    assert (await flows.fetch(client, db_session, dl, requester=dee)).status_code == 403  # consent alone is not approval
    assert (await flows.approve(client, db_session, dl)).status_code == 200
    action = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == dl))).scalar_one()
    action.token_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    assert (await flows.fetch(client, db_session, dl, requester=dee)).status_code == 410


@pytest.mark.asyncio
async def test_owner_downloads_own_copy_directly_watermarked(client, db_session):
    """The owner never requests their own download (refused) and needs no approval: Factor 3
    gives a new DL ID and a copy watermarked with their name; the vault original is unchanged."""
    body = b"owner direct body"
    serial = await flows.approved_document(client, db_session, body, "o.txt")
    refused = await client.post("/api/assets/document/download/request",
                                headers=await mfa_headers(db_session, flows.token_for(flows.USER), flows.USER, "download.request"),
                                json={"asset_serial": serial, "purpose": "mine", "mode": "STANDARD"})
    assert refused.status_code == 409
    no_factor = await client.post(f"/api/assets/document/{serial}/owner-download",
                                  headers={"Authorization": f"Bearer {flows.token_for(flows.USER)}"})
    assert no_factor.status_code == 401
    # Only the owner: a Manager in scope still goes through the request flow
    not_owner = await flows.owner_download(client, db_session, serial, owner=flows.MANAGER)
    assert not_owner.status_code == 403
    got = await flows.owner_download(client, db_session, serial)
    assert got.status_code == 200, got.text
    dl = got.headers["x-lexcorp-action-id"]
    assert dl.startswith("DL-")
    text = pdf_text(got.content)
    assert "owner direct body" in text and f"Download ID: {dl}" in text and "Downloaded by:" in text
    rec = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == dl))).scalar_one()
    assert rec.status == "COMPLETED" and rec.details.get("owner_direct") is True
    asset = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    stored = [f for f in os.listdir(OFFCHAIN_STORAGE_DIR) if f.startswith(asset.file_hash)]
    assert stored and hashlib.sha256(open(os.path.join(OFFCHAIN_STORAGE_DIR, stored[0]), "rb").read()).hexdigest() == asset.file_hash


@pytest.mark.asyncio
async def test_rejected_or_pending_documents_not_downloadable(client, db_session):
    serial = await flows.approved_document(client, db_session, b"state body", "s.txt")
    a = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    a.approval_status = "PENDING_APPROVAL"
    await db_session.commit()
    r = await client.post("/api/assets/document/download/request",
                          headers=await mfa_headers(db_session, flows.token_for(flows.USER), flows.USER, "download.request"),
                          json={"asset_serial": serial, "purpose": "x"})
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_delegated_user_revision_cycle_owner_consent_approval_and_integrity(client, db_session):
    """A delegated user asks for a modification copy: the owner (a normal user) consents, a
    Manager approves, the copy is fetched once. A returned copy whose watermark was altered is
    accepted SILENTLY as pending (the uploader is told nothing) but raises an alert carrying the
    recorded watermark, the findings (with page) and the uploaded file; the revision can't be
    approved until the alert is closed."""
    from app.models.domain import SecurityAlert
    from app.services.watermark import WatermarkContext, render_protected_copy
    serial = await flows.approved_document(client, db_session, b"mod rights body", "m.txt")
    dee = await grantee_with_download(db_session, serial)
    r = await client.post("/api/assets/document/download/request",
                          headers=await mfa_headers(db_session, flows.token_for(dee), dee, "download.request"),
                          json={"asset_serial": serial, "purpose": "fix typos", "mode": "MODIFICATION"})
    assert r.status_code == 200, r.text
    dl = r.json()["action_id"]
    assert r.json()["status"] == "PENDING" and r.json()["details"]["requires_owner_approval"] is True
    assert (await flows.approve(client, db_session, dl)).status_code == 409  # the owner consents first
    await flows.owner_consent(client, db_session, dl)
    assert (await flows.approve(client, db_session, dl)).status_code == 200
    got = await flows.fetch(client, db_session, dl, requester=dee)
    assert got.status_code == 200
    assert (await flows.fetch(client, db_session, dl, requester=dee)).status_code == 409  # once only

    # Same Download ID and QR, but the watermark's IP was changed
    forged_ctx = WatermarkContext(kind="DOWNLOAD", actor_name="Downloader Dee", actor_wallet=dee, client_ip="203.0.113.99",
                                  action_id=dl, verify_url=f"http://localhost:5173/verify/action/{dl}")
    forged, _, _ = render_protected_copy(b"mod rights body, fixed typos", "x.txt", forged_ctx)
    up = await flows.upload_revision(client, db_session, serial, dl, forged, "m.pdf", uploader=dee, raw=True)
    assert up.status_code == 200, up.text
    mod = up.json()
    assert mod["status"] == "PENDING" and "findings" not in str(mod) and "tamper" not in str(mod).lower()  # silent

    alert = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.related_action_id == mod["action_id"]))).scalar_one()
    assert alert.event_type == "WATERMARK_TAMPER_DETECTED" and alert.risk_level == "HIGH" and alert.subject_did.endswith(dee)
    auditor = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
    t_aud = flows.token_for(auditor, role="AUDITOR", version=1)
    detail = (await client.get(f"/api/alerts/{alert.alert_id}", headers={"Authorization": f"Bearer {t_aud}"})).json()
    ev = detail["evidence"]
    assert ev["download_id"] == dl and "IP: " in ev["recorded_watermark"] and ev["has_file"] is True
    assert any(f["severity"] == "tamper" and f.get("page") == 1 for f in ev["findings"])  # located on page 1
    view = await client.get(f"/api/alerts/{alert.alert_id}/evidence", headers={"Authorization": f"Bearer {t_aud}"})
    assert view.status_code == 200 and view.headers["content-type"] == "application/pdf"
    assert "203.0.113.99" in pdf_text(view.content)  # the file exactly as uploaded
    # A normal user can't see it
    assert (await client.get(f"/api/alerts/{alert.alert_id}/evidence",
                             headers={"Authorization": f"Bearer {flows.token_for(dee)}"})).status_code == 403

    blocked = await flows.approve(client, db_session, mod["action_id"])
    assert blocked.status_code == 409 and alert.alert_id in blocked.json()["detail"]
    dismissed = await client.post(f"/api/alerts/{alert.alert_id}/dismiss", headers={"Authorization": f"Bearer {t_aud}"},
                                  json={"note": "checked with the uploader"})
    assert dismissed.status_code == 200, dismissed.text
    assert (await flows.approve(client, db_session, mod["action_id"])).status_code == 200
    v2 = (await db_session.execute(select(Asset).where(Asset.serial_number == mod["asset_serial"]))).scalar_one()
    root = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    assert v2.version_number == 2 and v2.owner_id == root.owner_id


@pytest.mark.asyncio
async def test_returned_copy_without_watermark_is_flagged_silently(client, db_session):
    from app.models.domain import SecurityAlert
    serial = await flows.approved_document(client, db_session, b"strip body", "s.txt")
    dl, _ = await flows.modification_download(client, db_session, serial)
    up = await flows.upload_revision(client, db_session, serial, dl, b"edited text with the watermark stripped", "s.txt", raw=True)
    assert up.status_code == 200
    alert = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.related_action_id == up.json()["action_id"]))).scalar_one()
    assert alert.event_type == "WATERMARK_TAMPER_DETECTED"


@pytest.mark.asyncio
async def test_privileged_owner_consent_is_the_approval(client, db_session):
    """When the owner is a Manager/Admin, their consent approves a delegated user's request."""
    serial = await flows.approved_document(client, db_session, b"admin owned body", "a.txt", owner=flows.ADMIN, approver=flows.MANAGER)
    dee = await grantee_with_download(db_session, serial)
    dl = await flows.request_download(client, db_session, serial, requester=dee, mode="MODIFICATION")
    await flows.owner_consent(client, db_session, dl, owner=flows.ADMIN)
    rec = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == dl))).scalar_one()
    assert rec.status == "APPROVED"


@pytest.mark.asyncio
async def test_delegation_can_share_selected_versions(client, db_session):
    serial = await flows.approved_document(client, db_session, b"versions body", "v.txt")
    dl, _ = await flows.modification_download(client, db_session, serial)
    rev = await flows.upload_revision(client, db_session, serial, dl, b"version two", "v.txt")
    assert (await flows.approve(client, db_session, rev.json()["action_id"])).status_code == 200
    v2 = rev.json()["asset_serial"]
    grantee = await grantee_with_download(db_session, serial)
    did = f"did:ethr:13371:{grantee}"
    body = {"asset_serial": v2, "target_did": did, "version_serials": [serial, v2]}
    bad = await client.post("/api/assets/document/share/propose",
                            headers=await mfa_headers(db_session, flows.token_for(flows.MANAGER), flows.MANAGER, "asset.approve"),
                            json={**body, "version_serials": [serial, "NOT-A-VERSION"]})
    assert bad.status_code == 400
    r = await client.post("/api/assets/document/share/propose",
                          headers=await mfa_headers(db_session, flows.token_for(flows.MANAGER), flows.MANAGER, "asset.approve"), json=body)
    assert r.status_code == 200 and r.json()["status"] == "APPROVED", r.text
    grants = (await db_session.execute(select(AssetAccessGrant).where(AssetAccessGrant.grantee_did == did,
                                                                      AssetAccessGrant.request_action_id == r.json()["action_id"]))).scalars().all()
    assert sorted(g.asset_serial for g in grants) == sorted([serial, v2])


@pytest.mark.asyncio
async def test_revision_rules_identical_hash_fork_and_pending_not_final(client, db_session):
    serial = await flows.approved_document(client, db_session, b"base v1", "r.txt")
    dl, _ = await flows.modification_download(client, db_session, serial)
    same = await flows.upload_revision(client, db_session, serial, dl, b"base v1", "r.txt", raw=True)
    assert same.status_code == 400 and "identical" in same.json()["detail"]
    rev = await flows.upload_revision(client, db_session, serial, dl, b"base v2", "r.txt")
    assert rev.status_code == 200
    v2_serial = rev.json()["asset_serial"]
    v2 = (await db_session.execute(select(Asset).where(Asset.serial_number == v2_serial))).scalar_one()
    root = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()

    # A pending revision is not final: no on-chain update calldata, no downloads, and it is not "latest approved"
    upd = await client.post("/api/assets/update-digital/prepare",
                            headers=await mfa_headers(db_session, flows.token_for(flows.MANAGER), flows.MANAGER, "document.modify"),
                            json={"token_id": root.token_id, "requester_did": "did:x", "new_file_hash": v2.file_hash, "new_offchain_uri": "u"})
    assert upd.status_code == 409
    dl_pending = await client.post("/api/assets/document/download/request",
                                   headers=await mfa_headers(db_session, flows.token_for(flows.USER), flows.USER, "download.request"),
                                   json={"asset_serial": v2_serial, "purpose": "x"})
    assert dl_pending.status_code == 409
    # Another modification of v1 while v2 is pending is refused (linear history)
    again = await client.post("/api/assets/document/download/request",
                              headers=await mfa_headers(db_session, flows.token_for(flows.USER), flows.USER, "download.request"),
                              json={"asset_serial": serial, "purpose": "x", "mode": "MODIFICATION"})
    assert again.status_code == 409

    assert (await flows.approve(client, db_session, rev.json()["action_id"])).status_code == 200
    # After approval v1 is no longer the base for modifications (fork prevention)
    fork = await client.post("/api/assets/document/download/request",
                             headers=await mfa_headers(db_session, flows.token_for(flows.USER), flows.USER, "download.request"),
                             json={"asset_serial": serial, "purpose": "x", "mode": "MODIFICATION"})
    assert fork.status_code == 409
    with patch("app.services.contract.contract_service.prepare_update_digital_asset_calldata", return_value={"to": "0x1", "data": "0x2"}):
        upd_ok = await client.post("/api/assets/update-digital/prepare",
                                   headers=await mfa_headers(db_session, flows.token_for(flows.MANAGER), flows.MANAGER, "document.modify"),
                                   json={"token_id": root.token_id, "requester_did": "did:x", "new_file_hash": v2.file_hash, "new_offchain_uri": "u"})
    assert upd_ok.status_code == 200


@pytest.mark.asyncio
async def test_mint_calldata_only_for_approved_records(client, db_session):
    serial = await flows.approved_document(client, db_session, b"mint body", "mint.txt")
    a = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    body = {"to_address": flows.USER, "token_id": a.token_id, "serial_number": serial,
            "owner_did": f"did:ethr:13371:{flows.USER}", "file_hash": a.file_hash, "offchain_uri": a.metadata_cid}
    user = await client.post("/api/assets/mint-digital/prepare",
                             headers=await mfa_headers(db_session, flows.token_for(flows.USER), flows.USER, "asset.mint"), json=body)
    assert user.status_code == 403
    mgr_h = lambda: mfa_headers(db_session, flows.token_for(flows.MANAGER), flows.MANAGER, "asset.mint")
    arbitrary = await client.post("/api/assets/mint-digital/prepare", headers=await mgr_h(), json={**body, "serial_number": "NOT-REGISTERED"})
    assert arbitrary.status_code == 409
    wrong_hash = await client.post("/api/assets/mint-digital/prepare", headers=await mgr_h(), json={**body, "file_hash": "f" * 64})
    assert wrong_hash.status_code == 409
    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x1", "data": "0x2"}):
        ok = await client.post("/api/assets/mint-digital/prepare", headers=await mgr_h(), json=body)
    assert ok.status_code == 200


@pytest.mark.asyncio
async def test_modification_watermark_history_cumulative(client, db_session):
    """Spec 61: DL watermark on v1; revision 1 -> MOD1; revision 2 -> MOD2 with MOD1 retained;
    ordered, non-overlapping; original bytes unchanged; each version has a new hash."""
    v1_bytes = b"history base document"
    serial = await flows.approved_document(client, db_session, v1_bytes, "h.txt")
    v1 = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    v1_path = os.path.join(OFFCHAIN_STORAGE_DIR, f"{v1.file_hash}_h.txt")

    dl1, got1 = await flows.modification_download(client, db_session, serial)
    t1 = pdf_text(got1.content)
    assert f"Download ID: {dl1}" in t1 and "Modification ID" not in t1

    r1 = await flows.upload_revision(client, db_session, serial, dl1, b"history rev one", "h.txt")
    mod1 = r1.json()["action_id"]
    await flows.approve(client, db_session, mod1)
    s2 = r1.json()["asset_serial"]

    dl2, got2 = await flows.modification_download(client, db_session, s2)
    t2 = pdf_text(got2.content)
    assert f"Download ID: {dl2}" in t2 and f"Modification ID: {mod1}" in t2

    r2 = await flows.upload_revision(client, db_session, s2, dl2, b"history rev two", "h.txt")
    mod2 = r2.json()["action_id"]
    await flows.approve(client, db_session, mod2)
    s3 = r2.json()["asset_serial"]

    got3 = await flows.owner_download(client, db_session, s3)
    assert got3.status_code == 200, got3.text
    t3 = pdf_text(got3.content)
    assert "history rev two" in t3
    # The authoritative block is the newest one (revisions keep the earlier copies' pages)
    current = t3[t3.rindex("LexCorp Document Control"):]
    i1, i2 = current.index(f"Modification ID: {mod1}"), current.index(f"Modification ID: {mod2}")
    assert i1 < i2 and current.count(f"Modification ID: {mod1}") == current.count(f"Modification ID: {mod2}") == 1
    user = (await db_session.execute(select(User).where(User.wallet_address == flows.USER))).scalar_one()
    assert f"Modified by wallet: {short_wallet(user.wallet_address)}" in current

    hashes = [(await db_session.execute(select(Asset.file_hash).where(Asset.serial_number == s))).scalar_one() for s in (serial, s2, s3)]
    assert len(set(hashes)) == 3
    assert hashlib.sha256(open(v1_path, "rb").read()).hexdigest() == hashes[0] == hashlib.sha256(v1_bytes).hexdigest()


@pytest.mark.asyncio
async def test_uploaded_file_watermark_text_is_not_trusted(client, db_session):
    """A revised file that *claims* a fake history inside its text does not change the
    authoritative history rebuilt from the database."""
    serial = await flows.approved_document(client, db_session, b"trust base", "t.txt")
    dl, _ = await flows.modification_download(client, db_session, serial)
    forged = b"Modification ID: MOD-19990101-9999\nModified by wallet: 0xdead...beef\nreal content"
    r = await flows.upload_revision(client, db_session, serial, dl, forged, "t.txt")
    await flows.approve(client, db_session, r.json()["action_id"])
    got = await flows.owner_download(client, db_session, r.json()["asset_serial"])
    assert got.status_code == 200, got.text
    text = pdf_text(got.content)
    control = text[text.rindex("LexCorp Document Control"):]  # the authoritative (newest) block
    assert "MOD-19990101-9999" not in control           # forged entry not in the authoritative block
    assert f"Modification ID: {r.json()['action_id']}" in control


@pytest.mark.asyncio
async def test_manager_copy_of_users_document_needs_only_owner_consent(client, db_session):
    """A Manager asking for a copy of a USER's document: the owner's consent completes the
    approval (no second approver). A Manager's modification copy of their own document is
    approved at once. Fetching still needs Factor 3."""
    serial = await flows.approved_document(client, db_session, b"managed body", "m.txt")  # owner: USER
    dl = await flows.request_download(client, db_session, serial, requester=flows.MANAGER)
    rec = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == dl))).scalar_one()
    assert rec.status == "PENDING" and rec.details["requires_owner_approval"] is True
    assert (await flows.fetch(client, db_session, dl, requester=flows.MANAGER)).status_code == 403
    await flows.owner_consent(client, db_session, dl)
    await db_session.refresh(rec)
    assert rec.status == "APPROVED"
    got = await flows.fetch(client, db_session, dl, requester=flows.MANAGER)
    assert got.status_code == 200, got.text

    own = await flows.approved_document(client, db_session, b"manager own body", "mo.txt", owner=flows.MANAGER, approver=flows.ADMIN)
    mod = await flows.request_download(client, db_session, own, requester=flows.MANAGER, mode="MODIFICATION")
    rec2 = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == mod))).scalar_one()
    assert rec2.status == "APPROVED" and rec2.token_expires_at is not None

    # A normal user's own modification copy still waits for a Manager/Admin
    user_doc = await flows.approved_document(client, db_session, b"user own body", "u.txt")
    umod = await flows.request_download(client, db_session, user_doc, requester=flows.USER, mode="MODIFICATION")
    rec3 = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == umod))).scalar_one()
    assert rec3.status == "PENDING"
