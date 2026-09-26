"""Delegated access: request -> Manager/Admin approval -> grant with optional view
limit, optional expiry, and view permission separate from download (spec 19-22, 57)."""

import asyncio
import os
import random
import uuid
from datetime import datetime, timedelta, UTC
from unittest.mock import patch

import httpx
import pytest
from sqlalchemy import select

from app.api.assets import OFFCHAIN_STORAGE_DIR
from app.core.crypto import encrypt_secret
from app.main import app
from app.models.domain import Asset, AssetAccessGrant, AuditEvent, User
from app.services.auth import create_jwt
from tests.conftest import mfa_headers, step_up_token, totp_secret_for

OWNER = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"      # USER, Avionics
MANAGER = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"    # MANAGER, Avionics
ADMIN = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
VERSIONS = {OWNER: 1, MANAGER: 8, ADMIN: 5}
ROLES = {OWNER: "USER", MANAGER: "MANAGER", ADMIN: "ADMIN"}


def token(wallet, role=None, version=None):
    return create_jwt(wallet, f"did:ethr:13371:{wallet}", role or ROLES[wallet], VERSIONS.get(wallet, 1) if version is None else version,
                      client_ip="127.0.0.1")


@pytest.fixture
async def setup(db_session):
    """An approved document owned by OWNER, plus a second onboarded USER (the grantee)."""
    owner = (await db_session.execute(select(User).where(User.wallet_address == OWNER))).scalar_one()
    grantee_wallet = "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    grantee = User(
        wallet_address=grantee_wallet, did=f"did:ethr:13371:{grantee_wallet}", role="USER", department="Avionics",
        is_active=True, onboarding_pending=False, session_version=1,
        is_totp_enabled=True, is_totp_factor2_enabled=True, is_totp_factor3_enabled=True,
        totp_factor2_secret=encrypt_secret(totp_secret_for(grantee_wallet, "factor2")),
        totp_factor3_secret=encrypt_secret(totp_secret_for(grantee_wallet, "factor3")),
    )
    db_session.add(grantee)
    serial = f"DLG-{uuid.uuid4().hex[:8]}"
    fname = f"{serial}.txt"
    os.makedirs(os.path.join(OFFCHAIN_STORAGE_DIR, "documents"), exist_ok=True)
    with open(os.path.join(OFFCHAIN_STORAGE_DIR, "documents", fname), "w") as f:
        f.write("classified delegated document")
    asset = Asset(token_id=random.randint(10_000_000, 2_000_000_000), serial_number=serial, owner_id=owner.id,
                  department="Avionics", is_physical=False, asset_type="DOCUMENT", approval_status="APPROVED",
                  metadata_cid=f"secure-vault://documents/{fname}", file_hash="d" * 64, version_number=1)
    db_session.add(asset)
    await db_session.commit()
    asset.root_asset_id = asset.id
    await db_session.commit()
    return {"asset": asset, "grantee": grantee, "g_wallet": grantee_wallet, "g_token": token(grantee_wallet, "USER", 1)}


async def request_access(client, db, setup, **extra):
    r = await client.post("/api/assets/document/share/propose",
                          headers=await mfa_headers(db, token(OWNER), OWNER, "access.request"),
                          json={"asset_serial": setup["asset"].serial_number, "target_did": setup["grantee"].did, **extra})
    assert r.status_code == 200, r.text
    assert r.json()["action_id"].startswith("ACR-")
    return r.json()["action_id"]


async def approve(client, db, action_id, approver=MANAGER, **opts):
    with patch("app.services.contract.contract_service.prepare_grant_access_calldata", return_value={"to": "0x1", "data": "0x2"}), \
         patch("app.services.contract.contract_service.get_token_by_serial", return_value=None):
        return await client.post(f"/api/assets/document/approval/{action_id}",
                                 headers=await mfa_headers(db, token(approver), approver, "asset.approve"),
                                 json={"decision": "APPROVE", **opts})


async def view(client, db, setup, *, with_factor=True):
    headers = {"Authorization": f"Bearer {setup['g_token']}"}
    if with_factor:
        headers["X-Step-Up-Token"] = await step_up_token(db, setup["g_wallet"], "document.view")
    return await client.get(f"/api/assets/document/view/{setup['asset'].serial_number}", headers=headers)


async def grant_row(db, setup):
    return (await db.execute(select(AssetAccessGrant).where(AssetAccessGrant.grantee_did == setup["grantee"].did))).scalar_one()


@pytest.mark.asyncio
async def test_request_alone_grants_nothing_and_needs_manager_or_admin(client, db_session, setup):
    acr = await request_access(client, db_session, setup)
    denied = await view(client, db_session, setup)
    assert denied.status_code == 403
    # The requesting USER cannot approve (role) ...
    r = await client.post(f"/api/assets/document/approval/{acr}", headers=await mfa_headers(db_session, token(OWNER), OWNER, "asset.approve"),
                          json={"decision": "APPROVE"})
    assert r.status_code == 403
    # ... the grantee cannot approve either
    r = await client.post(f"/api/assets/document/approval/{acr}", headers={"Authorization": f"Bearer {setup['g_token']}"}, json={"decision": "APPROVE"})
    assert r.status_code == 403
    ok = await approve(client, db_session, acr)
    assert ok.status_code == 200, ok.text
    assert (await view(client, db_session, setup)).status_code == 200
    audit = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "ACCESS_GRANTED",
                                                              AuditEvent.target_did == setup["grantee"].did))).scalars().all()
    assert len(audit) == 1 and audit[0].risk_factors["request_action_id"] == acr


@pytest.mark.asyncio
async def test_unrelated_user_and_grantee_cannot_reshare(client, db_session, setup):
    # The grantee (not the holder) cannot request access for someone else
    r = await client.post("/api/assets/document/share/propose",
                          headers=await mfa_headers(db_session, setup["g_token"], setup["g_wallet"], "access.request"),
                          json={"asset_serial": setup["asset"].serial_number, "target_did": f"did:ethr:13371:{ADMIN}"})
    assert r.status_code == 404
    # Unknown target identity
    r = await client.post("/api/assets/document/share/propose",
                          headers=await mfa_headers(db_session, token(OWNER), OWNER, "access.request"),
                          json={"asset_serial": setup["asset"].serial_number, "target_did": "did:ethr:13371:0xdeadbeef"})
    assert r.status_code == 400
    # No grant -> denial is audited
    assert (await view(client, db_session, setup)).status_code == 403
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "ACCESS_DENIED_NO_GRANT",
                                                           AuditEvent.actor_did == setup["grantee"].did))).scalars().all()
    assert ev


@pytest.mark.asyncio
async def test_manager_grants_directly_with_factor3_but_users_still_need_approval(client, db_session, setup):
    """Policy: a Manager/Admin in scope delegates without an approver, proving Factor 3 (the
    approval factor), with final limits; a normal user's delegation still waits for approval."""
    body = {"asset_serial": setup["asset"].serial_number, "target_did": setup["grantee"].did, "max_views": 3}
    # A Factor 2 proof is not enough for a direct grant
    weak = await client.post("/api/assets/document/share/propose",
                             headers=await mfa_headers(db_session, token(MANAGER), MANAGER, "access.request"), json=body)
    assert weak.status_code == 401
    past = await client.post("/api/assets/document/share/propose",
                             headers=await mfa_headers(db_session, token(MANAGER), MANAGER, "asset.approve"),
                             json={**body, "accessible_until": "2020-01-01T00:00:00+00:00"})
    assert past.status_code == 400
    r = await client.post("/api/assets/document/share/propose",
                          headers=await mfa_headers(db_session, token(MANAGER), MANAGER, "asset.approve"), json=body)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "APPROVED"
    g = await grant_row(db_session, setup)
    assert g.max_views == 3 and g.can_view and not g.can_download and g.granted_by_did.endswith(MANAGER)

    # The owner is a normal user: their request is only a proposal until a Manager/Admin decides
    owner_req = await client.post("/api/assets/document/share/propose",
                                  headers=await mfa_headers(db_session, token(OWNER), OWNER, "access.request"), json=body)
    assert owner_req.status_code == 200 and owner_req.json()["status"] == "PENDING"
    # A Manager may also decide on a request they submitted themselves (no one else is needed)
    own = await client.post("/api/assets/document/share/propose",
                            headers=await mfa_headers(db_session, token(ADMIN), ADMIN, "asset.approve"), json=body)
    assert own.status_code == 200 and own.json()["status"] == "APPROVED"


@pytest.mark.asyncio
async def test_default_is_unlimited_view_only_without_expiry(client, db_session, setup):
    await approve(client, db_session, await request_access(client, db_session, setup))
    g = await grant_row(db_session, setup)
    assert g.max_views is None and g.expires_at is None and g.can_view and not g.can_download
    for _ in range(4):
        assert (await view(client, db_session, setup)).status_code == 200


@pytest.mark.asyncio
async def test_view_limit_counts_only_successful_views(client, db_session, setup):
    await approve(client, db_session, await request_access(client, db_session, setup), max_views=2)
    # Failed attempts (no factor) do not count
    assert (await view(client, db_session, setup, with_factor=False)).status_code in (401, 403)
    g = await grant_row(db_session, setup)
    await db_session.refresh(g)
    assert g.views_count == 0
    assert (await view(client, db_session, setup)).status_code == 200
    assert (await view(client, db_session, setup)).status_code == 200
    third = await view(client, db_session, setup)
    assert third.status_code == 403 and "limit" in third.json()["detail"].lower()
    await db_session.refresh(g)
    assert g.views_count == 2
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "ACCESS_LIMIT_REACHED",
                                                           AuditEvent.actor_did == setup["grantee"].did))).scalars().all()
    assert ev


@pytest.mark.asyncio
async def test_view_limit_is_atomic_under_concurrency(client, db_session, setup):
    await approve(client, db_session, await request_access(client, db_session, setup), max_views=3)
    tokens = [await step_up_token(db_session, setup["g_wallet"], "document.view") for _ in range(8)]
    # Separate client whose requests each get their OWN session/connection (no shared test session),
    # so the eight views genuinely race on the grant row.
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from app.core.config import settings
    from app.core.database import get_db
    engine = create_async_engine(settings.DATABASE_URL, pool_size=10)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def per_request_db():
        async with factory() as s:
            yield s

    saved = dict(app.dependency_overrides)
    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = per_request_db
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as raw:
            async def one(t):
                return (await raw.get(f"/api/assets/document/view/{setup['asset'].serial_number}",
                                      headers={"Authorization": f"Bearer {setup['g_token']}", "X-Step-Up-Token": t})).status_code
            codes = await asyncio.gather(*[one(t) for t in tokens])
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)
        await engine.dispose()
    assert codes.count(200) == 3, codes
    assert codes.count(403) == 5, codes
    g = await grant_row(db_session, setup)
    await db_session.refresh(g)
    assert g.views_count == 3


@pytest.mark.asyncio
async def test_expiry(client, db_session, setup):
    acr = await request_access(client, db_session, setup)
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    assert (await approve(client, db_session, acr, accessible_until=past)).status_code == 400
    naive = (datetime.now(UTC) + timedelta(days=1)).replace(tzinfo=None).isoformat()
    assert (await approve(client, db_session, acr, accessible_until=naive)).status_code == 400
    future = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    assert (await approve(client, db_session, acr, accessible_until=future)).status_code == 200
    assert (await view(client, db_session, setup)).status_code == 200
    reg = {a["serial_number"] for a in (await client.get("/api/assets/registry", headers={"Authorization": f"Bearer {setup['g_token']}"})).json()}
    assert setup["asset"].serial_number in reg

    g = await grant_row(db_session, setup)
    g.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    r = await view(client, db_session, setup)
    assert r.status_code == 403 and "expired" in r.json()["detail"].lower()
    reg = {a["serial_number"] for a in (await client.get("/api/assets/registry", headers={"Authorization": f"Bearer {setup['g_token']}"})).json()}
    assert setup["asset"].serial_number not in reg
    dl = await client.post("/api/assets/document/download/request", headers=await mfa_headers(db_session, setup["g_token"], setup["g_wallet"], "download.request"),
                           json={"asset_serial": setup["asset"].serial_number, "purpose": "x"})
    assert dl.status_code == 403


@pytest.mark.asyncio
async def test_view_permission_separate_from_download(client, db_session, setup):
    await approve(client, db_session, await request_access(client, db_session, setup, request_download=True))
    assert (await view(client, db_session, setup)).status_code == 200
    dl = await client.post("/api/assets/document/download/request", headers=await mfa_headers(db_session, setup["g_token"], setup["g_wallet"], "download.request"),
                           json={"asset_serial": setup["asset"].serial_number, "purpose": "x"})
    assert dl.status_code == 403 and "view-only" in dl.json()["detail"]

    g = await grant_row(db_session, setup)
    g.is_active = False
    await db_session.commit()
    acr2 = await request_access(client, db_session, setup, request_download=True)
    assert (await approve(client, db_session, acr2, allow_download=True)).status_code == 200
    dl2 = await client.post("/api/assets/document/download/request", headers=await mfa_headers(db_session, setup["g_token"], setup["g_wallet"], "download.request"),
                            json={"asset_serial": setup["asset"].serial_number, "purpose": "x"})
    assert dl2.status_code == 200, dl2.text


@pytest.mark.asyncio
async def test_revocation_and_listing(client, db_session, setup):
    await approve(client, db_session, await request_access(client, db_session, setup), max_views=5)
    listed = (await client.get(f"/api/assets/access-grants?asset_serial={setup['asset'].serial_number}", headers={"Authorization": f"Bearer {token(OWNER)}"})).json()
    assert len(listed) == 1 and listed[0]["status"] == "ACTIVE" and listed[0]["views_remaining"] == 5
    # grantee cannot revoke; owner can
    assert (await client.post(f"/api/assets/access-grants/{listed[0]['id']}/revoke", headers={"Authorization": f"Bearer {setup['g_token']}"})).status_code == 403
    r = await client.post(f"/api/assets/access-grants/{listed[0]['id']}/revoke", headers={"Authorization": f"Bearer {token(OWNER)}"})
    assert r.status_code == 200 and r.json()["status"] == "REVOKED"
    assert (await view(client, db_session, setup)).status_code == 403


@pytest.mark.asyncio
async def test_share_approval_never_flips_document_state(client, db_session, setup):
    a = setup["asset"]
    a.approval_status = "PENDING_APPROVAL"
    await db_session.commit()
    r = await client.post("/api/assets/document/share/propose", headers=await mfa_headers(db_session, token(OWNER), OWNER, "access.request"),
                          json={"asset_serial": a.serial_number, "target_did": setup["grantee"].did})
    assert r.status_code == 409
    # A share request made while approved cannot be approved after the document is rejected,
    # and rejecting a share never changes the document's state.
    a.approval_status = "APPROVED"
    await db_session.commit()
    acr = await request_access(client, db_session, setup)
    rej = await client.post(f"/api/assets/document/approval/{acr}", headers=await mfa_headers(db_session, token(MANAGER), MANAGER, "asset.approve"),
                            json={"decision": "REJECT", "rejection_reason": "no"})
    assert rej.status_code == 200
    await db_session.refresh(a)
    assert a.approval_status == "APPROVED"
