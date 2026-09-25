"""Test suite for Phase 7: Document Revision Workflow (MOD-)."""

import pytest
from tests.conftest import mfa_headers
import uuid
import os
import pyotp
from unittest.mock import patch
from app.services.auth import create_jwt
from app.models.domain import User, Asset, DocumentAction
from sqlalchemy import select

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower()
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower()
USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower()

def get_token(wallet: str, role: str, session_version: int = 1) -> str:
    did = f"did:ethr:13371:{wallet}"
    return create_jwt(wallet, did, role, session_version, client_ip="testclient")

@pytest.mark.asyncio
async def test_revise_document_success(client, db_session):
    """Modification: request -> approval -> Factor 3 controlled download -> upload revision
    (server hash, MOD ID, pending v2) -> approval -> v2 approved, v1 kept and marked OBSOLETE."""
    from tests import flows
    import hashlib
    serial1 = await flows.approved_document(client, db_session, b"version one text", "spec.txt")

    # Upload without an approved modification download is refused
    none = await flows.upload_revision(client, db_session, serial1, "DL-19990101-0001", b"v2", "spec.txt")
    assert none.status_code == 403

    dl, got = await flows.modification_download(client, db_session, serial1)
    rev = await flows.upload_revision(client, db_session, serial1, dl, b"version two text", "spec.txt")
    assert rev.status_code == 200, rev.text
    mod = rev.json()
    assert mod["action_id"].startswith("MOD-") and mod["status"] == "PENDING"
    assert mod["details"]["download_id"] == dl
    assert mod["details"]["file_hash"] == hashlib.sha256(b"version two text").hexdigest()

    # The same modification download cannot be reused
    reuse = await flows.upload_revision(client, db_session, serial1, dl, b"version three", "spec.txt")
    assert reuse.status_code == 409

    asset1 = (await db_session.execute(select(Asset).where(Asset.serial_number == serial1))).scalar_one()
    asset2 = (await db_session.execute(select(Asset).where(Asset.serial_number == mod["asset_serial"]))).scalar_one()
    assert asset2.approval_status == "PENDING_APPROVAL" and asset2.version_number == 2 and asset2.parent_asset_id == asset1.id

    appr = await flows.approve(client, db_session, mod["action_id"])
    assert appr.status_code == 200, appr.text
    await db_session.refresh(asset1)
    await db_session.refresh(asset2)
    assert asset1.lifecycle_status == "OBSOLETE"
    assert asset2.lifecycle_status == "CREATED" and asset2.approval_status == "APPROVED"
    assert asset1.file_hash == hashlib.sha256(b"version one text").hexdigest()  # original never overwritten


@pytest.mark.asyncio
async def test_revise_document_different_department(client, db_session):
    """Users cannot revise documents belonging to other departments."""
    user_token = get_token(USER_WALLET, "USER", 1)  # Avionics

    # Create doc in Cyber dept directly in DB
    res = await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))
    admin_user = res.scalar_one()

    serial1 = f"BEL-DOC-CYBER-{uuid.uuid4().hex[:6].upper()}"
    cyber_asset = Asset(
        token_id=uuid.uuid4().int % 100000000,
        serial_number=serial1,
        name="Cyber Doc",
        asset_type="DIGITAL",
        department="Cyber",
        lifecycle_status="ACTIVE",
        owner_id=admin_user.id
    )
    db_session.add(cyber_asset)
    await db_session.commit()

    # 2. USER (Avionics) tries to revise CYBER doc
    serial2 = f"BEL-DOC-{uuid.uuid4().hex[:6].upper()}"
    revise_res = await client.post(
        "/api/assets/document/revise",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "parent_asset_serial": serial1,
            "name": "Revised Cyber Doc",
            "new_serial_number": serial2,
            "new_file_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
            "new_offchain_uri": "secure-vault://documents/cyber_v2.txt",
            "purpose": "Sneaky update"
        }
    )

    assert revise_res.status_code == 403
    assert "Users can only revise documents in their own department" in revise_res.text
