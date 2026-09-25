"""Backend-generated action IDs, version lineage and action audit fields (spec 17, 18, 26, 27, 45)."""

import asyncio
import re
import uuid
from datetime import datetime, UTC
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.models.domain import Asset, DocumentAction
from app.services.action_ids import next_action_id, next_token_id
from app.services.auth import create_jwt
from tests.conftest import mfa_headers

USER = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
MANAGER = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"


def tok(wallet, role, v):
    return create_jwt(wallet, f"did:ethr:13371:{wallet}", role, v, client_ip="127.0.0.1")


def id_re(prefix):
    today = datetime.now(UTC).strftime("%Y%m%d")
    return re.compile(rf"^{prefix}-{today}-\d{{4,}}$")


@pytest.mark.asyncio
async def test_action_id_format_and_uniqueness_under_concurrency():
    engine = create_async_engine(settings.DATABASE_URL)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def one():
        async with factory() as s:
            v = await next_action_id(s, "VW")
            await s.commit()
            return v

    ids = await asyncio.gather(*[one() for _ in range(25)])
    await engine.dispose()
    assert len(set(ids)) == 25
    assert all(id_re("VW").match(i) for i in ids)
    numbers = sorted(int(i.rsplit("-", 1)[1]) for i in ids)
    assert numbers == list(range(numbers[0], numbers[0] + 25))  # gap-free, no duplicates


@pytest.mark.asyncio
async def test_token_ids_come_from_sequence(db_session):
    a, b = await next_token_id(db_session), await next_token_id(db_session)
    assert b == a + 1


@pytest.mark.asyncio
async def test_creation_view_download_modification_ids_and_versions(client, db_session):
    user_t, mgr_t = tok(USER, "USER", 1), tok(MANAGER, "MANAGER", 8)
    serial = f"AID-{uuid.uuid4().hex[:8]}"
    prop = await client.post("/api/assets/document/propose", headers=await mfa_headers(db_session, user_t, USER, "document.submit"),
                             json={"name": "IDs", "serial_number": serial, "file_hash": "a" * 64,
                                   "offchain_uri": "secure-vault://documents/ids.txt", "recipient_address": USER})
    assert prop.status_code == 200, prop.text
    crt = prop.json()["action_id"]
    assert id_re("CRT").match(crt)
    v1 = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    assert v1.version_number == 1 and v1.root_asset_id == v1.id and v1.action_id == crt
    crt_action = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == crt))).scalar_one()
    assert crt_action.actor_did.endswith(USER) and crt_action.asset_id == v1.id and crt_action.asset_version == 1
    assert crt_action.client_ip == "127.0.0.1"

    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x1", "data": "0x2"}):
        await client.post(f"/api/assets/document/approval/{crt}", headers=await mfa_headers(db_session, mgr_t, MANAGER, "asset.approve"),
                          json={"decision": "APPROVE"})

    import os
    from app.api.assets import OFFCHAIN_STORAGE_DIR
    os.makedirs(os.path.join(OFFCHAIN_STORAGE_DIR, "documents"), exist_ok=True)
    with open(os.path.join(OFFCHAIN_STORAGE_DIR, "documents", "ids.txt"), "w") as f:
        f.write("action id test document")

    # VIEW via a trusted proxy hop: the recorded IP is the forwarded client IP, not a placeholder
    view_h = await mfa_headers(db_session, user_t, USER, "document.view")
    user_t2 = create_jwt(USER, f"did:ethr:13371:{USER}", "USER", 1, client_ip="198.51.100.23")
    view_h["Authorization"] = f"Bearer {user_t2}"
    view_h["X-Forwarded-For"] = "198.51.100.23"
    await client.get(f"/api/assets/document/view/{serial}", headers=view_h)
    vw = (await db_session.execute(select(DocumentAction).where(DocumentAction.asset_id == v1.id, DocumentAction.action_type == "VIEW"))).scalars().all()
    assert len(vw) == 1 and id_re("VW").match(vw[0].action_id)
    assert vw[0].client_ip == "198.51.100.23" and vw[0].asset_version == 1

    dl = await client.post("/api/assets/document/download/request", headers=await mfa_headers(db_session, user_t, USER, "download.request"),
                           json={"asset_serial": serial, "purpose": "ids"})
    assert dl.status_code == 200, dl.text
    assert id_re("DL").match(dl.json()["action_id"])

    # Revisions: v2 then v3, each a new row linked to its parent and the lineage root
    serial2, serial3 = f"{serial}-r1", f"{serial}-r2"
    r1 = await client.post("/api/assets/document/revise", headers=await mfa_headers(db_session, user_t, USER, "document.modify"),
                           json={"parent_asset_serial": serial, "name": "r1", "new_serial_number": serial2,
                                 "new_file_hash": "b" * 64, "new_offchain_uri": "secure-vault://documents/r1.txt"})
    assert r1.status_code == 200, r1.text
    assert id_re("MOD").match(r1.json()["action_id"])
    v2 = (await db_session.execute(select(Asset).where(Asset.serial_number == serial2))).scalar_one()
    assert v2.version_number == 2 and v2.parent_asset_id == v1.id and v2.root_asset_id == v1.id
    r2 = await client.post("/api/assets/document/revise", headers=await mfa_headers(db_session, user_t, USER, "document.modify"),
                           json={"parent_asset_serial": serial2, "name": "r2", "new_serial_number": serial3,
                                 "new_file_hash": "c" * 64, "new_offchain_uri": "secure-vault://documents/r2.txt"})
    assert r2.status_code == 200, r2.text
    v3 = (await db_session.execute(select(Asset).where(Asset.serial_number == serial3))).scalar_one()
    assert v3.version_number == 3 and v3.parent_asset_id == v2.id and v3.root_asset_id == v1.id
    mod = (await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == r2.json()["action_id"]))).scalar_one()
    assert mod.details["parent_version"] == 2 and mod.details["version"] == 3 and mod.asset_version == 3

    # Original row untouched by revisions
    await db_session.refresh(v1)
    assert v1.file_hash == "a" * 64 and v1.version_number == 1

    lineage = (await client.get(f"/api/assets/document/lineage/{serial3}", headers={"Authorization": f"Bearer {user_t}"})).json()
    assert [n["version_number"] for n in lineage["lineage"]] == [1, 2, 3]
