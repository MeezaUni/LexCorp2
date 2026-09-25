"""On-chain confirmation: success is recorded only when Besu's receipt AND the resulting
contract state match the approved record (spec 49, "no fake blockchain success")."""

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.domain import Asset, AuditEvent
from app.services.contract import contract_service
from tests import flows
from tests.conftest import mfa_headers

GOOD = lambda: {"status": 1, "to": contract_service.contract_address, "blockNumber": 777}
TX = "0x" + "ef" * 32


async def confirm(client, serial, receipt, chain_view):
    with patch.object(contract_service.w3.eth, "get_transaction_receipt", MagicMock(return_value=receipt)), \
         patch("app.services.contract.contract_service.get_digital_asset", return_value=chain_view):
        return await client.post(f"/api/assets/chain-confirm/{serial}", json={"tx_hash": TX},
                                 headers={"Authorization": f"Bearer {flows.token_for(flows.MANAGER)}"})


@pytest.mark.asyncio
async def test_document_mint_confirmation(client, db_session):
    serial = await flows.approved_document(client, db_session, b"mint confirm doc", "mc.txt")
    a = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    wrong = await confirm(client, serial, GOOD(), {"serial_number": serial, "file_hash": "0" * 64})
    assert wrong.status_code == 409
    missing = await confirm(client, serial, GOOD(), None)
    assert missing.status_code == 409
    ok = await confirm(client, serial, GOOD(), {"serial_number": serial, "file_hash": a.file_hash})
    assert ok.status_code == 200 and ok.json()["lifecycle_status"] == "MINTED"
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.asset_serial == serial, AuditEvent.event_type == "DOCUMENT_MINTED"))).scalar_one()
    assert ev.risk_factors["tx_hash"] == TX and ev.risk_factors["block_number"] == 777


@pytest.mark.asyncio
async def test_revision_anchor_confirmation(client, db_session):
    serial = await flows.approved_document(client, db_session, b"anchor v1", "an.txt")
    dl, _ = await flows.modification_download(client, db_session, serial)
    rev = await flows.upload_revision(client, db_session, serial, dl, b"anchor v2", "an.txt")
    v2_serial = rev.json()["asset_serial"]
    # Pending revision cannot be anchored
    pend = await confirm(client, v2_serial, GOOD(), {"file_hash": rev.json()["details"]["file_hash"]})
    assert pend.status_code == 409
    await flows.approve(client, db_session, rev.json()["action_id"])
    stale = await confirm(client, v2_serial, GOOD(), {"file_hash": "1" * 64})  # root still has the old hash
    assert stale.status_code == 409
    ok = await confirm(client, v2_serial, GOOD(), {"file_hash": rev.json()["details"]["file_hash"]})
    assert ok.status_code == 200 and ok.json()["lifecycle_status"] == "ANCHORED" and ok.json()["version"] == 2


@pytest.mark.asyncio
async def test_chain_confirm_real_besu_rejects_fabricated_tx(client, db_session):
    """Read-only query of the live node: invented tx hashes are never recorded."""
    serial = await flows.approved_document(client, db_session, b"fabricated tx doc", "fx.txt")
    r = await client.post(f"/api/assets/chain-confirm/{serial}", json={"tx_hash": "0x" + "12" * 32},
                          headers={"Authorization": f"Bearer {flows.token_for(flows.MANAGER)}"})
    assert r.status_code == 409
    a = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    assert a.lifecycle_status != "MINTED"


@pytest.mark.asyncio
async def test_admin_may_submit_document_but_not_approve_it(client, db_session):
    serial = await flows.approved_document(client, db_session, b"admin submitted", "adm.txt", owner=flows.ADMIN, approver=flows.MANAGER)
    assert serial
    # The admin's own pending submission cannot be self-approved
    t = flows.token_for(flows.ADMIN)
    up = await client.post("/api/assets/upload-document", headers={"Authorization": f"Bearer {t}"},
                           files={"file": ("self.txt", b"self approve attempt", "text/plain")})
    prop = await client.post("/api/assets/document/propose", headers=await mfa_headers(db_session, t, flows.ADMIN, "document.submit"),
                             json={"name": "self", "serial_number": "SELF-" + up.json()["file_hash"][:8], "file_hash": up.json()["file_hash"],
                                   "offchain_uri": up.json()["offchain_uri"], "recipient_address": flows.ADMIN})
    assert prop.status_code == 200
    r = await flows.approve(client, db_session, prop.json()["action_id"], approver=flows.ADMIN)
    assert r.status_code == 403
