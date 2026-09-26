"""Test suite for Phase 11: Audit Trail & Event Indexer Pipeline Updates for New Action Types."""

import pytest
import uuid
import random
from unittest.mock import patch, MagicMock, AsyncMock
from sqlalchemy import select
from app.models.domain import AuditEvent, Asset, User
from app.indexer.event_indexer import EventIndexer

OWNER = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
LOW = {"risk_score": 0.1, "risk_label": "LOW", "anomaly_score": 0.05, "features": {}}


def _indexer():
    ix = EventIndexer()
    ix.w3 = MagicMock()
    ix.contract = MagicMock()
    return ix


def _mint_log(token_id, serial, owner=OWNER, file_hash="ab" * 32):
    raw = uuid.uuid4().hex + uuid.uuid4().hex
    return raw, {"transactionHash": bytes.fromhex(raw), "blockNumber": random.randint(1000, 9999),
                 "args": {"tokenId": token_id, "serialNumber": serial, "owner": owner,
                          "ownerDID": f"did:ethr:13371:{owner}", "fileHash": file_hash, "offchainURI": "vault://x"}}


async def _registered_doc(db, token_id, serial, file_hash="ab" * 32, status="APPROVED"):
    owner = (await db.execute(select(User).where(User.wallet_address == OWNER))).scalar_one()
    a = Asset(token_id=token_id, serial_number=serial, owner_id=owner.id, is_physical=False, asset_type="DOCUMENT",
              file_hash=file_hash, approval_status=status, department="Avionics")
    db.add(a)
    await db.commit()
    return a


async def _write(ix, db, name, log):
    with patch("app.indexer.event_indexer.ai_engine.analyze_event", return_value=dict(LOW)), \
         patch("app.indexer.event_indexer.ai_engine.record_event"):
        return await ix._write_event(db, name, log, log["blockNumber"])


async def _audit(db, raw):
    return (await db.execute(select(AuditEvent).where(AuditEvent.tx_hash == raw))).scalar_one()


@pytest.mark.asyncio
async def test_registered_mint_matching_registry_is_low_and_changes_nothing(db_session, seed_test_users):
    token_id, serial = random.randint(10**6, 10**7), f"DOC-TEST-{uuid.uuid4().hex[:6].upper()}"
    asset = await _registered_doc(db_session, token_id, serial)
    users_before = len((await db_session.execute(select(User))).scalars().all())
    raw, log = _mint_log(token_id, serial)
    assert await _write(_indexer(), db_session, "DigitalAssetMinted", log) is True
    audit = await _audit(db_session, raw)
    assert audit.event_type == "DigitalAssetMinted" and audit.asset_serial == serial and audit.risk_label == "LOW"
    await db_session.refresh(asset)
    assert asset.file_hash == "ab" * 32
    assert len((await db_session.execute(select(User))).scalars().all()) == users_before


@pytest.mark.asyncio
async def test_unregistered_mint_raises_integrity_alert_and_creates_no_identity(db_session, seed_test_users):
    stranger = "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    token_id, serial = random.randint(10**7, 10**8), f"DOC-ROGUE-{uuid.uuid4().hex[:6].upper()}"
    raw, log = _mint_log(token_id, serial, owner=stranger)
    assert await _write(_indexer(), db_session, "DigitalAssetMinted", log) is True
    audit = await _audit(db_session, raw)
    assert audit.risk_label == "HIGH"
    assert audit.risk_factors["integrity_anomaly"]["rule"] == "UNREGISTERED_MINT"
    assert (await db_session.execute(select(User).where(User.wallet_address == stranger))).scalar_one_or_none() is None
    assert (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one_or_none() is None
    from app.models.domain import SecurityAlert
    alert = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.source_event_id == audit.id))).scalar_one()
    assert alert.source == "RULE"
    alert.state = "DISMISSED"
    await db_session.commit()


@pytest.mark.asyncio
async def test_mint_with_mismatched_hash_is_flagged_not_copied(db_session, seed_test_users):
    token_id, serial = random.randint(10**8, 10**9), f"DOC-MM-{uuid.uuid4().hex[:6].upper()}"
    asset = await _registered_doc(db_session, token_id, serial, file_hash="cd" * 32)
    raw, log = _mint_log(token_id, serial, file_hash="ef" * 32)
    await _write(_indexer(), db_session, "DigitalAssetMinted", log)
    audit = await _audit(db_session, raw)
    assert audit.risk_label == "HIGH" and "file_hash" in audit.risk_factors["integrity_anomaly"]["fields"]
    await db_session.refresh(asset)
    assert asset.file_hash == "cd" * 32  # the registry is never overwritten from chain data


@pytest.mark.asyncio
async def test_event_indexer_idempotent_duplicate(db_session, seed_test_users):
    """A re-delivered event is skipped entirely: no second audit row, no projection change."""
    token_id, serial = random.randint(10**6, 10**7), f"DOC-DUP-{uuid.uuid4().hex[:6].upper()}"
    asset = await _registered_doc(db_session, token_id, serial)
    raw, log = _mint_log(token_id, serial)
    ix = _indexer()
    assert await _write(ix, db_session, "DigitalAssetMinted", log) is True
    assert await _write(ix, db_session, "DigitalAssetMinted", log) is False
    rows = (await db_session.execute(select(AuditEvent).where(AuditEvent.tx_hash == raw))).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_revision_anchor_must_match_an_approved_version(db_session, seed_test_users):
    token_id, serial = random.randint(10**6, 10**7), f"DOC-ANC-{uuid.uuid4().hex[:6].upper()}"
    root = await _registered_doc(db_session, token_id, serial, file_hash="01" * 32)
    rev = Asset(token_id=random.randint(10**9, 2*10**9), serial_number=f"{serial}-V2", owner_id=root.owner_id, is_physical=False, asset_type="DOCUMENT",
                file_hash="02" * 32, approval_status="APPROVED", root_asset_id=root.id, parent_asset_id=root.id, version_number=2)
    db_session.add(rev)
    await db_session.commit()
    ix = _indexer()
    ix.contract.functions.getDigitalAsset.return_value.call.return_value = (serial, "d", "02" * 32, "u", True)
    for new_hash, expect in (("02" * 32, "LOW"), ("99" * 32, "HIGH")):
        raw = uuid.uuid4().hex + uuid.uuid4().hex
        log = {"transactionHash": bytes.fromhex(raw), "blockNumber": 5,
               "args": {"tokenId": token_id, "oldFileHash": "01" * 32, "newFileHash": new_hash,
                        "newOffchainURI": "u", "updater": "0x049dd1327d3bf40ab2dd8d70086304770e841fca"}}
        await _write(ix, db_session, "DigitalAssetUpdated", log)
        assert (await _audit(db_session, raw)).risk_label == expect
    await db_session.refresh(root)
    assert root.file_hash == "01" * 32  # v1's integrity record is never rewritten


@pytest.mark.asyncio
async def test_unexpected_onchain_role_grant_is_flagged(db_session, seed_test_users):
    ix = _indexer()
    minter = b"\x01" * 32
    ix.contract.functions.MINTER_ROLE.return_value.call.return_value = minter
    for name in ("ANCHOR_ROLE", "MANAGER_ROLE", "AUDITOR_ROLE", "REGISTRAR_ROLE", "DEFAULT_ADMIN_ROLE"):
        getattr(ix.contract.functions, name).return_value.call.return_value = name.encode().ljust(32, b"\0")
    cases = (("0x049dd1327d3bf40ab2dd8d70086304770e841fca", "LOW"),   # active MANAGER -> expected
             (OWNER, "HIGH"))                                          # plain USER -> never a minter
    for account, expect in cases:
        raw = uuid.uuid4().hex + uuid.uuid4().hex
        log = {"transactionHash": bytes.fromhex(raw), "blockNumber": 7,
               "args": {"role": minter, "account": account, "sender": "0x" + "33" * 20}}
        await _write(ix, db_session, "RoleGranted", log)
        assert (await _audit(db_session, raw)).risk_label == expect


@pytest.mark.asyncio
async def test_event_indexer_digital_asset_updated(db_session, seed_test_users):
    """Test EventIndexer correctly processes DigitalAssetUpdated event."""
    indexer = EventIndexer()
    indexer.w3 = MagicMock()
    indexer.contract = MagicMock()

    raw_hash = uuid.uuid4().hex + uuid.uuid4().hex
    block_num = random.randint(1000, 9999)
    token_id = random.randint(1000000, 9999999)
    updater_wallet = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
    serial = f"DOC-MOD-{uuid.uuid4().hex[:6].upper()}"

    # Setup contract getDigitalAsset mock
    indexer.contract.functions.getDigitalAsset.return_value.call.return_value = (
        serial,
        f"did:ethr:13371:{updater_wallet}",
        "0xNewHash",
        "ipfs://QmNewURI",
        True
    )

    log = {
        "transactionHash": bytes.fromhex(raw_hash),
        "blockNumber": block_num,
        "args": {
            "tokenId": token_id,
            "updater": updater_wallet,
            "fileHash": "0xNewHash",
            "offchainURI": "ipfs://QmNewURI"
        }
    }

    event_name = "DigitalAssetUpdated"

    with patch("app.indexer.event_indexer.ai_engine.analyze_event", return_value={"risk_score": 0.2, "risk_label": "LOW", "anomaly_score": 0.1, "features": {}}), \
         patch("app.indexer.event_indexer.ai_engine.record_event"):
        success = await indexer._write_event(db_session, event_name, log, block_num)

    assert success is True

    audit_res = await db_session.execute(select(AuditEvent).where(AuditEvent.tx_hash == raw_hash))
    audit = audit_res.scalar_one_or_none()
    assert audit is not None
    assert audit.event_type == "DigitalAssetUpdated"
    assert audit.asset_serial == serial


@pytest.mark.asyncio
async def test_event_indexer_access_attempted(db_session, seed_test_users):
    """Test EventIndexer records AccessAttempted event and passes granted status to AI engine."""
    indexer = EventIndexer()
    indexer.w3 = MagicMock()
    indexer.contract = MagicMock()

    raw_hash = uuid.uuid4().hex + uuid.uuid4().hex
    block_num = random.randint(1000, 9999)
    token_id = random.randint(1000000, 9999999)
    actor_did = "did:ethr:13371:0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
    serial = f"DOC-ACC-{uuid.uuid4().hex[:6].upper()}"

    indexer.contract.functions.getAsset.return_value.call.return_value = (
        serial,
        "did:ethr:13371:0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
    )

    log = {
        "transactionHash": bytes.fromhex(raw_hash),
        "blockNumber": block_num,
        "args": {
            "tokenId": token_id,
            "actorDID": actor_did,
            "granted": False,
            "reason": "Unauthorized access attempt"
        }
    }

    event_name = "AccessAttempted"

    with patch("app.indexer.event_indexer.ai_engine.analyze_event", return_value={"risk_score": 0.8, "risk_label": "HIGH", "anomaly_score": -0.3, "features": {}}), \
         patch("app.indexer.event_indexer.ai_engine.record_event") as mock_rec:
        success = await indexer._write_event(db_session, event_name, log, block_num)

    assert success is True
    assert mock_rec.called
    assert mock_rec.call_args[1]["granted"] is False

    audit_res = await db_session.execute(select(AuditEvent).where(AuditEvent.tx_hash == raw_hash))
    audit = audit_res.scalar_one_or_none()
    assert audit is not None
    assert audit.event_type == "AccessAttempted"
    assert audit.risk_label == "HIGH"
    assert audit.risk_score == 0.8


@pytest.mark.asyncio
async def test_every_event_in_one_transaction_is_recorded(db_session, seed_test_users):
    """A transaction emitting several events (e.g. the constructor's two RoleGranted)
    must produce one audit row per LOG; re-delivery of any of them is still skipped."""
    ix = _indexer()
    for name in ("MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE", "AUDITOR_ROLE", "REGISTRAR_ROLE", "DEFAULT_ADMIN_ROLE"):
        getattr(ix.contract.functions, name).return_value.call.return_value = name.encode().ljust(32, b"\0")
    raw = uuid.uuid4().hex + uuid.uuid4().hex
    logs = [{"transactionHash": bytes.fromhex(raw), "blockNumber": 3, "logIndex": i,
             "args": {"role": b"MANAGER_ROLE".ljust(32, b"\0"), "account": "0x049dd1327d3bf40ab2dd8d70086304770e841fca",
                      "sender": "0x" + "33" * 20}} for i in (0, 1)]
    assert await _write(ix, db_session, "RoleGranted", logs[0]) is True
    assert await _write(ix, db_session, "RoleGranted", logs[1]) is True
    assert await _write(ix, db_session, "RoleGranted", logs[1]) is False
    rows = (await db_session.execute(select(AuditEvent).where(AuditEvent.tx_hash == raw))).scalars().all()
    assert sorted(r.log_index for r in rows) == [0, 1]
    assert all(r.risk_label == "LOW" for r in rows)  # expected grant: no AI false positive


@pytest.mark.asyncio
async def test_governance_grants_judged_by_granting_admin(db_session, seed_test_users):
    """A registrar granted by the governance admin (even one later rotated away) is legitimate;
    a governance role granted by anyone else is flagged."""
    ix = _indexer()
    for name in ("MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE", "AUDITOR_ROLE", "REGISTRAR_ROLE", "DEFAULT_ADMIN_ROLE"):
        getattr(ix.contract.functions, name).return_value.call.return_value = name.encode().ljust(32, b"\0")
    admin = "0x" + "22" * 20  # tests/.test_deployment.json admin
    for sender, expect in ((admin, "LOW"), ("0x" + "66" * 20, "HIGH")):
        raw = uuid.uuid4().hex + uuid.uuid4().hex
        log = {"transactionHash": bytes.fromhex(raw), "blockNumber": 9, "logIndex": 0,
               "args": {"role": b"REGISTRAR_ROLE".ljust(32, b"\0"), "account": "0x" + "77" * 20, "sender": sender}}
        await _write(ix, db_session, "RoleGranted", log)
        assert (await _audit(db_session, raw)).risk_label == expect
    from app.models.domain import SecurityAlert
    for a in (await db_session.execute(select(SecurityAlert).where(SecurityAlert.state == "AUDITOR_REVIEW"))).scalars().all():
        a.state = "DISMISSED"
    await db_session.commit()


@pytest.mark.asyncio
async def test_mint_actor_is_the_transaction_sender_not_the_holder(db_session, seed_test_users):
    token_id, serial = random.randint(10**6, 10**7), f"DOC-ACT-{uuid.uuid4().hex[:6].upper()}"
    await _registered_doc(db_session, token_id, serial)
    raw, log = _mint_log(token_id, serial)
    ix = _indexer()
    minter = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"
    ix.w3.eth.get_transaction.return_value = {"from": minter}
    await _write(ix, db_session, "DigitalAssetMinted", log)
    audit = await _audit(db_session, raw)
    assert audit.actor_did == f"did:ethr:13371:{minter}"
    assert audit.target_did == f"did:ethr:13371:{OWNER}"
