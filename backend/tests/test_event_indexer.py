"""Test suite for Phase 11: Audit Trail & Event Indexer Pipeline Updates for New Action Types."""

import pytest
import uuid
import random
from unittest.mock import patch, MagicMock, AsyncMock
from sqlalchemy import select
from app.models.domain import AuditEvent, Asset, User
from app.indexer.event_indexer import EventIndexer

@pytest.mark.asyncio
async def test_event_indexer_mint_digital_asset(db_session, seed_test_users):
    """Test EventIndexer correctly processes DigitalAssetMinted and writes AuditEvent and Asset."""
    indexer = EventIndexer()
    indexer.w3 = MagicMock()
    indexer.contract = MagicMock()

    raw_hash = uuid.uuid4().hex + uuid.uuid4().hex
    block_num = random.randint(1000, 9999)

    token_id = random.randint(1000000, 9999999)
    serial = f"DOC-TEST-{uuid.uuid4().hex[:6].upper()}"
    owner_wallet = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"

    log = {
        "transactionHash": bytes.fromhex(raw_hash),
        "blockNumber": block_num,
        "args": {
            "tokenId": token_id,
            "serialNumber": serial,
            "owner": owner_wallet,
            "ownerDID": f"did:ethr:13371:{owner_wallet}",
            "fileHash": "QmTestHash...",
            "offchainURI": "ipfs://QmTestHash..."
        }
    }

    event_name = "DigitalAssetMinted"

    # Mock AI risk engine
    with patch("app.indexer.event_indexer.ai_engine.analyze_event", return_value={"risk_score": 0.1, "risk_label": "LOW", "anomaly_score": 0.05, "features": {}}), \
         patch("app.indexer.event_indexer.ai_engine.record_event"):
        success = await indexer._write_event(db_session, event_name, log, block_num)

    assert success is True

    # Verify AuditEvent
    audit_res = await db_session.execute(select(AuditEvent).where(AuditEvent.tx_hash == raw_hash))
    audit = audit_res.scalar_one_or_none()
    assert audit is not None
    assert audit.event_type == "DigitalAssetMinted"
    assert audit.asset_serial == serial
    assert audit.risk_label == "LOW"

    # Verify Asset Projection
    asset_res = await db_session.execute(select(Asset).where(Asset.serial_number == serial))
    asset = asset_res.scalar_one_or_none()
    assert asset is not None
    assert asset.token_id == token_id
    assert asset.metadata_cid == "ipfs://QmTestHash..."


@pytest.mark.asyncio
async def test_event_indexer_idempotent_duplicate(db_session, seed_test_users):
    """Test EventIndexer skips writing duplicate AuditEvent but updates Asset projection."""
    indexer = EventIndexer()
    indexer.w3 = MagicMock()
    indexer.contract = MagicMock()

    raw_hash = uuid.uuid4().hex + uuid.uuid4().hex
    block_num = random.randint(1000, 9999)

    token_id = random.randint(1000000, 9999999)
    serial = f"DOC-DUP-{uuid.uuid4().hex[:6].upper()}"
    owner_wallet = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"

    log = {
        "transactionHash": bytes.fromhex(raw_hash),
        "blockNumber": block_num,
        "args": {
            "tokenId": token_id,
            "serialNumber": serial,
            "owner": owner_wallet,
            "ownerDID": f"did:ethr:13371:{owner_wallet}"
        }
    }

    event_name = "DigitalAssetMinted"

    # Insert AuditEvent manually to mimic already processed
    audit_event = AuditEvent(
        event_type=event_name,
        tx_hash=raw_hash,
        block_number=block_num,
        asset_serial=serial
    )
    db_session.add(audit_event)
    await db_session.commit()

    with patch.object(indexer, '_create_asset_record', new_callable=AsyncMock) as mock_create:
        success = await indexer._write_event(db_session, event_name, log, block_num)
        assert success is False  # Duplicate event returns False
        assert mock_create.called


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
