"""Indexer cursor safety: no data deletion on chain replacement, no skipped events."""

import random
import uuid
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.indexer.event_indexer import EventIndexer
from app.models.domain import Asset, AuditEvent, IndexerState, User

CONTRACT = "0x0165878A594ca255338adfa4d48449f69242Eb8F"


@pytest.fixture
async def indexer():
    engine = create_async_engine(settings.DATABASE_URL)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    ix = EventIndexer()
    ix.w3 = MagicMock()
    ix.contract = MagicMock()
    ix.contract.address = CONTRACT
    async def _session():
        return factory()
    ix._get_session = _session
    async with factory() as s:
        await s.execute(delete(IndexerState))
        await s.commit()
    yield ix, factory
    async with factory() as s:
        await s.execute(delete(IndexerState))
        await s.commit()
    await engine.dispose()


def chain(head, hashes):
    """(head, provider.make_request stub) answering eth_getBlockByNumber like Besu does."""
    def make_request(method, params):
        assert method == "eth_getBlockByNumber"
        n = int(params[0], 16)
        return {"result": {"hash": hashes.get(n, f"0xh{n}")}}
    return head, make_request


async def counts(factory):
    async with factory() as s:
        return ((await s.execute(select(func.count()).select_from(AuditEvent))).scalar_one(),
                (await s.execute(select(func.count()).select_from(Asset))).scalar_one())


@pytest.mark.asyncio
async def test_no_state_starts_from_zero(indexer):
    ix, _ = indexer
    ix.w3.eth.block_number = 100
    assert await ix._validated_cursor() == 0


@pytest.mark.asyncio
async def test_valid_cursor_resumes_and_is_saved_with_hash(indexer):
    ix, factory = indexer
    ix.w3.eth.block_number, ix.w3.provider.make_request = chain(500, {300: "0xgood"})
    await ix._save_state(300)
    async with factory() as s:
        st = (await s.execute(select(IndexerState))).scalar_one()
    assert st.last_block == 300 and st.last_block_hash == "0xgood" and st.contract_address == CONTRACT
    assert await ix._validated_cursor() == 300


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["hash", "beyond_head", "contract"])
async def test_replaced_chain_rescans_without_deleting_anything(indexer, case):
    ix, factory = indexer
    ix.w3.eth.block_number, ix.w3.provider.make_request = chain(500, {300: "0xold"})
    await ix._save_state(300)
    if case == "hash":
        ix.w3.eth.block_number, ix.w3.provider.make_request = chain(500, {300: "0xnew"})
    elif case == "beyond_head":
        ix.w3.eth.block_number = 120
    else:
        ix.contract.address = "0x" + "9" * 40
    before = await counts(factory)
    assert await ix._validated_cursor() == 0
    after = await counts(factory)
    assert after[1] == before[1]            # no asset rows deleted
    assert after[0] == before[0] + 1        # only the INDEXER_RESCAN audit row was added
    async with factory() as s:
        ev = (await s.execute(select(AuditEvent).where(AuditEvent.event_type == "INDEXER_RESCAN")
                              .order_by(AuditEvent.created_at.desc()))).scalars().first()
    assert ev.risk_factors["previous_cursor"] == 300


@pytest.mark.asyncio
async def test_failed_log_fetch_does_not_advance_cursor(indexer):
    ix, _ = indexer
    broken = MagicMock()
    broken.return_value.get_logs.side_effect = Exception("RPC range error")
    for name in ("AssetMinted", "DigitalAssetMinted", "DigitalAssetUpdated", "AssetTransferred", "AssetRevoked",
                 "AccessPermissionGranted", "AccessPermissionRevoked", "AccessAttempted"):
        setattr(ix.contract.events, name, broken)
    ix._last_indexed_block = 1000
    with pytest.raises(ConnectionError):
        await ix._index_block(1001, 1500)
    assert ix._last_indexed_block == 1000


@pytest.mark.asyncio
async def test_onchain_revoke_keeps_registry_record(db_session, indexer):
    ix, _ = indexer
    owner = (await db_session.execute(select(User).where(User.wallet_address == "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"))).scalar_one()
    serial = f"BURN-{uuid.uuid4().hex[:8]}"
    db_session.add(Asset(token_id=random.randint(10_000_000, 2_000_000_000), serial_number=serial, owner_id=owner.id, is_physical=True))
    await db_session.commit()
    log = {"transactionHash": bytes.fromhex(uuid.uuid4().hex * 2), "blockNumber": 42, "args": {"tokenId": 1, "serialNumber": serial}}
    with patch("app.indexer.event_indexer.ai_engine.analyze_event", return_value={"risk_score": 1, "risk_label": "LOW", "features": {}}), \
         patch("app.indexer.event_indexer.ai_engine.record_event"):
        assert await ix._write_event(db_session, "AssetRevoked", log, 42) is True
    row = (await db_session.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one()
    await db_session.refresh(row)
    assert row.lifecycle_status == "REVOKED"
