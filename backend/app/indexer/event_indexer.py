"""Event Indexer — polls contract events and writes idempotent AuditEvent rows.

Architecture:
- Polls AssetMinted, DigitalAssetMinted, AssetTransferred, AssetRevoked,
  AccessPermissionGranted, AccessPermissionRevoked, AccessAttempted events.
- Each event is written exactly once (idempotent: skips already-indexed tx_hash).
- AuditEvent rows originate ONLY from chain events — never from API call handlers.
- Safe to re-run: processes new blocks only, no duplicates on restart.
"""

import asyncio
import logging
from typing import Optional
from datetime import datetime

from sqlalchemy import delete, select, func
from sqlalchemy.ext.asyncio import AsyncSession
from web3 import Web3

from app.core.config import settings
from app.core.database import async_session_factory
from app.models.domain import AuditEvent, Asset, User
from app.services.ai import ai_engine

logger = logging.getLogger(__name__)


class EventIndexer:
    """Background service that indexes blockchain events into the audit trail."""

    def __init__(self):
        self.w3: Optional[Web3] = None
        self.contract: Optional[object] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_indexed_block = 0

    def _load_contract(self) -> None:
        """Load contract ABI and instantiate Web3."""
        import json

        deployment_path = settings.CONTRACT_DEPLOYMENT_PATH

        with open(deployment_path, "r") as f:
            deployment = json.load(f)

        self.w3 = Web3(Web3.HTTPProvider(settings.RPC_URL))
        if not self.w3.is_connected():
            raise ConnectionError(f"Cannot connect to RPC at {settings.RPC_URL}")

        address = Web3.to_checksum_address(deployment["address"])
        self.contract = self.w3.eth.contract(address=address, abi=deployment["abi"])
        logger.info(f"Contract loaded at {address}, current block: {self.w3.eth.block_number}")

    async def _get_session(self) -> AsyncSession:
        return async_session_factory()

    async def _fetch_last_indexed_block(self) -> int:
        """Query the DB for the highest-indexed block number."""
        session = await self._get_session()
        try:
            result = await session.execute(
                select(AuditEvent.block_number).order_by(AuditEvent.block_number.desc()).limit(1)
            )
            row = result.scalar_one_or_none()
            return row if row is not None else 0
        finally:
            await session.close()

    async def _clear_stale_chain_data(self) -> None:
        """Remove indexed rows from a replaced local chain before re-indexing."""
        session = await self._get_session()
        try:
            await session.execute(delete(AuditEvent))
            await session.execute(delete(Asset))
            await session.commit()
            logger.warning("Cleared audit and asset rows from the previous chain")
        finally:
            await session.close()

    async def _is_indexed(self, session: AsyncSession, tx_hash: str) -> bool:
        """Check if a tx_hash is already in the audit trail."""
        result = await session.execute(
            select(AuditEvent.id).filter(AuditEvent.tx_hash == tx_hash).limit(1)
        )
        return result.scalar_one_or_none() is not None

    async def _write_event(
        self,
        session: AsyncSession,
        event_name: str,
        log: dict,
        block_number: int,
    ) -> bool:
        """Write one event as an AuditEvent row. Returns True if written, False if skipped."""
        tx_hash = log["transactionHash"].hex()

        args = log.get("args", {})
        already_indexed = await self._is_indexed(session, tx_hash)

        # Audit rows are immutable, but asset projections may need rebuilding
        # after a database reset or schema repair.
        if already_indexed:
            if event_name in ["AssetMinted", "DigitalAssetMinted"]:
                token_id = args.get("tokenId")
                asset_serial = args.get("serialNumber")
                actor_address = args.get("owner")
                if actor_address and token_id is not None:
                    await self._create_asset_record(session, actor_address, asset_serial, token_id, args)
            elif event_name == "AssetTransferred":
                token_id = args.get("tokenId")
                new_owner = args.get("newOwner")
                if new_owner and token_id is not None:
                    asset_info = self.contract.functions.getAsset(token_id).call()
                    await self._create_asset_record(session, new_owner, asset_info[0], token_id, args)
            logger.debug(f"Skipping already-indexed audit tx: {tx_hash}")
            return False

        actor_did: Optional[str] = None
        target_did: Optional[str] = None
        asset_serial: Optional[str] = None
        actor_address: Optional[str] = None

        if event_name in ["AssetMinted", "DigitalAssetMinted"]:
            asset_serial = args.get("serialNumber")
            actor_address = args.get("owner")
            target_did = args.get("ownerDID")
            token_id = args.get("tokenId")
            if actor_address and token_id is not None:
                await self._create_asset_record(session, actor_address, asset_serial, token_id, args)

        elif event_name == "DigitalAssetUpdated":
            token_id = args.get("tokenId")
            actor_address = args.get("updater")
            actor_did = f"did:ethr:{settings.CHAIN_ID}:{actor_address.lower()}" if actor_address else None
            try:
                asset_info = self.contract.functions.getDigitalAsset(token_id).call()
                asset_serial = asset_info[0]
            except Exception:
                asset_serial = f"TOKEN-{token_id}"

        elif event_name == "AssetTransferred":
            token_id = args.get("tokenId")
            if token_id is not None:
                try:
                    asset_info = self.contract.functions.getAsset(token_id).call()
                    asset_serial = asset_info[0]
                except Exception:
                    asset_serial = None
            actor_address = args.get("newOwner")
            target_did = args.get("toDID")
            if actor_address and token_id is not None:
                await self._create_asset_record(session, actor_address, asset_serial, token_id, args)

        elif event_name == "AssetRevoked":
            asset_serial = args.get("serialNumber")
            token_id = args.get("tokenId")
            actor_address = None
            try:
                if asset_serial:
                    asset_res = await session.execute(select(Asset).filter(Asset.serial_number == asset_serial))
                    asset_row = asset_res.scalar_one_or_none()
                    if asset_row:
                        owner_res = await session.execute(select(User.did).filter(User.id == asset_row.owner_id))
                        target_did = owner_res.scalar_one_or_none()
                        # Remove the DB Asset record since the NFT is burned on-chain
                        await session.delete(asset_row)
                        await session.flush()
            except Exception:
                pass

        elif event_name in ["AccessPermissionGranted", "AccessPermissionRevoked"]:
            token_id = args.get("tokenId")
            target_did = args.get("targetDID")
            actor_address = args.get("grantedBy") or args.get("revokedBy")
            try:
                asset_info = self.contract.functions.getAsset(token_id).call()
                asset_serial = asset_info[0]
            except Exception:
                asset_serial = f"TOKEN-{token_id}"

        elif event_name == "AccessAttempted":
            token_id = args.get("tokenId")
            actor_did = args.get("actorDID")
            granted = args.get("granted", True)
            try:
                asset_info = self.contract.functions.getAsset(token_id).call()
                asset_serial = asset_info[0]
                target_did = asset_info[1]
            except Exception:
                asset_serial = f"TOKEN-{token_id}"
                try:
                    asset_res = await session.execute(select(Asset).filter(Asset.token_id == token_id))
                    asset_row = asset_res.scalar_one_or_none()
                    if asset_row:
                        asset_serial = asset_row.serial_number
                        owner_res = await session.execute(select(User.did).filter(User.id == asset_row.owner_id))
                        target_did = owner_res.scalar_one_or_none()
                except Exception:
                    pass

        if not actor_address and not actor_did:
            try:
                tx_data = self.w3.eth.get_transaction(log["transactionHash"])
                if tx_data and "from" in tx_data:
                    actor_address = tx_data["from"]
                    actor_did = f"did:ethr:{settings.CHAIN_ID}:{actor_address.lower()}"
            except Exception:
                pass

        if actor_address and not actor_did:
            actor_did = f"did:ethr:{settings.CHAIN_ID}:{actor_address.lower()}"

        # Look up actor role from DB if available
        actor_role = "USER"
        if actor_did or actor_address:
            try:
                user_q = select(User.role).filter(
                    (func.lower(User.did) == (actor_did or "").lower()) |
                    (func.lower(User.wallet_address) == (actor_address or "").lower())
                )
                res = await session.execute(user_q)
                found_role = res.scalar_one_or_none()
                if found_role:
                    actor_role = found_role
            except Exception:
                pass

        # Record event in actor cache for behavioral modeling
        is_granted = True
        if event_name == "AccessAttempted":
            is_granted = args.get("granted", True)

        ai_engine.record_event(
            actor_did=actor_did,
            event_type=event_name,
            granted=is_granted
        )

        try:
            # AI/ML Behavioral Analysis using the production model
            analysis = ai_engine.analyze_event(
                event_type=event_name,
                actor_role=actor_role,
                actor_did=actor_did,
                target_did=target_did,
                is_write=event_name in ["AssetMinted", "DigitalAssetMinted", "DigitalAssetUpdated", "AssetTransferred", "AssetRevoked"],
                asset_sensitivity_tier=0
            )
            risk_score = analysis.get("risk_score")
            risk_label = analysis.get("risk_label")
            risk_factors = analysis.get("features", {})
            if risk_factors:
                risk_factors["anomaly_score"] = analysis.get("anomaly_score")
                risk_factors["actor_role"] = actor_role
                risk_factors["is_granted"] = is_granted
        except Exception as e:
            logger.error(f"AI Risk Engine failed: {e}")
            risk_score, risk_label, risk_factors = None, None, None

        audit_event = AuditEvent(
            event_type=event_name,
            tx_hash=tx_hash,
            block_number=block_number,
            actor_did=actor_did,
            target_did=target_did,
            asset_serial=asset_serial,
            risk_score=risk_score,
            risk_label=risk_label,
            risk_factors=risk_factors,
        )
        try:
            session.add(audit_event)
            await session.commit()
            logger.info(
                f"[{event_name}] tx={tx_hash} block={block_number} "
                f"actor={actor_did} target={target_did} serial={asset_serial}"
            )
            return True
        except Exception as e:
            await session.rollback()
            logger.error(f"Failed to commit audit event {event_name} ({tx_hash}): {e}")
            return False

    async def _create_asset_record(
        self,
        session: AsyncSession,
        actor_address: str,
        asset_serial: str,
        token_id: int,
        args: dict,
    ) -> None:
        """Create or update Asset record for minted asset."""
        from sqlalchemy import or_
        try:
            result = await session.execute(
                select(User).where(func.lower(User.wallet_address) == actor_address.lower())
            )
            user_obj = result.scalar_one_or_none()
            if not user_obj:
                user_obj = User(
                    wallet_address=actor_address.lower(),
                    name=args.get("ownerName", "Unknown"),
                    contact_number=args.get("contactNumber", None),
                    did=f"did:ethr:{settings.CHAIN_ID}:{actor_address.lower()}",
                    role="USER",
                    is_active=True
                )
                session.add(user_obj)
                await session.flush()
            owner_id = user_obj.id

            result = await session.execute(
                select(Asset).where(
                    or_(
                        Asset.token_id == token_id,
                        func.lower(Asset.serial_number) == asset_serial.lower()
                    )
                )
            )
            existing_asset = result.scalar_one_or_none()
            if existing_asset:
                existing_asset.owner_id = owner_id
                existing_asset.token_id = token_id
                existing_asset.serial_number = asset_serial
                if args.get("offchainURI"):
                    existing_asset.metadata_cid = args.get("offchainURI")
            else:
                asset = Asset(
                    token_id=token_id,
                    serial_number=asset_serial,
                    metadata_cid=args.get("offchainURI"),
                    owner_id=owner_id
                )
                session.add(asset)
            await session.flush()
        except Exception as e:
            await session.rollback()
            logger.error(f"Failed to create Asset record: {e}")

    async def _index_block(self, from_block: int, to_block: Optional[int] = None) -> int:
        """Index all events from a range of blocks. Returns count of newly-written events."""
        session = await self._get_session()
        written = 0
        if to_block is None:
            to_block = from_block

        events = [
            ("AssetMinted", self.contract.events.AssetMinted),
            ("DigitalAssetMinted", self.contract.events.DigitalAssetMinted),
            ("DigitalAssetUpdated", self.contract.events.DigitalAssetUpdated),
            ("AssetTransferred", self.contract.events.AssetTransferred),
            ("AssetRevoked", self.contract.events.AssetRevoked),
            ("AccessPermissionGranted", self.contract.events.AccessPermissionGranted),
            ("AccessPermissionRevoked", self.contract.events.AccessPermissionRevoked),
            ("AccessAttempted", self.contract.events.AccessAttempted),
        ]

        try:
            for event_name, event_type in events:
                try:
                    entries = event_type().get_logs(from_block=from_block, to_block=to_block)
                except Exception:
                    try:
                        entries = event_type().get_logs(fromBlock=from_block, toBlock=to_block)
                    except Exception as e:
                        logger.warning(f"Error fetching {event_name} logs from {from_block} to {to_block}: {e}")
                        continue

                for log in entries:
                    block_num = log.get("blockNumber", to_block)
                    if await self._write_event(session, event_name, log, block_num):
                        written += 1

            self._last_indexed_block = max(self._last_indexed_block, to_block)
        finally:
            await session.close()

        return written

    async def catch_up(self, from_block: int, to_block: Optional[int] = None) -> dict:
        self._load_contract()
        current_head = to_block if to_block else self.w3.eth.block_number
        logger.info(f"Catch-up: blocks {from_block} → {current_head}")

        written = await self._index_block(from_block, current_head)
        logger.info(f"Catch-up complete: {written} new events indexed")
        return {
            "from_block": from_block,
            "to_block": current_head,
            "events_written": written,
        }

    async def run(self) -> None:
        self._load_contract()
        self._running = True

        current_head = self.w3.eth.block_number
        if self._last_indexed_block > current_head:
            logger.info(
                f"Chain reset detected (last indexed block {self._last_indexed_block} > current head {current_head}). "
                f"Resetting indexer to block 0."
            )
            await self._clear_stale_chain_data()
            self._last_indexed_block = 0

        logger.info(
            f"EventIndexer polling started from block {self._last_indexed_block + 1}, "
            f"contract: {self.contract.address}"
        )

        while self._running:
            try:
                if not self.w3.is_connected():
                    self._load_contract()

                current_head = self.w3.eth.block_number
                if current_head > self._last_indexed_block:
                    target_block = min(current_head, self._last_indexed_block + 500)
                    written = await self._index_block(self._last_indexed_block + 1, target_block)
                    if written > 0:
                        logger.info(f"Indexed blocks {self._last_indexed_block + 1} to {target_block}: {written} new event(s)")
                    else:
                        self._last_indexed_block = target_block

            except ConnectionError as e:
                logger.error(f"RPC connection error: {e}")
                await asyncio.sleep(10)
            except Exception as e:
                logger.error(f"Indexer loop error: {e}")
                await asyncio.sleep(5)

            await asyncio.sleep(5)

    def stop(self) -> None:
        self._running = False
        logger.info("EventIndexer polling stopped")

    async def start_background(self) -> None:
        try:
            self._last_indexed_block = await self._fetch_last_indexed_block()
        except Exception as e:
            logger.warning(f"Could not restore last indexed block from DB: {e}")
            self._last_indexed_block = 0

        self._task = asyncio.create_task(self.run())
        logger.info(f"Indexer background task started (last indexed block: {self._last_indexed_block})")


_indexer: Optional[EventIndexer] = None


async def get_indexer() -> EventIndexer:
    global _indexer
    if _indexer is None:
        _indexer = EventIndexer()
    return _indexer
