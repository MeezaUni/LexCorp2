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

from sqlalchemy import select, func
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

    def _block_hash(self, block: int) -> str:
        """Block hash via raw JSON-RPC (web3's get_block rejects QBFT's long extraData)."""
        resp = self.w3.provider.make_request("eth_getBlockByNumber", [hex(block), False])
        result = resp.get("result") if isinstance(resp, dict) else None
        if not result:
            raise ConnectionError(f"Block {block} not available from RPC")
        return result["hash"]

    async def _load_state(self):
        from app.models.domain import IndexerState
        session = await self._get_session()
        try:
            return (await session.execute(select(IndexerState).where(IndexerState.id == 1))).scalar_one_or_none()
        finally:
            await session.close()

    async def _save_state(self, block: int) -> None:
        """Persist the cursor with the block hash so a replaced chain is detectable."""
        from app.models.domain import IndexerState
        block_hash = self._block_hash(block) if block > 0 else "genesis"
        session = await self._get_session()
        try:
            state = (await session.execute(select(IndexerState).where(IndexerState.id == 1))).scalar_one_or_none()
            if state is None:
                session.add(IndexerState(id=1, contract_address=self.contract.address, last_block=block, last_block_hash=block_hash))
            else:
                state.contract_address, state.last_block, state.last_block_hash = self.contract.address, block, block_hash
            await session.commit()
        finally:
            await session.close()

    async def _validated_cursor(self) -> int:
        """Resume point on THIS chain and contract. A different contract, a cursor beyond the
        head, or a block-hash mismatch means the chain was replaced: rescan from block 0.
        Nothing is ever deleted (events are de-duplicated by tx hash; pre-reset history stays)."""
        state = await self._load_state()
        head = self.w3.eth.block_number
        if state is None:
            return 0
        reason = None
        if state.contract_address.lower() != self.contract.address.lower():
            reason = "contract changed"
        elif state.last_block > head:
            reason = f"cursor {state.last_block} is beyond chain head {head}"
        elif state.last_block > 0 and self._block_hash(state.last_block) != state.last_block_hash:
            reason = f"block {state.last_block} hash differs"
        if reason is None:
            return state.last_block
        logger.warning(f"Indexer cursor invalid ({reason}); rescanning from block 0 without deleting any rows")
        session = await self._get_session()
        try:
            import hashlib, time
            session.add(AuditEvent(
                event_type="INDEXER_RESCAN", block_number=0,
                tx_hash="0x" + hashlib.sha256(f"rescan:{time.time_ns()}".encode()).hexdigest(),
                risk_factors={"reason": reason, "previous_cursor": state.last_block, "head": head,
                              "contract": self.contract.address},
            ))
            await session.commit()
        finally:
            await session.close()
        return 0

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
                    await self._create_asset_record(session, actor_address, asset_serial, token_id, args, event_name=event_name)
                    await session.commit()
            elif event_name == "AssetTransferred":
                token_id = args.get("tokenId")
                new_owner = args.get("newOwner")
                if new_owner and token_id is not None:
                    try:
                        asset_info = self.contract.functions.getAsset(token_id).call()
                        serial = asset_info[0]
                    except Exception:
                        serial = f"TOKEN-{token_id}"
                    await self._create_asset_record(session, new_owner, serial, token_id, args, event_name=event_name)
                    await session.commit()
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
                await self._create_asset_record(session, actor_address, asset_serial, token_id, args, event_name=event_name)

        elif event_name == "DigitalAssetUpdated":
            token_id = args.get("tokenId")
            actor_address = args.get("updater")
            actor_did = f"did:ethr:{settings.CHAIN_ID}:{actor_address.lower()}" if actor_address else None
            try:
                asset_info = self.contract.functions.getDigitalAsset(token_id).call()
                asset_serial = asset_info[0]
            except Exception:
                asset_serial = f"TOKEN-{token_id}"

            # Sync DB asset if present
            if token_id is not None:
                try:
                    res = await session.execute(select(Asset).where(Asset.token_id == token_id))
                    asset_obj = res.scalar_one_or_none()
                    if asset_obj:
                        if args.get("newFileHash"):
                            asset_obj.file_hash = args.get("newFileHash")
                        if args.get("newOffchainURI"):
                            asset_obj.metadata_cid = args.get("newOffchainURI")
                        asset_obj.is_physical = False
                        asset_obj.asset_type = "DOCUMENT"
                        await session.flush()
                except Exception as e:
                    logger.warning(f"Error syncing updated digital asset token {token_id}: {e}")

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
                await self._create_asset_record(session, actor_address, asset_serial, token_id, args, event_name=event_name)

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
                        # The NFT is burned on-chain: keep the registry record and its history,
                        # mark it revoked (a hard delete destroyed versions, actions and audit links).
                        asset_row.lifecycle_status = "REVOKED"
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
            if (risk_label or "").upper() in ("HIGH", "CRITICAL"):
                from app.services.alerts import raise_alert
                await raise_alert(session, audit_event, source="AI")
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
        event_name: str = "AssetMinted",
    ) -> None:
        """Create or update Asset record for minted asset."""
        from sqlalchemy import or_
        is_digital = event_name == "DigitalAssetMinted" or bool(args.get("fileHash")) or (asset_serial and asset_serial.startswith("DOC-"))
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
                if args.get("fileHash"):
                    existing_asset.file_hash = args.get("fileHash")
                if is_digital:
                    existing_asset.is_physical = False
                    existing_asset.asset_type = "DOCUMENT"
                    if not existing_asset.name or "Defense Equipment" in (existing_asset.name or ""):
                        existing_asset.name = f"Digital Document {asset_serial}"
                elif event_name == "AssetMinted":
                    existing_asset.is_physical = True
                    existing_asset.asset_type = "EQUIPMENT"
            else:
                asset = Asset(
                    token_id=token_id,
                    serial_number=asset_serial,
                    name=f"Digital Document {asset_serial}" if is_digital else f"Defense Equipment {asset_serial}",
                    asset_type="DOCUMENT" if is_digital else "EQUIPMENT",
                    metadata_cid=args.get("offchainURI"),
                    file_hash=args.get("fileHash") if is_digital else None,
                    is_physical=not is_digital,
                    owner_id=owner_id
                )
                session.add(asset)
            await session.flush()
            logger.info(f"Asset record added/updated to session for token {token_id}, serial {asset_serial}, owner {owner_id}, is_digital={is_digital}")
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

        failed = False
        try:
            for event_name, event_type in events:
                try:
                    entries = event_type().get_logs(from_block=from_block, to_block=to_block)
                except Exception:
                    try:
                        entries = event_type().get_logs(fromBlock=from_block, toBlock=to_block)
                    except Exception as e:
                        logger.warning(f"Error fetching {event_name} logs from {from_block} to {to_block}: {e}")
                        failed = True
                        continue

                for log in entries:
                    block_num = log.get("blockNumber", to_block)
                    if await self._write_event(session, event_name, log, block_num):
                        written += 1

            if failed:
                raise ConnectionError(f"Log fetch failed for blocks {from_block}-{to_block}; cursor not advanced")
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

        self._last_indexed_block = await self._validated_cursor()

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
                    first = self._last_indexed_block + 1
                    written = await self._index_block(first, target_block)
                    await self._save_state(self._last_indexed_block)
                    if written > 0:
                        logger.info(f"Indexed blocks {first} to {target_block}: {written} new event(s)")

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
        self._last_indexed_block = 0  # validated against the chain in run()

        self._task = asyncio.create_task(self.run())
        logger.info(f"Indexer background task started (last indexed block: {self._last_indexed_block})")


_indexer: Optional[EventIndexer] = None


async def get_indexer() -> EventIndexer:
    global _indexer
    if _indexer is None:
        _indexer = EventIndexer()
    return _indexer
