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


class _SkipAI(Exception):
    pass


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
        # Nothing can precede the contract's deployment block (recorded by deploy.js).
        try:
            from app.services.chain import load_deployment
            dep = load_deployment()
            genesis = max(0, int(dep.get("deployBlock") or 0) - 1) if dep.get("address", "").lower() == self.contract.address.lower() else 0
        except Exception:
            genesis = 0
        if state is None:
            return genesis
        reason = None
        if state.contract_address.lower() != self.contract.address.lower():
            reason = "contract changed"
        elif state.last_block > head:
            reason = f"cursor {state.last_block} is beyond chain head {head}"
        elif state.last_block > 0 and self._block_hash(state.last_block) != state.last_block_hash:
            reason = f"block {state.last_block} hash differs"
        if reason is None:
            return state.last_block
        logger.warning(f"Indexer cursor invalid ({reason}); rescanning from block {genesis} without deleting any rows")
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
        return genesis

    async def _is_indexed(self, session: AsyncSession, tx_hash: str, log_index: Optional[int] = None) -> bool:
        """Is this exact chain LOG (tx hash + log index) already in the audit trail?
        A transaction can emit several events; each is recorded once."""
        result = await session.execute(
            select(AuditEvent.id).filter(AuditEvent.tx_hash == tx_hash,
                                         AuditEvent.log_index.is_(None) if log_index is None else AuditEvent.log_index == log_index).limit(1)
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
        log_index = log.get("logIndex")
        already_indexed = await self._is_indexed(session, tx_hash, log_index)

        if already_indexed:
            logger.debug(f"Skipping already-indexed audit tx: {tx_hash}")
            return False

        anomaly: Optional[dict] = None
        actor_did: Optional[str] = None
        target_did: Optional[str] = None
        asset_serial: Optional[str] = None
        actor_address: Optional[str] = None

        if event_name in ["AssetMinted", "DigitalAssetMinted"]:
            asset_serial = args.get("serialNumber")
            # The actor of a mint is the transaction sender (the approving minter); the
            # token holder is the target. (Resolved from the transaction below.)
            actor_address = None
            target_did = args.get("ownerDID")
            token_id = args.get("tokenId")
            anomaly = await self._reconcile_mint(session, event_name, args)

        elif event_name == "DigitalAssetUpdated":
            token_id = args.get("tokenId")
            actor_address = args.get("updater")
            actor_did = f"did:ethr:{settings.CHAIN_ID}:{actor_address.lower()}" if actor_address else None
            try:
                asset_info = self.contract.functions.getDigitalAsset(token_id).call()
                asset_serial = asset_info[0]
            except Exception:
                asset_serial = f"TOKEN-{token_id}"

            anomaly = await self._reconcile_anchor(session, token_id, args.get("newFileHash"))

        elif event_name == "AssetTransferred":
            token_id = args.get("tokenId")
            if token_id is not None:
                try:
                    asset_info = self.contract.functions.getAsset(token_id).call()
                    asset_serial = asset_info[0]
                except Exception:
                    asset_serial = None
            actor_address = None  # the signer is resolved from the transaction below
            target_did = args.get("toDID")
            anomaly = await self._reconcile_transfer(session, token_id, args.get("newOwner"))

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

        elif event_name in ("RoleGranted", "RoleRevoked"):
            account = args.get("account")
            actor_address = args.get("sender")
            target_did = f"did:ethr:{settings.CHAIN_ID}:{account.lower()}" if account else None
            anomaly = await self._reconcile_role_event(session, event_name, args)

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
            if event_name in ("RoleGranted", "RoleRevoked"):
                # Role changes are judged by the deterministic expected-role rule above
                # (the behavioural model was not trained on them).
                raise _SkipAI()
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
                risk_factors["native_label"] = analysis.get("native_risk_label")
                risk_factors["label_basis"] = analysis.get("label_basis")
                risk_factors["actor_role"] = actor_role
                risk_factors["is_granted"] = is_granted
        except _SkipAI:
            risk_score, risk_label, risk_factors = 0.0, "LOW", {"rule": "expected_role_check"}
        except Exception as e:
            logger.error(f"AI Risk Engine failed: {e}")
            risk_score, risk_label, risk_factors = None, None, None

        if anomaly:
            # Deterministic integrity rule (not an AI judgement): the chain disagrees with
            # the LexCorp registry. Raised as HIGH so humans triage it.
            risk_label = "HIGH"
            risk_score = max(risk_score or 0.0, 0.9)
            risk_factors = {**(risk_factors or {}), "integrity_anomaly": anomaly}
            logger.warning(f"Chain/registry integrity anomaly on {event_name} tx={tx_hash}: {anomaly}")

        audit_event = AuditEvent(
            event_type=event_name,
            tx_hash=tx_hash,
            log_index=log_index,
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
                await raise_alert(session, audit_event, source="RULE" if anomaly else "AI")
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

    async def _user_by_wallet(self, session: AsyncSession, wallet: Optional[str]):
        if not wallet:
            return None
        return (await session.execute(select(User).where(func.lower(User.wallet_address) == wallet.lower()))).scalar_one_or_none()

    async def _reconcile_mint(self, session: AsyncSession, event_name: str, args: dict) -> Optional[dict]:
        """A mint must correspond to an approved LexCorp registry record with the same
        token ID, serial, owner and (digital) file hash. The registry is never rewritten
        from chain data and no identity is ever created here."""
        token_id, serial = args.get("tokenId"), args.get("serialNumber")
        asset = (await session.execute(select(Asset).where(Asset.token_id == token_id))).scalars().first()
        if asset is None:
            return {"rule": "UNREGISTERED_MINT", "token_id": token_id, "serial": serial, "owner": args.get("owner")}
        problems = []
        if (asset.serial_number or "") != (serial or ""):
            problems.append("serial")
        if event_name == "DigitalAssetMinted" and (asset.file_hash or "") != (args.get("fileHash") or ""):
            problems.append("file_hash")
        if (event_name == "DigitalAssetMinted") == bool(asset.is_physical):
            problems.append("asset_kind")
        if asset.approval_status not in ("APPROVED", "ACTIVE"):
            problems.append("not_approved")
        owner = await session.get(User, asset.owner_id) if asset.owner_id else None
        if not owner or (owner.wallet_address or "").lower() != (args.get("owner") or "").lower():
            problems.append("owner")
        if problems:
            return {"rule": "MINT_MISMATCH", "token_id": token_id, "serial": serial, "fields": problems}
        return None

    async def _reconcile_anchor(self, session: AsyncSession, token_id, new_hash: Optional[str]) -> Optional[dict]:
        """An anchored hash must equal an APPROVED version in the token's lineage."""
        root = (await session.execute(select(Asset).where(Asset.token_id == token_id))).scalars().first()
        if root is None:
            return {"rule": "ANCHOR_UNKNOWN_TOKEN", "token_id": token_id}
        root_id = root.root_asset_id or root.id
        match = (await session.execute(select(Asset).where(
            ((Asset.id == root_id) | (Asset.root_asset_id == root_id)) & (Asset.file_hash == new_hash)
        ))).scalars().first()
        if match is None or match.approval_status not in ("APPROVED", "ACTIVE"):
            return {"rule": "ANCHOR_HASH_NOT_APPROVED", "token_id": token_id, "new_hash": new_hash}
        return None

    async def _reconcile_transfer(self, session: AsyncSession, token_id, new_owner: Optional[str]) -> Optional[dict]:
        """Custody may only move to an active LexCorp identity; the registry follows it."""
        user = await self._user_by_wallet(session, new_owner)
        if user is None or not user.is_active:
            return {"rule": "TRANSFER_TO_UNKNOWN_IDENTITY", "token_id": token_id, "new_owner": new_owner}
        asset = (await session.execute(select(Asset).where(Asset.token_id == token_id))).scalars().first()
        if asset is None:
            return {"rule": "TRANSFER_OF_UNREGISTERED_TOKEN", "token_id": token_id}
        asset.owner_id = user.id
        await session.flush()
        return None

    async def _reconcile_role_event(self, session: AsyncSession, event_name: str, args: dict) -> Optional[dict]:
        """On-chain roles must match the LexCorp identity (see services/chain.py)."""
        from app.services.chain import desired_roles
        role_names = {}
        for name in ("MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE", "AUDITOR_ROLE", "REGISTRAR_ROLE", "DEFAULT_ADMIN_ROLE"):
            try:
                role_names[getattr(self.contract.functions, name)().call()] = name
            except Exception:
                pass
        role = role_names.get(args.get("role"), "UNKNOWN_ROLE")
        if event_name == "RoleRevoked" or role in ("REGISTRAR_ROLE", "DEFAULT_ADMIN_ROLE"):
            if role in ("REGISTRAR_ROLE", "DEFAULT_ADMIN_ROLE") and event_name == "RoleGranted":
                try:
                    from app.services.chain import load_deployment
                    d = load_deployment()
                    expected = {d.get("admin", "").lower(), d.get("registrar", "").lower()}
                except Exception:
                    expected = set()
                # Legitimate when granted by the governance admin (including a registrar that was
                # later rotated away) or when it names the currently recorded admin/registrar.
                admin = (d.get("admin") or "").lower() if expected else ""
                if (args.get("account") or "").lower() not in expected and (args.get("sender") or "").lower() != admin:
                    return {"rule": "UNEXPECTED_GOVERNANCE_GRANT", "role": role, "account": args.get("account"), "sender": args.get("sender")}
            return None
        user = await self._user_by_wallet(session, args.get("account"))
        if user is None or role not in desired_roles(user.role, bool(user.is_active)):
            return {"rule": "UNEXPECTED_ROLE_GRANT", "role": role, "account": args.get("account"),
                    "identity_role": user.role if user else None}
        return None

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
            ("RoleGranted", self.contract.events.RoleGranted),
            ("RoleRevoked", self.contract.events.RoleRevoked),
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
