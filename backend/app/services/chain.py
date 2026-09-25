"""Chain integrity checks and on-chain role synchronisation.

The backend's chain-operator key holds ONLY REGISTRAR_ROLE on AssetNFT v3. It is used
to make on-chain roles follow the LexCorp2 identity lifecycle:

    ADMIN, MANAGER (active)  -> MINTER_ROLE, ANCHOR_ROLE, MANAGER_ROLE
    AUDITOR (active)         -> AUDITOR_ROLE
    USER, or any revoked/deactivated identity -> no operational role

The contract forbids the registrar from ever holding an operational role itself, so
this key cannot mint, anchor, transfer or burn. Every change is receipt-verified and
audited; `reconcile_all` is run periodically so a missed update is corrected.
"""

import json
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

from eth_account import Account
from web3 import Web3

from app.core.config import settings

logger = logging.getLogger(__name__)

OPERATIONAL_ROLES = ("MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE", "AUDITOR_ROLE")
ROLE_MAP = {
    "ADMIN": {"MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE"},
    "MANAGER": {"MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE"},
    "AUDITOR": {"AUDITOR_ROLE"},
    "USER": set(),
}

_lock = threading.Lock()  # serialises operator nonces


class ChainUnavailable(RuntimeError):
    pass


@dataclass
class DeploymentStatus:
    ok: bool
    checks: dict = field(default_factory=dict)
    address: Optional[str] = None
    chain_id: Optional[int] = None
    head: Optional[int] = None
    registrar_ok: Optional[bool] = None


def _w3() -> Web3:
    return Web3(Web3.HTTPProvider(settings.RPC_URL, request_kwargs={"timeout": 10}))


def load_deployment() -> dict:
    with open(settings.CONTRACT_DEPLOYMENT_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def desired_roles(role: str, is_active: bool) -> set:
    return set(ROLE_MAP.get(role, set())) if is_active else set()


def verify_deployment() -> DeploymentStatus:
    """Read-only integrity check of the configured network and contract."""
    st = DeploymentStatus(ok=False)
    try:
        d = load_deployment()
    except Exception as e:
        st.checks["deployment_record"] = f"missing: {e.__class__.__name__}"
        return st
    st.address = d.get("address")
    try:
        w3 = _w3()
        st.chain_id = w3.eth.chain_id
        st.head = w3.eth.block_number
        code = w3.eth.get_code(Web3.to_checksum_address(d["address"]))
    except Exception as e:
        st.checks["rpc"] = f"unreachable: {e.__class__.__name__}"
        return st
    st.checks["chain_id"] = st.chain_id == settings.CHAIN_ID
    st.checks["code_present"] = len(code) > 0
    st.checks["bytecode_matches_record"] = Web3.keccak(code).hex().removeprefix("0x") == str(d.get("runtimeBytecodeKeccak", "")).removeprefix("0x")
    st.checks["contract_version_3"] = d.get("contractVersion") == 3
    if settings.CHAIN_OPERATOR_PRIVATE_KEY:
        try:
            c = w3.eth.contract(address=Web3.to_checksum_address(d["address"]), abi=d["abi"])
            me = Account.from_key(settings.CHAIN_OPERATOR_PRIVATE_KEY).address
            st.registrar_ok = bool(c.functions.hasRole(c.functions.REGISTRAR_ROLE().call(), me).call())
            st.checks["operator_is_registrar"] = st.registrar_ok
        except Exception as e:
            st.checks["operator_is_registrar"] = f"error: {e.__class__.__name__}"
    st.ok = all(v is True for v in st.checks.values())
    return st


class RoleSync:
    def __init__(self):
        if not settings.CHAIN_OPERATOR_PRIVATE_KEY:
            raise ChainUnavailable("CHAIN_OPERATOR_PRIVATE_KEY is not configured")
        self.w3 = _w3()
        d = load_deployment()
        self.contract = self.w3.eth.contract(address=Web3.to_checksum_address(d["address"]), abi=d["abi"])
        self.account = Account.from_key(settings.CHAIN_OPERATOR_PRIVATE_KEY)
        self.role_ids = {r: getattr(self.contract.functions, r)().call() for r in OPERATIONAL_ROLES}

    def onchain_role_holders(self) -> set:
        """Every account that was ever granted an operational role (AccessControl is not
        enumerable, so membership is rebuilt from RoleGranted logs since deployment)."""
        d = load_deployment()
        start = int(d.get("deployBlock") or 0)
        head = self.w3.eth.block_number
        op_ids = {rid for rid in self.role_ids.values()}
        topic = "0x" + Web3.keccak(text="RoleGranted(bytes32,address,address)").hex().removeprefix("0x")
        holders = set()
        for a in range(start, head + 1, 1000):
            logs = self.w3.eth.get_logs({"address": self.contract.address, "fromBlock": a,
                                         "toBlock": min(a + 999, head), "topics": [topic]})
            for lg in logs:
                if bytes(lg["topics"][1]) in op_ids:
                    holders.add(Web3.to_checksum_address("0x" + bytes(lg["topics"][2]).hex()[-40:]))
        return holders

    def current_roles(self, wallet: str) -> set:
        a = Web3.to_checksum_address(wallet)
        return {r for r, rid in self.role_ids.items() if self.contract.functions.hasRole(rid, a).call()}

    def _send(self, fn) -> str:
        with _lock:
            tx = fn.build_transaction({
                "from": self.account.address,
                "nonce": self.w3.eth.get_transaction_count(self.account.address, "pending"),
                "gasPrice": 0,
                "chainId": settings.CHAIN_ID,
            })
            tx["gas"] = int(self.w3.eth.estimate_gas(tx) * 1.2)
            signed = self.account.sign_transaction(tx)
            h = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        rcpt = self.w3.eth.wait_for_transaction_receipt(h, timeout=60)
        if rcpt.status != 1:
            raise ChainUnavailable(f"role transaction reverted: {h.hex()}")
        return h.hex()

    def sync(self, wallet: str, role: str, is_active: bool) -> dict:
        want = desired_roles(role, is_active)
        have = self.current_roles(wallet)
        a = Web3.to_checksum_address(wallet)
        granted, revoked, txs = [], [], []
        # Revoke first so a demotion never leaves a window with extra power.
        for r in sorted(have - want):
            txs.append(self._send(self.contract.functions.revokeRole(self.role_ids[r], a)))
            revoked.append(r)
        for r in sorted(want - have):
            txs.append(self._send(self.contract.functions.grantRole(self.role_ids[r], a)))
            granted.append(r)
        after = self.current_roles(wallet)
        if after != want:
            raise ChainUnavailable(f"on-chain roles for {a} did not converge")
        return {"wallet": a, "granted": granted, "revoked": revoked, "roles": sorted(after), "tx_hashes": txs}


async def sync_user_chain_roles(db, user, *, actor_did: Optional[str] = None, client_ip: Optional[str] = None) -> dict:
    """Converge one user's on-chain roles with their LexCorp2 role and status.
    Never raises: failures are audited (HIGH) and returned so callers can surface them;
    the periodic reconciler retries."""
    import asyncio
    from app.api.dependencies import record_audit

    try:
        result = await asyncio.to_thread(lambda: RoleSync().sync(user.wallet_address, user.role, bool(user.is_active)))
    except Exception as e:
        logger.error("On-chain role sync failed for %s: %s", user.wallet_address, e)
        await record_audit(db, "CHAIN_ROLE_SYNC_FAILED", actor_did=actor_did, target_did=user.did, client_ip=client_ip,
                           details={"error": str(e)[:300], "role": user.role, "active": bool(user.is_active)}, risk_label="HIGH")
        await db.commit()
        return {"ok": False, "error": "On-chain role update failed; it will be retried automatically."}
    if result["granted"] or result["revoked"]:
        await record_audit(db, "CHAIN_ROLES_UPDATED", actor_did=actor_did, target_did=user.did, client_ip=client_ip,
                           details=result)
        await db.commit()
    return {"ok": True, **result}


async def reconcile_all(db) -> dict:
    """Converge on-chain roles with the identity registry (periodic safety net):
    every registered identity gets exactly its expected roles, and any on-chain role
    holder that is NOT a registered identity loses its operational roles."""
    import asyncio
    from sqlalchemy import select
    from app.api.dependencies import record_audit
    from app.models.domain import User

    users = (await db.execute(select(User))).scalars().all()
    ok = failed = orphans = 0
    known = set()
    for u in users:
        if not u.wallet_address:
            continue
        known.add(u.wallet_address.lower())
        r = await sync_user_chain_roles(db, u, actor_did="system:role-reconciler")
        ok, failed = (ok + 1, failed) if r["ok"] else (ok, failed + 1)
    try:
        rs = await asyncio.to_thread(RoleSync)
        holders = await asyncio.to_thread(rs.onchain_role_holders)
        for wallet in sorted(h for h in holders if h.lower() not in known):
            result = await asyncio.to_thread(rs.sync, wallet, "USER", False)
            if result["revoked"]:
                orphans += 1
                await record_audit(db, "CHAIN_ROLES_REVOKED_UNREGISTERED", actor_did="system:role-reconciler",
                                   target_did=f"did:ethr:{settings.CHAIN_ID}:{wallet.lower()}", details=result, risk_label="HIGH")
                await db.commit()
    except Exception as e:
        logger.error("Orphan on-chain role sweep failed: %s", e)
        failed += 1
    return {"synced": ok, "failed": failed, "unregistered_revoked": orphans}
