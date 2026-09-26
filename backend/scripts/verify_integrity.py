"""Read-only integrity check of the running LexCorp2 environment. Prints PASS/FAIL lines
(no secret values). Exit code 0 only when every check passes.

    cd backend && python scripts/verify_integrity.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select, text  # noqa: E402
from web3 import Web3  # noqa: E402

from app.core.database import async_session_factory  # noqa: E402
from app.models.domain import Asset, IndexerState, SecurityAlert, User  # noqa: E402
from app.services import chain as chain_service  # noqa: E402
from app.services.alerts import _manager_exists_for  # noqa: E402
from app.services.chain import RoleSync, desired_roles  # noqa: E402
from app.services.key_rotation import ENCRYPTED_USER_FIELDS  # noqa: E402

results = []


def check(name, ok, info=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  (' + info + ')') if info else ''}")


async def main() -> int:
    st = chain_service.verify_deployment()
    check("chain id, contract bytecode, registrar role", st.ok, f"chain {st.chain_id}, head {st.head}, {st.address}")
    d = chain_service.load_deployment()
    w3 = Web3(Web3.HTTPProvider(os.environ.get("RPC_URL", "http://127.0.0.1:8545")))
    c = w3.eth.contract(address=Web3.to_checksum_address(d["address"]), abi=d["abi"])

    async with async_session_factory() as db:
        from alembic.config import Config
        from alembic.script import ScriptDirectory
        cfg = Config(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "migrations"))
        head = ScriptDirectory.from_config(cfg).get_current_head()
        current = (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar_one_or_none()
        check("database schema at Alembic head", current == head, f"{current}")
        triggers = (await db.execute(text("SELECT count(*) FROM pg_trigger WHERE tgname LIKE '%append_only' OR tgname LIKE '%no_truncate'"))).scalar_one()
        check("append-only triggers on audit history", triggers == 4, f"{triggers}/4")

        users = (await db.execute(select(User))).scalars().all()
        plain = sum(1 for u in users for f in ENCRYPTED_USER_FIELDS if getattr(u, f) and not getattr(u, f).startswith("enc:v1:"))
        check("no plaintext secrets stored", plain == 0, f"{plain} plaintext values")
        pins = sum(1 for u in users if getattr(u, "one_time_pin", None))
        check("no plaintext provisioning PINs", pins == 0)

        assets = (await db.execute(select(Asset))).scalars().all()
        by_id = {a.id: a for a in assets}
        owners = {u.id: u for u in users}
        mism = []
        recorded = [a for a in assets if (a.watermark_metadata or {}).get("chain_tx")]
        for a in recorded:
            root = a if (a.version_number or 1) == 1 else by_id.get(a.root_asset_id)
            try:
                if a.is_physical:
                    ok = c.functions.getTokenBySerial(a.serial_number).call() == a.token_id
                else:
                    serial, _, fhash, _, _ = c.functions.getDigitalAsset(root.token_id).call()
                    latest = max((x for x in assets if (x.root_asset_id or x.id) == root.id and x.approval_status == "APPROVED"
                                  and (x.watermark_metadata or {}).get("chain_tx")), key=lambda x: x.version_number or 1)
                    ok = serial == root.serial_number and fhash == latest.file_hash
                holder = c.functions.ownerOf(root.token_id).call()
                ok = ok and owners.get(root.owner_id) is not None and owners[root.owner_id].wallet_address.lower() == holder.lower()
            except Exception as e:
                ok = False
            if not ok:
                mism.append(a.serial_number)
        check("recorded assets match the ledger (serial, hash, holder)", not mism, f"{len(recorded)} checked; mismatches: {', '.join(mism) or 'none'}")

        stt = (await db.execute(select(IndexerState))).scalar_one_or_none()
        if stt:
            lag = w3.eth.block_number - stt.last_block
            raw = w3.provider.make_request("eth_getBlockByNumber", [hex(stt.last_block), False])
            same = (raw.get("result") or {}).get("hash") == stt.last_block_hash or stt.last_block == 0
            check("indexer cursor on this chain and contract", same and stt.contract_address.lower() == d["address"].lower() and lag < 200, f"lag {lag} blocks")
        else:
            check("indexer cursor present", False)

        try:
            rs = RoleSync()
            holders = rs.onchain_role_holders()
            wallets = {u.wallet_address.lower(): u for u in users}
            wrong = []
            for h in holders | {Web3.to_checksum_address(u.wallet_address) for u in users if u.wallet_address}:
                u = wallets.get(h.lower())
                want = desired_roles(u.role, bool(u.is_active)) if u else set()
                if rs.current_roles(h) != want:
                    wrong.append(h)
            check("on-chain roles match the identity registry", not wrong, f"{len(holders)} holders; mismatches: {len(wrong)}")
        except Exception as e:
            check("on-chain roles match the identity registry", False, type(e).__name__)

        parked = [a.alert_id for a in (await db.execute(select(SecurityAlert).where(SecurityAlert.state == "MANAGER_REVIEW"))).scalars().all()
                  if not await _manager_exists_for(db, a)]
        check("no alert parked at a stage no one covers", not parked, ", ".join(parked))

    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
