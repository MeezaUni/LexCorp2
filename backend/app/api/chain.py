"""Chain endpoints: deployment info, integrity status, role reconciliation, and the
authenticated JSON-RPC relay used by the browser wallet.

Besu's JSON-RPC is bound to 127.0.0.1 and accepts no browser origins. Browsers reach
the chain only through /api/chain/rpc, which requires a fully onboarded session,
allows a fixed set of read / submit methods, and accepts a raw transaction only if it
is signed by the caller's own wallet and addressed to the LexCorp2 contract.
"""

import asyncio
import logging
from typing import Any

import httpx
from eth_account import Account
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_onboarded_user, get_request_client_ip, record_audit
from app.core.config import settings
from app.core.database import get_db
from app.core.limiter import limiter
from app.models.domain import User
from app.services import chain as chain_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/chain", tags=["chain"])


def _rpc_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


@router.get("/info")
async def chain_info(current_user: User = Depends(get_onboarded_user)):
    d = chain_service.load_deployment()
    return {"chain_id": settings.CHAIN_ID, "contract_address": d["address"], "contract_version": d.get("contractVersion")}


@router.get("/status")
async def chain_status(current_user: User = Depends(get_onboarded_user)):
    if current_user.role not in ("ADMIN", "AUDITOR"):
        raise HTTPException(status_code=403, detail="Only Admins and Auditors can view chain integrity status.")
    st = await asyncio.to_thread(chain_service.verify_deployment)
    return {"ok": st.ok, "checks": st.checks, "contract_address": st.address, "chain_id": st.chain_id, "head_block": st.head}


@router.post("/roles/reconcile")
async def reconcile_roles(request: Request, current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only Admins can reconcile on-chain roles.")
    result = await chain_service.reconcile_all(db)
    await record_audit(db, "CHAIN_ROLES_RECONCILED", actor_did=current_user.did,
                       client_ip=get_request_client_ip(request), details=result)
    await db.commit()
    return result


@router.post("/rpc")
@limiter.limit("240/minute")
async def rpc_relay(request: Request, current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_rpc_error(None, -32700, "Parse error"), status_code=400)
    if isinstance(body, list):
        return JSONResponse(_rpc_error(None, -32600, "Batch requests are not supported"), status_code=400)
    if not isinstance(body, dict):
        return JSONResponse(_rpc_error(None, -32600, "Invalid request"), status_code=400)
    req_id, method, params = body.get("id"), body.get("method"), body.get("params") or []
    if method not in settings.CHAIN_RELAY_METHODS:
        return JSONResponse(_rpc_error(req_id, -32601, f"Method {method} is not permitted"), status_code=403)

    if method == "eth_sendRawTransaction":
        d = chain_service.load_deployment()
        try:
            raw = params[0]
            sender = Account.recover_transaction(raw)
            to_addr = _tx_to(raw)
        except Exception:
            return JSONResponse(_rpc_error(req_id, -32602, "Malformed transaction"), status_code=400)
        if sender.lower() != (current_user.wallet_address or "").lower():
            await record_audit(db, "CHAIN_RELAY_REJECTED", actor_did=current_user.did, client_ip=get_request_client_ip(request),
                               details={"reason": "sender is not the session wallet", "sender": sender}, risk_label="HIGH")
            await db.commit()
            return JSONResponse(_rpc_error(req_id, -32000, "Transaction must be signed by your own wallet"), status_code=403)
        if not to_addr or to_addr.lower() != d["address"].lower():
            return JSONResponse(_rpc_error(req_id, -32000, "Transactions may only target the LexCorp2 contract"), status_code=403)

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.post(settings.RPC_URL, json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        except httpx.HTTPError:
            return JSONResponse(_rpc_error(req_id, -32000, "Blockchain node unavailable"), status_code=503)
    return JSONResponse(r.json())


def _tx_to(raw_hex: str):
    """Destination address of a signed legacy or typed (EIP-2718) transaction."""
    import rlp
    from eth_utils import to_checksum_address

    raw = bytes.fromhex(raw_hex[2:] if raw_hex.startswith("0x") else raw_hex)
    if raw and raw[0] < 0x7F:  # typed transaction: type byte || rlp(payload)
        fields = rlp.decode(raw[1:])
        to = {1: fields[4], 2: fields[5]}.get(raw[0])
        if raw[0] not in (1, 2):
            raise ValueError("unsupported transaction type")
    else:
        to = rlp.decode(raw)[3]
    return to_checksum_address(to) if to else None
