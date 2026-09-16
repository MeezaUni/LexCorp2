"""Audit trail API — read-only access to on-chain events that the indexer has recorded."""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.domain import AuditEvent
from app.schemas.domain import AuditEventRead

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/events", response_model=List[AuditEventRead])
async def list_events(
    event_type: Optional[str] = Query(None, description="Filter by event type (AssetMinted, etc.)"),
    actor_did: Optional[str] = Query(None, description="Filter by actor DID"),
    asset_serial: Optional[str] = Query(None, description="Filter by asset serial"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List audit events with optional filters.

    These rows are written exclusively by the on-chain event indexer, never
    by API call handlers. They are the canonical, immutable audit trail.
    """
    query = select(AuditEvent).order_by(AuditEvent.block_number.desc())

    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    if actor_did:
        query = query.filter(AuditEvent.actor_did == actor_did)
    if asset_serial:
        query = query.filter(AuditEvent.asset_serial == asset_serial)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/events/by-tx/{tx_hash}", response_model=AuditEventRead)
async def get_event_by_tx(
    tx_hash: str,
    db: AsyncSession = Depends(get_db),
):
    """Look up a single audit event by transaction hash. 404 if not indexed."""
    result = await db.execute(
        select(AuditEvent).filter(AuditEvent.tx_hash == tx_hash)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail=f"No audit event for tx {tx_hash}")
    return event


@router.get("/user-permissions/{wallet_address}")
async def get_user_permissions(
    wallet_address: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve all active on-chain permission grant events for or by a specific user wallet."""
    from sqlalchemy import or_, desc
    from web3 import Web3
    try:
        clean_address = Web3.to_checksum_address(wallet_address).lower()
    except Exception:
        clean_address = wallet_address.lower()

    user_did_prefix = f":{clean_address}"

    # Query grants and revokes involving this user (either actor or target)
    query = (
        select(AuditEvent)
        .filter(
            AuditEvent.event_type.in_(["AccessPermissionGranted", "AccessPermissionRevoked"]),
            or_(
                AuditEvent.actor_did.ilike(f"%{clean_address}%"),
                AuditEvent.target_did.ilike(f"%{clean_address}%"),
            )
        )
        .order_by(desc(AuditEvent.created_at))
    )
    result = await db.execute(query)
    events = result.scalars().all()

    shared_by_me = []
    shared_with_me = []
    seen_grants = set()

    for ev in events:
        key = f"{ev.asset_serial}_{ev.target_did}"
        if key in seen_grants:
            continue
        seen_grants.add(key)

        # Only count if the latest status is Granted
        if ev.event_type == "AccessPermissionGranted":
            item = {
                "id": str(ev.id),
                "asset_serial": ev.asset_serial,
                "actor_did": ev.actor_did,
                "target_did": ev.target_did,
                "tx_hash": ev.tx_hash,
                "block_number": ev.block_number,
                "timestamp": ev.created_at.isoformat() if ev.created_at else None,
            }
            if ev.actor_did and clean_address in ev.actor_did.lower():
                shared_by_me.append(item)
            if ev.target_did and clean_address in ev.target_did.lower():
                shared_with_me.append(item)

    return {
        "shared_by_user": shared_by_me,
        "shared_with_user": shared_with_me,
        "total_shared_by_count": len(shared_by_me),
        "total_shared_with_count": len(shared_with_me),
    }
