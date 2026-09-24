"""Audit trail API — read-only access to on-chain events that the indexer has recorded, plus alert workflow triage."""

import logging
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.domain import AuditEvent, User
from app.schemas.domain import AuditEventRead, AlertStatusUpdateRequest
from app.api.dependencies import get_current_active_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/stats")
async def get_audit_stats(db: AsyncSession = Depends(get_db)):
    """Return the compact risk summary consumed by the executive dashboard."""
    total_result = await db.execute(select(func.count(AuditEvent.id)))
    latest_result = await db.execute(
        select(AuditEvent.risk_label)
        .where(AuditEvent.risk_label.is_not(None))
        .order_by(desc(AuditEvent.created_at))
        .limit(1)
    )
    return {
        "total_events": total_result.scalar_one() or 0,
        "latest_risk": latest_result.scalar_one_or_none() or "LOW",
    }


@router.get("/events", response_model=List[AuditEventRead])
async def list_events(
    event_type: Optional[str] = Query(None, description="Filter by event type (AssetMinted, etc.)"),
    actor_did: Optional[str] = Query(None, description="Filter by actor DID or wallet address"),
    asset_serial: Optional[str] = Query(None, description="Filter by asset serial"),
    risk_label: Optional[str] = Query(None, description="Filter by risk label (LOW, MEDIUM, HIGH, CRITICAL)"),
    alert_status: Optional[str] = Query(None, description="Filter by alert status (OPEN, FORWARDED_TO_MANAGER, ESCALATED_TO_ADMIN, etc.)"),
    role: Optional[str] = Query(None, description="Filter by actor role (USER, MANAGER, ADMIN, AUDITOR)"),
    from_date: Optional[str] = Query(None, description="Filter events created on or after ISO datetime/date"),
    to_date: Optional[str] = Query(None, description="Filter events created on or before ISO datetime/date"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List audit events with extensive filters for wallet, role, risk label, alert status, and time/date range.

    These rows are written exclusively by the on-chain event indexer, never
    by API call handlers. They are the canonical, immutable audit trail.
    """
    query = select(AuditEvent).order_by(desc(AuditEvent.created_at))

    if role:
        query = query.join(User, AuditEvent.actor_did == User.did, isouter=True).filter(
            func.upper(User.role) == role.strip().upper()
        )

    if event_type:
        query = query.filter(AuditEvent.event_type == event_type.strip())
    if actor_did:
        clean_actor = actor_did.strip()
        query = query.filter(
            or_(
                AuditEvent.actor_did.ilike(f"%{clean_actor}%"),
                AuditEvent.target_did.ilike(f"%{clean_actor}%"),
            )
        )
    if asset_serial:
        query = query.filter(AuditEvent.asset_serial == asset_serial.strip())
    if risk_label:
        query = query.filter(func.upper(AuditEvent.risk_label) == risk_label.strip().upper())
    if alert_status:
        query = query.filter(func.upper(AuditEvent.alert_status) == alert_status.strip().upper())

    if from_date:
        try:
            dt_from = datetime.fromisoformat(from_date.strip().replace("Z", "+00:00"))
            query = query.filter(AuditEvent.created_at >= dt_from)
        except Exception as e:
            logger.warning(f"Invalid from_date '{from_date}': {e}")

    if to_date:
        try:
            dt_to = datetime.fromisoformat(to_date.strip().replace("Z", "+00:00"))
            query = query.filter(AuditEvent.created_at <= dt_to)
        except Exception as e:
            logger.warning(f"Invalid to_date '{to_date}': {e}")

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.patch("/alerts/{event_id}/status", response_model=AuditEventRead)
async def update_alert_status(
    event_id: str,
    payload: AlertStatusUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Update the triage status of a security alert (Forward to Manager, Escalate to Admin, Dismiss, Resolve)."""
    try:
        uid = uuid.UUID(event_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid event UUID")

    result = await db.execute(select(AuditEvent).filter(AuditEvent.id == uid))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Audit event not found")

    allowed_statuses = ["OPEN", "FORWARDED_TO_MANAGER", "ESCALATED_TO_ADMIN", "DISMISSED", "RESOLVED"]
    status_upper = payload.alert_status.strip().upper()
    if status_upper not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid alert status '{payload.alert_status}'. Allowed: {allowed_statuses}"
        )

    event.alert_status = status_upper
    await db.commit()
    await db.refresh(event)
    return event


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
    from web3 import Web3
    try:
        clean_address = Web3.to_checksum_address(wallet_address).lower()
    except Exception:
        clean_address = wallet_address.lower()

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
