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
from app.api.dependencies import get_onboarded_user
from app.services import access

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/audit", tags=["audit"])


async def _scoped_events_query(db: AsyncSession, user: User):
    """AuditEvent query limited to what this role may read."""
    query = select(AuditEvent)
    if user.role in access.UNRESTRICTED_ROLES:
        return query
    own = or_(AuditEvent.actor_did == user.did, AuditEvent.target_did == user.did)
    if user.role == "MANAGER":
        depts = access.manager_departments(user)
        dept_dids = select(User.did).where(User.department.in_(depts))
        from app.models.domain import Asset
        dept_serials = select(Asset.serial_number).where(Asset.department.in_(depts))
        return query.where(or_(own, AuditEvent.actor_did.in_(dept_dids), AuditEvent.asset_serial.in_(dept_serials)))
    return query.where(own)


@router.get("/stats")
async def get_audit_stats(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_onboarded_user)):
    """Return the compact risk summary consumed by the executive dashboard."""
    if current_user.role == "USER":
        raise HTTPException(status_code=403, detail="Not authorized to view audit statistics.")
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
    current_user: User = Depends(get_onboarded_user),
):
    """List audit events with extensive filters for wallet, role, risk label, alert status, and time/date range.

    These rows are written exclusively by the on-chain event indexer, never
    by API call handlers. They are the canonical, immutable audit trail.
    """
    query = (await _scoped_events_query(db, current_user)).order_by(desc(AuditEvent.created_at))

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


@router.patch("/alerts/{event_id}/status")
async def update_alert_status(event_id: str, current_user: User = Depends(get_onboarded_user)):
    """Retired: statuses could be set to any value by any security role, skipping the
    Auditor -> Manager -> Admin chain. Use /api/alerts/{alert_id}/forward|dismiss|revoke-identity."""
    raise HTTPException(status_code=410, detail="Use the security alert workflow at /api/alerts.")


@router.get("/events/by-tx/{tx_hash}", response_model=AuditEventRead)
async def get_event_by_tx(
    tx_hash: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_onboarded_user),
):
    """Look up a single audit event by transaction hash. 404 if not indexed or out of scope."""
    result = await db.execute(
        (await _scoped_events_query(db, current_user)).filter(AuditEvent.tx_hash == tx_hash)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail=f"No audit event for tx {tx_hash}")
    return event


@router.get("/user-permissions/{wallet_address}")
async def get_user_permissions(
    wallet_address: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_onboarded_user),
):
    """Retrieve all active on-chain permission grant events for or by a specific user wallet."""
    from web3 import Web3
    try:
        clean_address = Web3.to_checksum_address(wallet_address).lower()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid wallet address")
    target = (await db.execute(select(User).where(func.lower(User.wallet_address) == clean_address))).scalar_one_or_none()
    if not target or not access.can_see_user(current_user, target):
        raise HTTPException(status_code=403, detail="Not authorized for this identity.")

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
