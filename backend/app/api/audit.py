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


def _for_viewer(item: AuditEventRead, user: User) -> AuditEventRead:
    """What each verification checked, against what, and why it failed is shown to Auditors only."""
    if user.role != "AUDITOR" and isinstance(item.risk_factors, dict) and "verification" in item.risk_factors:
        item.risk_factors = {k: v for k, v in item.risk_factors.items() if k != "verification"}
    return item


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
    """Risk summary for the dashboard, computed over the SAME scope the caller may read
    in /audit/events (Managers see their departments only)."""
    from datetime import timedelta, UTC
    if current_user.role == "USER":
        raise HTTPException(status_code=403, detail="Not authorized to view audit statistics.")
    scoped = (await _scoped_events_query(db, current_user)).subquery()
    now = datetime.now(UTC)
    denied = or_(*[scoped.c.event_type.contains(m) for m in _DENIED_MARKERS])

    async def count(*conds):
        q = select(func.count()).select_from(scoped)
        for c in conds:
            q = q.where(c)
        return (await db.execute(q)).scalar_one() or 0

    latest = (await db.execute(select(scoped.c.risk_label).where(scoped.c.risk_label.is_not(None))
                               .order_by(desc(scoped.c.created_at)).limit(1))).scalar_one_or_none()
    return {
        "total_events": await count(),
        "events_24h": await count(scoped.c.created_at >= now - timedelta(hours=24)),
        "high_risk_7d": await count(scoped.c.created_at >= now - timedelta(days=7),
                                    func.upper(scoped.c.risk_label).in_(("HIGH", "CRITICAL"))),
        "denied_7d": await count(scoped.c.created_at >= now - timedelta(days=7), denied),
        "latest_risk": latest or "LOW",
    }


# Event-type families for the audit filters (spec 44).
CATEGORIES = {
    "VIEW": ("DOCUMENT_VIEWED", "VIEW_NOT_PERMITTED"),
    "DOWNLOAD": ("DOCUMENT_DOWNLOADED", "DOWNLOAD_OWNER_APPROVED", "DOWNLOAD_OWNER_REJECTED", "DOWNLOAD_NOT_PERMITTED"),
    "MODIFICATION": ("REVISION_SUBMITTED", "DOCUMENT_REVISION_ANCHORED", "DigitalAssetUpdated"),
    "PHYSICAL": ("PHYSICAL_ASSET_CREATED", "PHYSICAL_ASSET_APPROVED", "PHYSICAL_ASSET_MINTED", "PhysicalAssetProposed",
                 "DUPLICATE_PHYSICAL_ASSET_ATTEMPT", "DUPLICATE_SERIAL_ATTEMPT", "DUPLICATE_MAC_ATTEMPT",
                 "DUPLICATE_UNIQUE_ADDRESS_ATTEMPT", "ASSET_TRANSFERRED", "AssetTransferred", "ASSET_CUSTODIAN_CHANGED",
                 "ASSET_STATUS_CHANGED", "ASSET_MAINTENANCE_RECORDED", "ASSET_VERIFIED", "AssetMinted"),
    "DIGITAL": ("DocumentProposed", "DOCUMENT_VIEWED", "DOCUMENT_DOWNLOADED", "REVISION_SUBMITTED", "DOCUMENT_MINTED",
                "DOCUMENT_REVISION_ANCHORED", "DigitalAssetMinted", "DigitalAssetUpdated", "WATERMARK_TAMPER_DETECTED"),
    "VERIFY": ("VERIFICATION_LOOKUP", "COPY_VERIFIED", "WATERMARK_TAMPER_DETECTED", "ASSET_VERIFIED", "COPY_IDENTIFIED"),
    "ACCESS": ("ACCESS_GRANTED", "ACCESS_REVOKED", "ACCESS_DENIED_NO_GRANT", "ACCESS_DENIED_REVOKED", "ACCESS_EXPIRED",
               "ACCESS_LIMIT_REACHED", "AccessPermissionGranted", "AccessPermissionRevoked", "AccessAttempted"),
    "AUTH": ("AuthenticationSucceeded", "AuthenticationFailed", "WALLET_PROVISIONED", "WALLET_PROVISIONING_FAILED",
             "STEP_UP_FAILED", "LOGOUT", "SESSION_TERMINATED_IP_CHANGE", "SESSION_EXPIRED_INACTIVITY",
             "LOGIN_RESET_REQUESTED", "ADMIN_LOGIN_RESET_APPROVED", "TOTP_ENROLLED", "TOTP_RESET",
             "PASSKEY_REGISTERED", "PASSKEY_DISABLED", "IDENTITY_REVOKED"),
    "ALERT": ("ALERT_FORWARDED_TO_MANAGER", "ALERT_FORWARDED_TO_ADMIN", "ALERT_DISMISSED", "ALERT_IDENTITY_REVOKED"),
    "CHAIN": ("CHAIN_ROLES_UPDATED", "CHAIN_ROLE_SYNC_FAILED", "CHAIN_ROLES_RECONCILED", "CHAIN_ROLES_REVOKED_UNREGISTERED",
              "CHAIN_RELAY_REJECTED", "RoleGranted", "RoleRevoked", "INDEXER_RESCAN"),
    "IDENTITY": ("USER_PROVISIONED", "ROLE_CHANGED", "IDENTITY_REVOKED", "PROVISIONING_PIN_REISSUED"),
}
_DENIED_MARKERS = ("DENIED", "FAILED", "DUPLICATE", "EXPIRED", "LIMIT_REACHED", "NOT_PERMITTED", "TAMPER",
                   "TERMINATED", "REJECTED", "Rejected")


def _parse_dt(value: str, name: str) -> datetime:
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{name} must be an ISO 8601 date or datetime.")


def _parse_time(value: str, name: str):
    try:
        return datetime.strptime(value.strip(), "%H:%M").time()
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{name} must be HH:MM (UTC).")


@router.get("/events", response_model=List[AuditEventRead])
async def list_events(
    event_type: Optional[str] = Query(None, description="Event type, or several separated by commas"),
    category: Optional[str] = Query(None, description="VIEW, DOWNLOAD, MODIFICATION, PHYSICAL, DIGITAL, ACCESS, AUTH, ALERT"),
    actor_did: Optional[str] = Query(None, description="Actor/target DID or wallet address (substring)"),
    identity: Optional[str] = Query(None, description="Actor name (substring)"),
    department: Optional[str] = Query(None, description="Actor's department"),
    asset_serial: Optional[str] = Query(None, description="Asset serial"),
    risk_label: Optional[str] = Query(None, description="LOW, MEDIUM, HIGH, CRITICAL"),
    result: Optional[str] = Query(None, description="SUCCESS or DENIED (denied/failed/duplicate/expired/tamper...)"),
    alert_status: Optional[str] = Query(None, description="Legacy alert status on the event (OPEN, FORWARDED_TO_MANAGER, ...)"),
    escalation_state: Optional[str] = Query(None, description="Alert state: AUDITOR_REVIEW, MANAGER_REVIEW, ADMIN_REVIEW, DISMISSED, IDENTITY_REVOKED"),
    role: Optional[str] = Query(None, description="Actor role (USER, MANAGER, ADMIN, AUDITOR)"),
    from_date: Optional[str] = Query(None, description="On/after this ISO date or datetime"),
    to_date: Optional[str] = Query(None, description="On/before this ISO date or datetime"),
    from_time: Optional[str] = Query(None, description="Time-of-day window start HH:MM (UTC)"),
    to_time: Optional[str] = Query(None, description="Time-of-day window end HH:MM (UTC)"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_onboarded_user),
):
    """Server-side filtered audit trail (scoped by role before any filter is applied).

    Rows come from the on-chain event indexer (block_number > 0) and from API
    security events recorded by the backend (block_number = 0)."""
    from sqlalchemy import cast, Time, and_
    from app.models.domain import SecurityAlert

    query = (await _scoped_events_query(db, current_user)).order_by(desc(AuditEvent.created_at))

    if role or identity or department:
        query = query.join(User, AuditEvent.actor_did == User.did, isouter=True)
        if role:
            # the role at the time of the event; older events (before migration 0014) use the current one
            query = query.filter(func.upper(func.coalesce(AuditEvent.actor_role, User.role)) == role.strip().upper())
        if identity:
            query = query.filter(User.name.ilike(f"%{identity.strip()}%"))
        if department:
            query = query.filter(User.department == department.strip())

    if event_type:
        types = [t.strip() for t in event_type.split(",") if t.strip()]
        query = query.filter(AuditEvent.event_type.in_(types))
    if category:
        cat = category.strip().upper()
        if cat not in CATEGORIES:
            raise HTTPException(status_code=400, detail=f"category must be one of {sorted(CATEGORIES)}")
        query = query.filter(AuditEvent.event_type.in_(CATEGORIES[cat]))
    if actor_did:
        clean_actor = actor_did.strip()
        query = query.filter(or_(AuditEvent.actor_did.ilike(f"%{clean_actor}%"), AuditEvent.target_did.ilike(f"%{clean_actor}%")))
    if asset_serial:
        query = query.filter(AuditEvent.asset_serial == asset_serial.strip())
    if risk_label:
        query = query.filter(func.upper(AuditEvent.risk_label) == risk_label.strip().upper())
    if result:
        denied = or_(*[AuditEvent.event_type.contains(m) for m in _DENIED_MARKERS])
        r = result.strip().upper()
        if r not in ("SUCCESS", "DENIED"):
            raise HTTPException(status_code=400, detail="result must be SUCCESS or DENIED")
        query = query.filter(denied if r == "DENIED" else ~denied)
    from app.services.alerts import LEGACY_STATUS_TO_STATE
    wanted_state = escalation_state.strip().upper() if escalation_state else None
    if alert_status:
        legacy = LEGACY_STATUS_TO_STATE.get(alert_status.strip().upper())
        if legacy is None:
            raise HTTPException(status_code=400, detail=f"alert_status must be one of {sorted(LEGACY_STATUS_TO_STATE)}")
        if wanted_state and wanted_state != legacy:
            return []
        wanted_state = legacy
    if wanted_state:
        query = query.join(SecurityAlert, SecurityAlert.source_event_id == AuditEvent.id).filter(
            SecurityAlert.state == wanted_state)

    if from_date:
        query = query.filter(AuditEvent.created_at >= _parse_dt(from_date, "from_date"))
    if to_date:
        query = query.filter(AuditEvent.created_at <= _parse_dt(to_date, "to_date"))
    if from_time or to_time:
        tod = cast(func.timezone("UTC", AuditEvent.created_at), Time)
        t1 = _parse_time(from_time, "from_time") if from_time else None
        t2 = _parse_time(to_time, "to_time") if to_time else None
        if t1 and t2 and t1 > t2:  # window across midnight, e.g. 22:00-06:00
            query = query.filter(or_(tod >= t1, tod <= t2))
        else:
            if t1:
                query = query.filter(tod >= t1)
            if t2:
                query = query.filter(tod <= t2)

    query = query.offset(offset).limit(limit)
    rows = (await db.execute(query)).scalars().all()
    # Alert status is read from security_alerts (audit rows are append-only).
    states = {}
    if rows:
        for ev_id, st in (await db.execute(select(SecurityAlert.source_event_id, SecurityAlert.state)
                                           .where(SecurityAlert.source_event_id.in_([r.id for r in rows])))).all():
            states[ev_id] = st
    out = []
    for r in rows:
        item = _for_viewer(AuditEventRead.model_validate(r), current_user)
        item.alert_status = states.get(r.id)
        out.append(item)
    return out


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
    return _for_viewer(AuditEventRead.model_validate(event), current_user)


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
