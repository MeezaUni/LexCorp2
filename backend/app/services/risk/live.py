"""Scoring live actions: the person's recent history is rebuilt from the audit trail, mapped
onto the same Event kinds the simulator and training use, and scored by the trained bundle."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, UTC
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.risk import model as risk_model
from app.services.risk.features import HISTORY_DAYS, Event, features_for

logger = logging.getLogger(__name__)

# Audit event type -> Event kind. Anything not listed is not behaviour of a person (system
# events, configuration) and is left out of their history.
AUDIT_KIND = {
    "AuthenticationSucceeded": "LOGIN", "WALLET_PROVISIONED": "LOGIN",
    "AuthenticationFailed": "LOGIN_FAILED", "WALLET_PROVISIONING_FAILED": "LOGIN_FAILED",
    "STEP_UP_FAILED": "STEP_UP_FAILED",
    "ACCESS_DENIED": "ACCESS_DENIED", "ACCESS_DENIED_NO_GRANT": "ACCESS_DENIED", "ACCESS_DENIED_REVOKED": "ACCESS_DENIED",
    "ACCESS_EXPIRED": "ACCESS_DENIED", "ACCESS_LIMIT_REACHED": "ACCESS_DENIED", "CHAIN_RELAY_REJECTED": "ACCESS_DENIED",
    "DOCUMENT_VIEWED": "VIEW",
    "DOCUMENT_DOWNLOADED": "DOWNLOAD",
    "REVISION_SUBMITTED": "REVISION",
    "DocumentProposed": "REGISTER", "PhysicalAssetProposed": "REGISTER", "PHYSICAL_ASSET_CREATED": "REGISTER",
    "AssetActionApproved": "APPROVE", "AssetActionRejected": "APPROVE", "PHYSICAL_ASSET_APPROVED": "APPROVE",
    "DOWNLOAD_OWNER_APPROVED": "APPROVE", "DOWNLOAD_OWNER_REJECTED": "APPROVE",
    "AssetShareProposed": "DELEGATE", "ACCESS_GRANTED": "DELEGATE",
    "WATERMARK_TAMPER_DETECTED": "TAMPER",
    "DUPLICATE_PHYSICAL_ASSET_ATTEMPT": "DUPLICATE",
}
FAILED = {"LOGIN_FAILED", "STEP_UP_FAILED", "ACCESS_DENIED"}


def _tz():
    from zoneinfo import ZoneInfo
    return ZoneInfo(os.environ.get("RISK_TIMEZONE", "Asia/Kolkata"))


def local(ts: datetime) -> datetime:
    """Organisation-local wall-clock time, naive (the simulator and training use the same)."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(_tz()).replace(tzinfo=None)


async def _asset_info(db: AsyncSession, serials: set) -> Dict[str, tuple]:
    from app.models.domain import Asset, User
    if not serials:
        return {}
    rows = (await db.execute(select(Asset.serial_number, Asset.department, Asset.owner_id, Asset.is_physical)
                             .where(Asset.serial_number.in_(serials)))).all()
    owners = {r.owner_id for r in rows if r.owner_id}
    dids = {u.id: u.did for u in (await db.execute(select(User).where(User.id.in_(owners)))).scalars().all()} if owners else {}
    return {r.serial_number: (r.department, dids.get(r.owner_id), 1 if r.is_physical else 2) for r in rows}


async def history_for(db: AsyncSession, actor, now: datetime) -> List[Event]:
    """The person's own behaviour in the last HISTORY_DAYS, from the audit trail."""
    from app.models.domain import AuditEvent
    since = now - timedelta(days=HISTORY_DAYS)
    rows = (await db.execute(select(AuditEvent).where(AuditEvent.actor_did == actor.did, AuditEvent.created_at >= since)
                             .order_by(AuditEvent.created_at).limit(5000))).scalars().all()
    info = await _asset_info(db, {r.asset_serial for r in rows if r.asset_serial})
    out = []
    for r in rows:
        kind = AUDIT_KIND.get(r.event_type)
        if kind is None:
            continue
        if kind == "DOWNLOAD" and isinstance(r.risk_factors, dict) and r.risk_factors.get("mode") == "MODIFICATION":
            kind = "MOD_COPY"
        dept, owner, sens = info.get(r.asset_serial, (None, None, 1))
        out.append(Event(ts=local(r.created_at), actor=actor.did, role=actor.role, dept=actor.department, kind=kind,
                         asset=r.asset_serial, asset_dept=dept, asset_owner=owner, sensitivity=sens,
                         ip=r.client_ip, ok=kind not in FAILED))
    return out


async def assess_action(db: AsyncSession, kind: str, actor, *, asset=None, asset_serial: Optional[str] = None,
                        client_ip: Optional[str] = None, ok: bool = True) -> Optional[dict]:
    """Risk of `actor` doing `kind` now. None when no trained model is installed."""
    bundle = risk_model.load_bundle()
    if bundle is None or actor is None:
        return None
    now = datetime.now(UTC)
    serial = asset.serial_number if asset is not None else asset_serial
    info = await _asset_info(db, {serial} if serial else set())
    dept, owner, sens = info.get(serial, (None, None, 1)) if serial else (None, None, 1)
    event = Event(ts=local(now), actor=actor.did, role=actor.role, dept=actor.department, kind=kind, asset=serial,
                  asset_dept=dept, asset_owner=owner, sensitivity=sens, ip=client_ip, ok=ok)
    feats = features_for(event, await history_for(db, actor, now))
    result = risk_model.assess(feats, bundle)
    if result is not None:
        result["features"] = {k: round(v, 3) for k, v in feats.items()}
    return result
