"""High-risk security alerts and their escalation chain (spec 39-43).

    AI / RULE flags HIGH or CRITICAL
      -> AUDITOR_REVIEW   Auditor: DISMISS (false alarm) | FORWARD -> Manager
      -> MANAGER_REVIEW   Manager of the subject's department: DISMISS | FORWARD -> Admin
      -> ADMIN_REVIEW     Admin: DISMISS | REVOKE IDENTITY (existing mechanism, Factor 3)

Every transition appends to security_alert_actions and writes an audit event, so the
whole chain is preserved. AI only raises alerts; it never replaces authentication,
authorization, uniqueness or approval decisions.
"""

import logging
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain import AuditEvent, SecurityAlert, SecurityAlertAction, User
from app.services import access
from app.services.action_ids import next_action_id

logger = logging.getLogger(__name__)

AUDITOR_REVIEW, MANAGER_REVIEW, ADMIN_REVIEW = "AUDITOR_REVIEW", "MANAGER_REVIEW", "ADMIN_REVIEW"
DISMISSED, IDENTITY_REVOKED = "DISMISSED", "IDENTITY_REVOKED"
OPEN_STATES = (AUDITOR_REVIEW, MANAGER_REVIEW, ADMIN_REVIEW)
HIGH_LEVELS = ("HIGH", "CRITICAL")

# Legacy alert-status names (still accepted by the audit filter) -> alert state. The
# audit row itself is append-only and is never updated; status lives on security_alerts.
LEGACY_STATUS_TO_STATE = {"OPEN": AUDITOR_REVIEW, "FORWARDED_TO_MANAGER": MANAGER_REVIEW,
                          "ESCALATED_TO_ADMIN": ADMIN_REVIEW, "DISMISSED": DISMISSED, "RESOLVED": IDENTITY_REVOKED}


async def raise_alert(db: AsyncSession, event: AuditEvent, source: str = "RULE") -> Optional[SecurityAlert]:
    """Create the alert for a HIGH/CRITICAL audit event (idempotent per event)."""
    if (event.risk_label or "").upper() not in HIGH_LEVELS:
        return None
    await db.flush()
    existing = (await db.execute(select(SecurityAlert).where(SecurityAlert.source_event_id == event.id))).scalar_one_or_none()
    if existing:
        return existing
    subject = None
    if event.actor_did:
        subject = (await db.execute(select(User).where(User.did == event.actor_did))).scalar_one_or_none()
    factors = event.risk_factors if isinstance(event.risk_factors, dict) else {}
    reason = factors.get("reason") or factors.get("explanation") or (
        f"{event.event_type} scored {event.risk_label} by the local Isolation Forest model"
        if source == "AI" else f"{event.event_type} flagged {event.risk_label}")
    alert = SecurityAlert(
        alert_id=await next_action_id(db, "ALT"), source=source, source_event_id=event.id,
        subject_user_id=subject.id if subject else None, subject_did=event.actor_did,
        subject_role=subject.role if subject else None, subject_wallet=subject.wallet_address if subject else None,
        department=subject.department if subject else None, risk_level=event.risk_label.upper(),
        risk_score=event.risk_score, reason=str(reason)[:1000], event_type=event.event_type,
        asset_serial=event.asset_serial,
        related_action_id=factors.get("action_id") or factors.get("download_id") or factors.get("modification_id"),
        client_ip=event.client_ip, state=AUDITOR_REVIEW,
    )
    db.add(alert)
    await db.flush()
    db.add(SecurityAlertAction(alert_id=alert.id, action="RAISED", from_state=None, to_state=AUDITOR_REVIEW,
                               note=f"Raised by {source} from {event.event_type}"))
    return alert


def _manager_covers(user: User, alert: SecurityAlert) -> bool:
    return bool(alert.department) and alert.department in access.manager_departments(user)


def can_see(user: User, alert: SecurityAlert) -> bool:
    if user.role in ("ADMIN", "AUDITOR"):
        return True
    if user.role == "MANAGER":
        # Managers see alerts once forwarded to them (and their outcome), for their departments.
        return alert.state != AUDITOR_REVIEW and _manager_covers(user, alert)
    return False


async def _manager_exists_for(db: AsyncSession, alert: SecurityAlert) -> bool:
    """Is there an active manager, OTHER than the alert's subject, who covers its department?"""
    if not alert.department:
        return False
    managers = (await db.execute(select(User).where(User.role == "MANAGER", User.is_active.is_(True)))).scalars().all()
    return any(alert.department in access.manager_departments(m) and m.id != alert.subject_user_id for m in managers)


async def _transition(db: AsyncSession, alert: SecurityAlert, actor: User, action: str, to_state: str,
                      note: Optional[str], client_ip: Optional[str]) -> SecurityAlert:
    from app.api.dependencies import record_audit  # avoid import cycle
    frm = alert.state
    alert.state = to_state
    db.add(SecurityAlertAction(alert_id=alert.id, actor_user_id=actor.id, actor_did=actor.did, actor_role=actor.role,
                               action=action, from_state=frm, to_state=to_state, note=(note or "")[:1000]))
    await record_audit(db, f"ALERT_{action}", actor_did=actor.did, target_did=alert.subject_did,
                       asset_serial=alert.asset_serial, client_ip=client_ip,
                       details={"alert_id": alert.alert_id, "from": frm, "to": to_state, "note": (note or "")[:500]})
    return alert


def _not_subject(actor: User, alert: SecurityAlert):
    if alert.subject_user_id and alert.subject_user_id == actor.id:
        raise HTTPException(status_code=403, detail="You cannot act on an alert about yourself.")


async def forward(db: AsyncSession, alert: SecurityAlert, actor: User, note: Optional[str], client_ip: Optional[str]):
    _not_subject(actor, alert)
    if alert.state == AUDITOR_REVIEW and actor.role == "AUDITOR":
        if not await _manager_exists_for(db, alert):
            # Nobody independent can review at the manager stage: go straight to Admins
            # rather than parking the alert in a queue no one reads.
            return await _transition(db, alert, actor, "FORWARDED_TO_ADMIN", ADMIN_REVIEW,
                                     f"[no independent manager covers this department] {note or ''}".strip(), client_ip)
        return await _transition(db, alert, actor, "FORWARDED_TO_MANAGER", MANAGER_REVIEW, note, client_ip)
    if alert.state == MANAGER_REVIEW:
        if actor.role == "MANAGER" and _manager_covers(actor, alert):
            return await _transition(db, alert, actor, "FORWARDED_TO_ADMIN", ADMIN_REVIEW, note, client_ip)
        if actor.role == "ADMIN" and not await _manager_exists_for(db, alert):
            return await _transition(db, alert, actor, "FORWARDED_TO_ADMIN", ADMIN_REVIEW,
                                     f"[no independent manager covers this department] {note or ''}", client_ip)
    raise HTTPException(status_code=403, detail=f"Your role cannot forward an alert in state {alert.state}.")


async def dismiss(db: AsyncSession, alert: SecurityAlert, actor: User, note: Optional[str], client_ip: Optional[str]):
    _not_subject(actor, alert)
    if not note or not note.strip():
        raise HTTPException(status_code=400, detail="Explain why this is a false alarm.")
    allowed = ((alert.state == AUDITOR_REVIEW and actor.role == "AUDITOR")
               or (alert.state == MANAGER_REVIEW and actor.role == "MANAGER" and _manager_covers(actor, alert))
               or (alert.state == ADMIN_REVIEW and actor.role == "ADMIN"))
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Your role cannot dismiss an alert in state {alert.state}.")
    return await _transition(db, alert, actor, "DISMISSED", DISMISSED, note, client_ip)


async def revoke_subject(db: AsyncSession, alert: SecurityAlert, actor: User, note: Optional[str], client_ip: Optional[str]):
    from app.services.identity import revoke_identity
    _not_subject(actor, alert)
    if actor.role != "ADMIN" or alert.state != ADMIN_REVIEW:
        raise HTTPException(status_code=403, detail="Only an Admin can revoke an identity, from an alert escalated to Admin.")
    if not alert.subject_user_id:
        raise HTTPException(status_code=409, detail="This alert is not linked to a LexCorp identity.")
    target = (await db.execute(select(User).where(User.id == alert.subject_user_id))).scalar_one()
    await revoke_identity(db, actor, target, note or f"Revoked from security alert {alert.alert_id}",
                          client_ip=client_ip, context={"alert_id": alert.alert_id})
    return await _transition(db, alert, actor, "IDENTITY_REVOKED", IDENTITY_REVOKED, note, client_ip)


# ------------------------------------------------------------------ AI scoring of API actions

_AI_EVENT = {
    "DOCUMENT_VIEWED": ("AccessAttempted", False),
    "DOCUMENT_DOWNLOADED": ("AccessAttempted", False),
    "REVISION_SUBMITTED": ("AssetUpdated", True),
    "PHYSICAL_ASSET_CREATED": ("AssetMinted", True),
    "ACCESS_GRANTED": ("RoleAssigned", True),
    "AuthenticationFailed": ("AccessAttempted", False),
}


def ai_score(event_type: str, actor: Optional[User], *, owner_did: Optional[str] = None, granted: bool = True,
             sensitivity: int = 1) -> dict:
    """Local, air-gapped Isolation Forest risk assessment for an API-level action.
    Never raises; returns {} when the model is unavailable."""
    try:
        from app.services.ai import ai_engine
        mapped, is_write = _AI_EVENT.get(event_type, ("AccessAttempted", False))
        did = actor.did if actor else None
        ai_engine.record_event(did, mapped, granted=granted)
        result = ai_engine.analyze_event(event_type=mapped, actor_role=actor.role if actor else "USER", actor_did=did,
                                         target_did=owner_did, is_write=is_write, asset_sensitivity_tier=sensitivity)
        if result.get("risk_label") in (None, "UNKNOWN", "ERROR"):
            return {}
        return {"risk_label": result["risk_label"], "risk_score": result.get("risk_score"),
                "ai": {"anomaly_score": result.get("anomaly_score"), "model": "IsolationForest(local)",
                       "native_label": result.get("native_risk_label"), "label_basis": result.get("label_basis")}}
    except Exception as e:
        logger.warning("AI risk scoring unavailable: %s", e)
        return {}
