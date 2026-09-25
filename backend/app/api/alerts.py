"""Security alert queue: Auditor -> Manager -> Admin (spec 39-43)."""

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db, get_onboarded_user, get_request_client_ip, get_step_up_token
from app.models.domain import SecurityAlert, SecurityAlertAction, User
from app.services import alerts as svc
from app.services import mfa
from app.services.watermark import short_wallet

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertDecision(BaseModel):
    note: Optional[str] = None
    totp_code: Optional[str] = None


def _row(a: SecurityAlert, subject: Optional[User] = None) -> dict:
    return {
        "alert_id": a.alert_id, "state": a.state, "source": a.source, "risk_level": a.risk_level, "risk_score": a.risk_score,
        "reason": a.reason, "event_type": a.event_type, "asset_serial": a.asset_serial, "related_action_id": a.related_action_id,
        "client_ip": a.client_ip, "created_at": a.created_at.isoformat() if a.created_at else None,
        "subject": {"name": subject.name if subject else None, "did": a.subject_did, "role": a.subject_role,
                    "wallet": short_wallet(a.subject_wallet) if a.subject_wallet else None, "department": a.department,
                    "is_active": subject.is_active if subject else None},
    }


async def _load(db: AsyncSession, alert_id: str, user: User) -> SecurityAlert:
    alert = (await db.execute(select(SecurityAlert).where(SecurityAlert.alert_id == alert_id))).scalar_one_or_none()
    if not alert or not svc.can_see(user, alert):
        raise HTTPException(status_code=404, detail="Alert not found.")
    return alert


def _require_security_role(user: User):
    if user.role not in ("AUDITOR", "MANAGER", "ADMIN"):
        raise HTTPException(status_code=403, detail="Not authorized for security alerts.")


@router.get("")
async def list_alerts(
    state: Optional[str] = Query(None),
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
):
    _require_security_role(current_user)
    query = select(SecurityAlert).order_by(desc(SecurityAlert.created_at))
    if state:
        query = query.where(SecurityAlert.state == state.strip().upper())
    rows = [a for a in (await db.execute(query)).scalars().all() if svc.can_see(current_user, a)]
    subjects = {}
    ids = {a.subject_user_id for a in rows if a.subject_user_id}
    if ids:
        subjects = {u.id: u for u in (await db.execute(select(User).where(User.id.in_(ids)))).scalars().all()}
    return [_row(a, subjects.get(a.subject_user_id)) for a in rows]


@router.get("/{alert_id}")
async def get_alert(alert_id: str, current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    _require_security_role(current_user)
    alert = await _load(db, alert_id, current_user)
    subject = (await db.execute(select(User).where(User.id == alert.subject_user_id))).scalar_one_or_none() if alert.subject_user_id else None
    history = (await db.execute(select(SecurityAlertAction).where(SecurityAlertAction.alert_id == alert.id)
                                .order_by(SecurityAlertAction.created_at))).scalars().all()
    return {**_row(alert, subject), "history": [{
        "action": h.action, "from": h.from_state, "to": h.to_state, "actor_did": h.actor_did, "actor_role": h.actor_role,
        "note": h.note, "at": h.created_at.isoformat() if h.created_at else None} for h in history]}


@router.post("/{alert_id}/forward")
async def forward_alert(alert_id: str, request: Request, body: AlertDecision = Body(default=AlertDecision()),
                        current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    _require_security_role(current_user)
    alert = await _load(db, alert_id, current_user)
    await svc.forward(db, alert, current_user, body.note, get_request_client_ip(request))
    await db.commit()
    return {"alert_id": alert.alert_id, "state": alert.state}


@router.post("/{alert_id}/dismiss")
async def dismiss_alert(alert_id: str, request: Request, body: AlertDecision = Body(default=AlertDecision()),
                        current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    _require_security_role(current_user)
    alert = await _load(db, alert_id, current_user)
    await svc.dismiss(db, alert, current_user, body.note, get_request_client_ip(request))
    await db.commit()
    return {"alert_id": alert.alert_id, "state": alert.state}


@router.post("/{alert_id}/revoke-identity")
async def revoke_from_alert(alert_id: str, request: Request, body: AlertDecision = Body(default=AlertDecision()),
                            step_up_token: Optional[str] = Depends(get_step_up_token),
                            current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    """Admin revokes the subject identity (existing revocation mechanism) with Factor 3."""
    _require_security_role(current_user)
    alert = await _load(db, alert_id, current_user)
    if current_user.role != "ADMIN" or alert.state != svc.ADMIN_REVIEW:
        raise HTTPException(status_code=403, detail="Only an Admin can revoke an identity, from an alert escalated to Admin.")
    await mfa.require_factor(db, current_user, "identity.revoke", totp_code=body.totp_code, step_up_token=step_up_token)
    await svc.revoke_subject(db, alert, current_user, body.note, get_request_client_ip(request))
    await db.commit()
    # Remove the revoked identity's on-chain operational roles (audited; retried if it fails).
    from app.services.chain import sync_user_chain_roles
    subject = (await db.execute(select(User).where(User.id == alert.subject_user_id))).scalar_one()
    chain_roles = await sync_user_chain_roles(db, subject, actor_did=current_user.did, client_ip=get_request_client_ip(request))
    return {"alert_id": alert.alert_id, "state": alert.state, "chain_roles_ok": chain_roles.get("ok")}
