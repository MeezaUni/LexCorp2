"""Security alert queue: Auditor -> Manager -> Admin (spec 39-43)."""

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi import Response

from app.api.dependencies import get_db, get_onboarded_user, get_request_client_ip, get_step_up_token, record_audit
from app.models.domain import Asset, AuditEvent, DocumentAction, SecurityAlert, SecurityAlertAction, User
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
    # Where "Forward" sends it from here, so the reviewer knows before clicking
    forward_to = None
    if alert.state == svc.AUDITOR_REVIEW:
        forward_to = "MANAGER" if await svc.manager_exists_for(db, alert) else "ADMIN"
    elif alert.state == svc.MANAGER_REVIEW:
        forward_to = "ADMIN"
    return {**_row(alert, subject), "forward_to": forward_to, "evidence": await _evidence(db, alert), "history": [{
        "action": h.action, "from": h.from_state, "to": h.to_state, "actor_did": h.actor_did, "actor_role": h.actor_role,
        "note": h.note, "at": h.created_at.isoformat() if h.created_at else None} for h in history]}


async def _source_factors(db: AsyncSession, alert: SecurityAlert) -> dict:
    if not alert.source_event_id:
        return {}
    event = (await db.execute(select(AuditEvent).where(AuditEvent.id == alert.source_event_id))).scalar_one_or_none()
    return event.risk_factors if event is not None and isinstance(event.risk_factors, dict) else {}


async def _evidence(db: AsyncSession, alert: SecurityAlert) -> Optional[dict]:
    """For a watermark tamper alert: what the copy said when it was issued (the record), what
    was found in the returned file (with page/slide/sheet), and whether the file can be viewed."""
    if alert.event_type != "WATERMARK_TAMPER_DETECTED":
        return None
    f = await _source_factors(db, alert)
    ev = f.get("evidence") or {}
    return {"download_id": f.get("download_id"), "modification_id": f.get("modification_id"),
            "recorded_watermark": f.get("recorded_watermark"), "findings": f.get("findings") or [],
            "has_file": bool(ev.get("file")), "filename": ev.get("filename")}


@router.get("/{alert_id}/evidence")
async def view_evidence(alert_id: str, request: Request, current_user: User = Depends(get_onboarded_user),
                        db: AsyncSession = Depends(get_db)):
    """The file as it was uploaded, as a protected view (watermarked for the reviewer, recorded)."""
    import hashlib
    import os
    from app.api.assets import OFFCHAIN_STORAGE_DIR, _verify_url
    from app.services.action_ids import next_action_id
    from app.services.hidden_mark import new_mark
    from app.services.watermark import UnsupportedDocumentType, WatermarkContext, render_view_copy

    _require_security_role(current_user)
    if current_user.role not in ("MANAGER", "ADMIN"):
        raise HTTPException(status_code=403, detail="The document itself is shown to the reviewing Manager or an Administrator. "
                                                    "Forward the alert to the Manager to have it checked.")
    alert = await _load(db, alert_id, current_user)
    ev = (await _source_factors(db, alert)).get("evidence") or {}
    rel = ev.get("file") or ""
    evidence_root = os.path.abspath(os.path.join(OFFCHAIN_STORAGE_DIR, "evidence"))
    path = os.path.abspath(os.path.join(OFFCHAIN_STORAGE_DIR, rel))
    if not rel or not path.startswith(evidence_root + os.sep) or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="No evidence file is stored for this alert.")
    asset = (await db.execute(select(Asset).where(Asset.serial_number == alert.asset_serial))).scalar_one_or_none()
    client_ip = get_request_client_ip(request)
    view_id = await next_action_id(db, "VW")
    ctx = WatermarkContext(kind="VIEW", actor_name=current_user.name or "Unnamed", actor_wallet=current_user.wallet_address,
                           client_ip=client_ip, action_id=view_id, verify_url=_verify_url(view_id), hidden_mark=new_mark())
    try:
        content, mime, _ = render_view_copy(open(path, "rb").read(), ev.get("filename") or "evidence", ctx)
    except UnsupportedDocumentType:
        raise HTTPException(status_code=415, detail="This evidence file can't be shown in the browser.")
    if asset is not None:
        db.add(DocumentAction(action_id=view_id, action_type="VIEW", asset_id=asset.id, asset_serial=asset.serial_number,
                              asset_version=asset.version_number, actor_id=current_user.id, actor_did=current_user.did,
                              status="COMPLETED", client_ip=client_ip, watermark_text="\n".join(ctx.all_lines()),
                              copy_sha256=hashlib.sha256(content).hexdigest(), hidden_mark=ctx.hidden_mark,
                              details={"evidence_for_alert": alert.alert_id}))
    await record_audit(db, "ALERT_EVIDENCE_VIEWED", actor_did=current_user.did, asset_serial=alert.asset_serial,
                       client_ip=client_ip, details={"alert_id": alert.alert_id, "view_id": view_id})
    await db.commit()
    return Response(content=content, media_type=mime, headers={"X-LexCorp-Action-Id": view_id, "Cache-Control": "no-store"})


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
