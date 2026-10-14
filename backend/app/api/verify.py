"""QR verification of digital action records (spec 31, 46, 62).

The QR on every protected copy encodes only PUBLIC_BASE_URL/verify/action/<ACTION_ID>.
The QR is not the trust anchor: the action ID is resolved against the authoritative
database record (and the version's hash / blockchain reference). Nothing sensitive is
in the QR itself, and no client-supplied parameter other than the action ID is used to
look anything up.

  GET  /verify/action/{id}               public minimal proof, plus RBAC-scoped detail
  POST /verify/action/{id}/compare       cross-check what a copy *shows* (typed fields and/or
                                         its SHA-256) against the stored record
  POST /verify/action/{id}/compare-file  the same for an uploaded copy: its watermark text,
                                         its SHA-256 and its invisible mark

  Auditors only (every check, with what the record says and why anything failed):
  GET  /verify/audit/action/{id}, POST /verify/audit/action/{id}/compare[-file],
  GET  /verify/audit/asset/{serial}, POST /verify/audit/identify

Every lookup and comparison is written to the audit trail; the checks themselves go under
details["verification"], which only Auditors are shown.
"""

import io
import re
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db, get_onboarded_user, get_optional_user, get_request_client_ip, record_audit
from app.core.config import settings
from app.core.limiter import limiter
from app.models.domain import Asset, DocumentAction, User
from app.services import access, verification as vf
from app.core.safe_files import limited_pages
from app.services.watermark import detect_type, office_text, short_wallet

router = APIRouter(prefix="/verify", tags=["verify"])

_ID_RE = re.compile(r"^(CRT|VW|DL|MOD|ACR)-\d{8}-\d{4,}$")
_MAX_FILE = 50 * 1024 * 1024


class CompareRequest(BaseModel):
    """Values exactly as they appear on the copy being checked, and optionally the file's SHA-256."""
    fields: dict[str, str] = {}
    asset_serial: Optional[str] = None
    version: Optional[int] = None
    sha256: Optional[str] = None


async def _find(db: AsyncSession, action_id: str):
    if not _ID_RE.match(action_id or ""):
        return None, None
    action = (await db.execute(select(DocumentAction).where(DocumentAction.action_id == action_id))).scalar_one_or_none()
    asset = action and (await db.execute(select(Asset).where(Asset.id == action.asset_id))).scalar_one_or_none()
    return (action, asset) if action and asset else (None, None)


async def _load(db: AsyncSession, action_id: str, request: Request, user: Optional[User], via: str):
    known = bool(_ID_RE.match(action_id or ""))
    if not known and user is None:
        # anonymous junk is refused without writing to the append-only audit trail
        raise HTTPException(status_code=404, detail="Not a LexCorp action reference.")
    action, asset = await _find(db, action_id)
    if action is None:
        await record_audit(db, "VERIFICATION_LOOKUP", actor_did=user.did if user else None,
                           client_ip=get_request_client_ip(request),
                           details={"action_id": action_id[:64], "found": False, "via": via, "verification": {"checks": [
                               vf.check("record", "record", "Reference exists in the LexCorp record", "differs", found=action_id[:64],
                                        reason="No LexCorp record exists for this reference." if known
                                        else "This is not the format of a LexCorp reference.")]}})
        await db.commit()
        raise HTTPException(status_code=404, detail="No LexCorp record exists for this reference." if known
                            else "Not a LexCorp action reference.")
    return action, asset


async def _lineage(db: AsyncSession, asset: Asset) -> list[Asset]:
    root_id = asset.root_asset_id or asset.id
    rows = await db.execute(select(Asset).where(or_(Asset.root_asset_id == root_id, Asset.id == root_id)).order_by(Asset.version_number))
    return list(rows.scalars().all())


async def _user(db: AsyncSession, user_id) -> Optional[User]:
    return (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none() if user_id else None


def _require_auditor(user: User) -> None:
    if user.role != "AUDITOR":
        raise HTTPException(status_code=403, detail="Detailed verification is part of the Auditor role.")


async def _record_detail(db: AsyncSession, action: DocumentAction, asset: Asset, current_user: Optional[User]) -> dict:
    lineage = await _lineage(db, asset)
    latest_approved = max((a.version_number for a in lineage if a.approval_status in ("APPROVED", "ACTIVE")), default=None)
    public = {
        "valid": True,
        "action_id": action.action_id,
        "action_type": action.action_type,
        "action_date": action.created_at.date().isoformat() if action.created_at else None,
        "document_version": asset.version_number,
        "document_status": asset.approval_status,
        "is_latest_approved_version": asset.version_number == latest_approved,
        "version_sha256": asset.file_hash,
        "modifications_in_lineage": sum(1 for a in lineage if a.action_type == "MODIFICATION"),
        "chain_id": settings.CHAIN_ID,
        "detail_level": "PUBLIC",
    }
    if not current_user or not await access.can_see_asset(db, current_user, asset):
        return public

    root = next((a for a in lineage if a.version_number == 1), lineage[0])
    creator_action = (await db.execute(select(DocumentAction).where(DocumentAction.action_id == root.action_id))).scalar_one_or_none() if root.action_id else None
    creator = await _user(db, creator_action.actor_id) if creator_action else None
    actor = await _user(db, action.actor_id)
    trail = []
    for v in lineage:
        if v.action_type != "MODIFICATION" or not v.action_id:
            continue
        mod = (await db.execute(select(DocumentAction).where(DocumentAction.action_id == v.action_id))).scalar_one_or_none()
        modifier = await _user(db, mod.actor_id) if mod else None
        trail.append({
            "modification_id": v.action_id, "version": v.version_number, "status": v.approval_status,
            "sha256": v.file_hash, "modifier": modifier.name if modifier else None,
            "modifier_wallet": modifier.wallet_address if modifier else None,
            "modified_at": mod.created_at.isoformat() if mod and mod.created_at else None,
            "approved_by": mod.approver_did if mod else None,
            "download_id": (mod.details or {}).get("download_id") if mod else None,
        })
    detail = {
        **public,
        "detail_level": "AUTHORIZED",
        "asset_serial": asset.serial_number,
        "root_serial": root.serial_number,
        "token_id": root.token_id,
        "creation_id": root.action_id,
        "creator": creator.name if creator else None,
        "creator_wallet": creator.wallet_address if creator else None,
        "action_actor": actor.name if actor else None,
        "action_actor_wallet": short_wallet(actor.wallet_address) if actor else None,
        "versions": [{"version": v.version_number, "serial": v.serial_number, "sha256": v.file_hash,
                      "status": v.approval_status, "action_id": v.action_id} for v in lineage],
        "modification_trail": trail,
        "recorded_watermark": vf.recorded_fields(action),
    }
    if current_user.role in ("ADMIN", "AUDITOR") or access.can_manage_asset(current_user, asset):
        detail["action_client_ip"] = action.client_ip
    return detail


async def _lookup_audit(db, action, asset, request, user, via, detail):
    checks = [vf.check("record", "record", "Reference exists in the LexCorp record", "match", expected=action.action_id,
                       found=action.action_id, reason=f"{action.action_type.title()} of {asset.serial_number} version {asset.version_number}."),
              vf.check("latest", "record", "Latest approved version", "match" if detail["is_latest_approved_version"] else "unavailable",
                       expected=asset.version_number, reason="" if detail["is_latest_approved_version"]
                       else "A newer approved version of this document exists.")]
    await record_audit(db, "VERIFICATION_LOOKUP", actor_did=user.did if user else None, asset_serial=asset.serial_number,
                       client_ip=get_request_client_ip(request),
                       details={"action_id": action.action_id, "found": True, "via": via, "detail_level": detail["detail_level"],
                                "verification": {"checks": checks, "issued_copy": await vf.describe_action(db, action)}})
    await db.commit()


@router.get("/action/{action_id}")
@limiter.limit("30/minute")
async def verify_action(
    action_id: str,
    request: Request,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    action, asset = await _load(db, action_id, request, current_user, "public")
    detail = await _record_detail(db, action, asset, current_user)
    await _lookup_audit(db, action, asset, request, current_user, "public", detail)
    return detail


async def _alert_already_raised(db: AsyncSession, action_id: str) -> bool:
    """An open alert, or a tamper event in the last hour, already covers this reference."""
    from datetime import UTC, datetime, timedelta
    from app.models.domain import AuditEvent, SecurityAlert
    from app.services.alerts import OPEN_STATES
    open_alert = (await db.execute(select(SecurityAlert.id).where(
        SecurityAlert.related_action_id == action_id, SecurityAlert.state.in_(OPEN_STATES)).limit(1))).first()
    if open_alert:
        return True
    recent = (await db.execute(select(AuditEvent.id).where(
        AuditEvent.event_type == "WATERMARK_TAMPER_DETECTED",
        AuditEvent.created_at >= datetime.now(UTC) - timedelta(hours=1),
        AuditEvent.risk_factors["action_id"].as_string() == action_id).limit(1))).first()
    return bool(recent)


async def _record_result(db: AsyncSession, request: Request, user: Optional[User], asset: Asset, result: dict, via: str) -> None:
    mismatch = result["verdict"] == "MISMATCH"
    # Anyone can hit the public page, so repeated anonymous mismatches for the same copy are
    # recorded but don't open alert after alert in the Auditor's queue.
    raise_alert = True
    if mismatch and via == "public" and user is None:
        raise_alert = not await _alert_already_raised(db, result["action_id"])
    await record_audit(db, "WATERMARK_TAMPER_DETECTED" if mismatch else "COPY_VERIFIED",
                       actor_did=user.did if user else None, asset_serial=asset.serial_number,
                       client_ip=get_request_client_ip(request),
                       risk_label="HIGH" if mismatch else None, risk_score=0.8 if mismatch else None,
                       alert=raise_alert,
                       details={**vf.audit_summary(result), "via": via,
                                **({"reason": f"A copy checked against {result['action_id']} does not match its record"} if mismatch else {}),
                                **({} if raise_alert else {"alert": "already raised for this reference"})})
    await db.commit()


def _extract_watermark_fields(data: bytes, filename: str) -> dict[str, str]:
    """The Document Control block of an uploaded copy (PDF, text, Word, PowerPoint, Excel)."""
    text = ""
    if data[:5] == b"%PDF-":
        from pypdf import PdfReader
        text = "\n".join(p.extract_text() or "" for p in limited_pages(PdfReader(io.BytesIO(data)).pages))
    elif data[:4] == b"PK\x03\x04":
        try:
            kind = detect_type(data, filename)
            text = office_text(data, kind) if kind in ("docx", "pptx", "xlsx") else ""
        except Exception:
            text = ""
    elif data[:8] == b"\x89PNG\r\n\x1a\n" or data[:3] == b"\xff\xd8\xff":
        return {}  # images: checked by hash and invisible mark
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=415, detail="Upload the copy as it was issued (PDF, image, Word, PowerPoint, Excel or text).")
    fields = {}
    control = text[text.find("LexCorp Document Control"):] if "LexCorp Document Control" in text else text
    for line in control.splitlines():
        if ": " in line:
            label, value = line.split(": ", 1)
            if label.strip() in vf.FIELDS and label.strip() not in fields:
                fields[label.strip()] = value.strip()
    return fields


async def _read_upload(file: UploadFile) -> bytes:
    data = await file.read()
    if len(data) > _MAX_FILE:
        raise HTTPException(status_code=413, detail="File too large.")
    if not data:
        raise HTTPException(status_code=400, detail="The file is empty.")
    return data


async def _compare(db, request, user, action_id, body: CompareRequest, via):
    action, asset = await _load(db, action_id, request, user, via)
    result = await vf.evaluate_copy(db, action, asset, method="typed", claimed=body.fields, serial=body.asset_serial,
                                    version=body.version, typed_hash=body.sha256)
    await _record_result(db, request, user, asset, result, via)
    return result


async def _compare_file(db, request, user, action_id, file: UploadFile, via):
    action, asset = await _load(db, action_id, request, user, via)
    data = await _read_upload(file)
    claimed = _extract_watermark_fields(data, file.filename or "")
    result = await vf.evaluate_copy(db, action, asset, method="file", claimed=claimed, file_bytes=data,
                                    filename=(file.filename or "")[:200])
    await _record_result(db, request, user, asset, result, via)
    return result


@router.post("/action/{action_id}/compare")
@limiter.limit("20/minute")
async def compare_action(
    action_id: str,
    body: CompareRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    return vf.public_view(await _compare(db, request, current_user, action_id, body, "public"))


@router.post("/action/{action_id}/compare-file")
@limiter.limit("10/minute")
async def compare_action_file(
    action_id: str,
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Check an uploaded copy against the record: its watermark text, its hash, its invisible mark."""
    return vf.public_view(await _compare_file(db, request, current_user, action_id, file, "public"))


# ------------------------------------------------------------------ Auditor verification

@router.get("/audit/action/{action_id}")
@limiter.limit("60/minute")
async def audit_verify_action(action_id: str, request: Request, db: AsyncSession = Depends(get_db),
                              current_user: User = Depends(get_onboarded_user)):
    _require_auditor(current_user)
    action, asset = await _load(db, action_id, request, current_user, "auditor")
    detail = await _record_detail(db, action, asset, current_user)
    await _lookup_audit(db, action, asset, request, current_user, "auditor", detail)
    return {**detail, "issued_copy": await vf.describe_action(db, action) | {
        "copy_sha256": action.copy_sha256, "hidden_mark_recorded": bool(action.hidden_mark)}}


@router.post("/audit/action/{action_id}/compare")
@limiter.limit("60/minute")
async def audit_compare_action(action_id: str, body: CompareRequest, request: Request, db: AsyncSession = Depends(get_db),
                               current_user: User = Depends(get_onboarded_user)):
    _require_auditor(current_user)
    return await _compare(db, request, current_user, action_id, body, "auditor")


@router.post("/audit/action/{action_id}/compare-file")
@limiter.limit("30/minute")
async def audit_compare_action_file(action_id: str, request: Request, file: UploadFile = File(...),
                                    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_onboarded_user)):
    _require_auditor(current_user)
    return await _compare_file(db, request, current_user, action_id, file, "auditor")


@router.post("/audit/identify")
@limiter.limit("30/minute")
async def audit_identify_file(request: Request, file: UploadFile = File(...), db: AsyncSession = Depends(get_db),
                              current_user: User = Depends(get_onboarded_user)):
    """A file with no (or an untrusted) reference: which issued copy is it, by hash and invisible mark?"""
    _require_auditor(current_user)
    data = await _read_upload(file)
    result = await vf.identify_file(db, data)
    found = result["exact_copy_of"] or (result["hidden_mark_of"][0] if result["hidden_mark_of"] else None)
    await record_audit(db, "COPY_IDENTIFIED", actor_did=current_user.did, client_ip=get_request_client_ip(request),
                       asset_serial=found["asset_serial"] if found else None,
                       details={"found": bool(found or result["unwatermarked_original_of"]), "via": "auditor",
                                "verification": {"file": {"name": (file.filename or "")[:200], "size": len(data), "sha256": result["sha256"]},
                                                 "identification": result}})
    await db.commit()
    return result


@router.get("/audit/asset/{serial}")
@limiter.limit("60/minute")
async def audit_verify_asset(serial: str, request: Request, db: AsyncSession = Depends(get_db),
                             current_user: User = Depends(get_onboarded_user)):
    from app.services.contract import contract_service
    _require_auditor(current_user)
    serial = serial.strip()
    asset = (await db.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one_or_none()
    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None and asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    on_chain = None
    if token_id is not None:
        on_chain = contract_service.get_digital_asset(token_id)
        if not on_chain or not on_chain.get("is_digital"):
            on_chain = contract_service.get_asset(token_id)
    result = await vf.evaluate_asset(db, serial, asset, token_id, on_chain)
    await record_audit(db, "ASSET_VERIFIED", actor_did=current_user.did, asset_serial=serial,
                       client_ip=get_request_client_ip(request),
                       details={"verdict": result["verdict"], "via": "auditor", "detail_level": "AUDITOR",
                                "verification": {"checks": result["checks"], "contradictions": result["contradictions"]}})
    await db.commit()
    return {**result, "asset": {"name": asset.name if asset else None, "is_physical": asset.is_physical if asset else None,
                                "department": asset.department if asset else None, "token_id": token_id,
                                "version": asset.version_number if asset else None}}
