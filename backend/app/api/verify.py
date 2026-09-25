"""QR verification of digital action records (spec 31, 46, 62).

The QR on every protected copy encodes only PUBLIC_BASE_URL/verify/action/<ACTION_ID>.
The QR is not the trust anchor: the action ID is resolved against the authoritative
database record (and the version's hash / blockchain reference). Nothing sensitive is
in the QR itself, and no client-supplied parameter other than the action ID is used to
look anything up.

  GET  /verify/action/{id}          public minimal proof, plus RBAC-scoped detail
  POST /verify/action/{id}/compare  cross-check what a copy *shows* (typed fields or an
                                    uploaded PDF/text copy) against the stored record,
                                    so an edited watermark is detectable.
"""

import io
import re
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db, get_optional_user, get_request_client_ip, record_audit
from app.core.config import settings
from app.core.limiter import limiter
from app.models.domain import Asset, DocumentAction, User
from app.services import access
from app.services.watermark import short_wallet

router = APIRouter(prefix="/verify", tags=["verify"])

_ID_RE = re.compile(r"^(CRT|VW|DL|MOD|ACR)-\d{8}-\d{4,}$")
# Fields that appear on a protected copy's watermark, keyed by their label.
_FIELDS = {
    "Viewed by": "actor_name", "Downloaded by": "actor_name", "Wallet": "actor_wallet", "IP": "client_ip",
    "Date": "date", "View ID": "action_id", "Download ID": "action_id", "Owner": "owner",
}


class CompareRequest(BaseModel):
    """Values exactly as they appear on the copy being checked."""
    fields: dict[str, str]
    asset_serial: Optional[str] = None
    version: Optional[int] = None


async def _load(db: AsyncSession, action_id: str):
    if not _ID_RE.match(action_id or ""):
        raise HTTPException(status_code=404, detail="Not a LexCorp action reference.")
    action = (await db.execute(select(DocumentAction).where(DocumentAction.action_id == action_id))).scalar_one_or_none()
    asset = action and (await db.execute(select(Asset).where(Asset.id == action.asset_id))).scalar_one_or_none()
    if not action or not asset:
        raise HTTPException(status_code=404, detail="No LexCorp record exists for this reference.")
    return action, asset


async def _lineage(db: AsyncSession, asset: Asset) -> list[Asset]:
    root_id = asset.root_asset_id or asset.id
    rows = await db.execute(select(Asset).where(or_(Asset.root_asset_id == root_id, Asset.id == root_id)).order_by(Asset.version_number))
    return list(rows.scalars().all())


async def _user(db: AsyncSession, user_id) -> Optional[User]:
    return (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none() if user_id else None


def _recorded_fields(action: DocumentAction) -> dict[str, str]:
    """Parse the authoritative watermark block stored on the action when the copy was made."""
    out = {}
    for line in (action.watermark_text or "").splitlines():
        if ": " in line:
            label, value = line.split(": ", 1)
            if label in _FIELDS and label not in out:
                out[label] = value.strip()
    return out


@router.get("/action/{action_id}")
@limiter.limit("30/minute")
async def verify_action(
    action_id: str,
    request: Request,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    action, asset = await _load(db, action_id)
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
        "recorded_watermark": _recorded_fields(action),
    }
    if current_user.role in ("ADMIN", "AUDITOR") or access.can_manage_asset(current_user, asset):
        detail["action_client_ip"] = action.client_ip
    return detail


def _compare(action: DocumentAction, asset: Asset, claimed: dict[str, str], serial: Optional[str], version: Optional[int]):
    recorded = _recorded_fields(action)
    results, mismatches = [], []
    for label, value in claimed.items():
        label = label.strip()
        if label not in _FIELDS:
            continue
        expected = recorded.get(label)
        ok = expected is not None and expected == value.strip()
        results.append({"field": label, "shown": value.strip(), "matches_record": ok})
        if not ok:
            mismatches.append(label)
    if serial is not None and serial != asset.serial_number:
        mismatches.append("asset_serial")
    if version is not None and version != asset.version_number:
        mismatches.append("version")
    return {
        "action_id": action.action_id,
        "record_found": True,
        "fields_checked": len(results),
        "results": results,
        "mismatches": mismatches,
        "verdict": "MATCH" if results and not mismatches else ("MISMATCH" if mismatches else "NOTHING_TO_COMPARE"),
    }


@router.post("/action/{action_id}/compare")
@limiter.limit("20/minute")
async def compare_action(
    action_id: str,
    body: CompareRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    action, asset = await _load(db, action_id)
    result = _compare(action, asset, body.fields, body.asset_serial, body.version)
    if result["verdict"] == "MISMATCH":
        await record_audit(db, "WATERMARK_TAMPER_DETECTED", actor_did=current_user.did if current_user else None,
                           asset_serial=asset.serial_number, client_ip=get_request_client_ip(request),
                           risk_label="HIGH", risk_score=0.8,
                           details={"action_id": action.action_id, "mismatched_fields": result["mismatches"]})
        await db.commit()
    return result


def _extract_watermark_fields(data: bytes, filename: str) -> dict[str, str]:
    text = ""
    if data[:5] == b"%PDF-":
        from pypdf import PdfReader
        text = "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=415, detail="Upload the PDF or text copy to check it.")
    fields = {}
    control = text[text.find("LexCorp Document Control"):] if "LexCorp Document Control" in text else text
    for line in control.splitlines():
        if ": " in line:
            label, value = line.split(": ", 1)
            if label.strip() in _FIELDS and label.strip() not in fields:
                fields[label.strip()] = value.strip()
    return fields


@router.post("/action/{action_id}/compare-file")
@limiter.limit("10/minute")
async def compare_action_file(
    action_id: str,
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """Check a copy's visible watermark (its Document Control block) against the record."""
    action, asset = await _load(db, action_id)
    data = await file.read()
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large.")
    claimed = _extract_watermark_fields(data, file.filename or "")
    result = _compare(action, asset, claimed, None, None)
    if result["verdict"] == "MISMATCH":
        await record_audit(db, "WATERMARK_TAMPER_DETECTED", actor_did=current_user.did if current_user else None,
                           asset_serial=asset.serial_number, client_ip=get_request_client_ip(request),
                           risk_label="HIGH", risk_score=0.8,
                           details={"action_id": action.action_id, "mismatched_fields": result["mismatches"], "source": "file"})
        await db.commit()
    return result
