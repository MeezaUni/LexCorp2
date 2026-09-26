"""Asset management API endpoints (V2 Enterprise Consortium)."""

import hashlib
import os
import re
import uuid
from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile, File, Form, status, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List, Any
import time
import secrets
from datetime import datetime, timedelta, UTC


from app.core.limiter import limiter
from app.api.dependencies import get_db, get_current_user, get_current_active_user, get_onboarded_user, get_optional_user, get_request_client_ip, get_step_up_token, record_audit
from app.core.config import settings
from app.services.contract import contract_service
from app.services import copy_integrity
from app.services.watermark import (HistoryEntry, UnsupportedDocumentType, WatermarkContext, render_protected_copy,
                                   render_protected_copy_with_manifest, render_view_copy)
from app.services import watermark_strip
from app.services.qr import generate_qr_for_url
from app.services.asset_card import generate_physical_card_svg
from app.services import physical as phys
from sqlalchemy.exc import IntegrityError
from app.models.domain import Asset, MaintenanceRecord, User, DocumentAction, AuditEvent, AssetAccessGrant
from app.schemas.domain import DocumentProposalRequest, DocumentApprovalRequest, DocumentActionRead, DownloadRequest, DocumentRevisionRequest, PhysicalProposalRequest, ShareProposalRequest, AssetRead, OwnerDecisionRequest, FetchDownloadRequest, PhysicalStatusRequest, MintConfirmRequest
from app.services import access, grants as grant_svc, mfa
from app.services.alerts import ai_score
from app.services.action_ids import next_action_id, next_token_id
from sqlalchemy import select, desc, false, func, or_

# Simple in-memory TTL cache (60 seconds) for registry queries
_CACHE = {}
_CACHE_TTL = 60.0

def _get_cache(key: str):
    data = _CACHE.get(key)
    if data is None:
        return None
    timestamp, value = data
    if (time.time() - timestamp) > _CACHE_TTL:
        _CACHE.pop(key, None)
        return None
    return value

def _set_cache(key: str, value):
    _CACHE[key] = (time.time(), value)

import logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assets", tags=["assets"])


def _asset_row(asset: Asset, viewer: User) -> dict:
    data = {
        "id": asset.id,
        "token_id": asset.token_id,
        "serial_number": asset.serial_number,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "metadata_cid": asset.metadata_cid,
        "file_hash": asset.file_hash,
        "owner_id": asset.owner_id,
        "custodian_id": asset.custodian_id,
        "custodian_did": asset.custodian_did,
        "custodian_department": asset.custodian_department,
        "lifecycle_status": asset.lifecycle_status,
        "parent_asset_id": asset.parent_asset_id,
        "action_id": asset.action_id,
        "action_type": asset.action_type,
        "approval_status": asset.approval_status,
        "watermark_metadata": asset.watermark_metadata,
        "is_physical": asset.is_physical,
        "is_digital": not asset.is_physical,
        "offchain_uri": asset.metadata_cid,
        "mac_address": asset.mac_address,
        "device_unique_address": asset.device_unique_address,
        "location": asset.location,
        "department": asset.department,
        "version_number": asset.version_number,
        "root_asset_id": asset.root_asset_id,
        "owner_wallet": asset.owner.wallet_address if asset.owner else None,
        "owner_address": asset.owner.wallet_address if asset.owner else None,
        "owner_did": asset.owner.did if asset.owner else None,
        "owner_name": asset.owner.name if asset.owner else None,
        "custodian_name": asset.custodian.name if asset.custodian else None,
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
    }
    return access.redact_asset_dict(data, viewer, asset)


def _public_url(path: str) -> str:
    """Absolute URL on the configured web app (never a caller-supplied host)."""
    base = settings.PUBLIC_BASE_URL.rstrip("/")
    if "localhost" in base or "127.0.0.1" in base:
        lan = get_lan_ip()
        base = base.replace("localhost", lan).replace("127.0.0.1", lan)
    return f"{base}{path}"


def _verify_url(action_id: str) -> str:
    """QR payload: a verification reference only (no sensitive data in the QR itself).
    With the default localhost base, the host's LAN IP is used so phones can scan it;
    set PUBLIC_BASE_URL explicitly in real deployments."""
    base = settings.PUBLIC_BASE_URL.rstrip("/")
    if "localhost" in base or "127.0.0.1" in base:
        lan = get_lan_ip()
        base = base.replace("localhost", lan).replace("127.0.0.1", lan)
    return f"{base}/verify/action/{action_id}"


def _original_filename(asset: Asset) -> str:
    base = os.path.basename((asset.metadata_cid or "document").replace("secure-vault://", ""))
    # vault files are stored as <sha256>_<original name>
    return base.split("_", 1)[1] if re.match(r"^[0-9a-f]{64}_", base) else base


async def _modification_history(db: AsyncSession, asset: Asset) -> list[HistoryEntry]:
    """Authoritative cumulative history for this version: every MODIFICATION on the
    path root -> ... -> asset, from the database (never from the file's own text)."""
    chain = []
    node, seen = asset, set()
    while node is not None and node.id not in seen:
        seen.add(node.id)
        chain.append(node)
        node = (await db.execute(select(Asset).where(Asset.id == node.parent_asset_id))).scalar_one_or_none() if node.parent_asset_id else None
    history = []
    for version in reversed(chain):
        if version.action_type != "MODIFICATION" or not version.action_id:
            continue
        mod = (await db.execute(select(DocumentAction).where(DocumentAction.action_id == version.action_id))).scalar_one_or_none()
        if not mod:
            continue
        actor = (await db.execute(select(User).where(User.id == mod.actor_id))).scalar_one_or_none()
        history.append(HistoryEntry(
            modification_id=mod.action_id,
            modifier_wallet=actor.wallet_address if actor else mod.actor_did.split(":")[-1],
            modifier_name=actor.name if actor else None,
            when=mod.created_at,
            version=version.version_number,
        ))
    return history


async def _lineage_state(db: AsyncSession, asset: Asset) -> tuple[uuid.UUID, int, bool]:
    """(root id, latest APPROVED version number, whether a revision is pending) for a lineage."""
    root_id = asset.root_asset_id or asset.id
    in_lineage = or_(Asset.root_asset_id == root_id, Asset.id == root_id)
    latest = (await db.execute(
        select(func.max(Asset.version_number)).where(in_lineage, Asset.approval_status.in_(("APPROVED", "ACTIVE")))
    )).scalar_one() or 1
    pending = (await db.execute(
        select(func.count()).select_from(Asset).where(in_lineage, Asset.version_number > 1, Asset.approval_status == "PENDING_APPROVAL")
    )).scalar_one() > 0
    return root_id, latest, pending


def _read_vault_file(asset: Asset) -> bytes:
    offchain_uri = (asset.metadata_cid or "").replace("secure-vault://", "").replace("ipfs://", "").lstrip("/\\")
    storage_root = os.path.abspath(OFFCHAIN_STORAGE_DIR)
    filepath = os.path.abspath(os.path.join(storage_root, offchain_uri))
    if not os.path.exists(filepath):
        filepath = os.path.abspath(os.path.join(storage_root, os.path.basename(offchain_uri)))
    if not asset.metadata_cid or not filepath.startswith(storage_root + os.sep) or not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail="Document file is not available in the vault.")
    with open(filepath, "rb") as f:
        return f.read()


async def _visible_asset_or_404(db: AsyncSession, user: User, *, serial: Optional[str] = None, token_id: Optional[int] = None) -> Asset:
    """Load a registry asset the caller may see. Out-of-scope and unknown look identical (404)."""
    query = select(Asset)
    query = query.where(Asset.serial_number == serial) if serial is not None else query.where(Asset.token_id == token_id)
    asset = (await db.execute(query)).scalar_one_or_none()
    if not asset or not await access.can_see_asset(db, user, asset):
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


async def _managed_asset_or_403(db: AsyncSession, user: User, token_id: int) -> Asset:
    asset = (await db.execute(select(Asset).where(Asset.token_id == token_id))).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset is not in the LexCorp registry.")
    if not access.can_manage_asset(user, asset):
        raise HTTPException(status_code=403, detail="This asset is outside your authorized departments.")
    return asset

# Storage directory for off-chain encrypted documents
OFFCHAIN_STORAGE_DIR = settings.OFFCHAIN_STORAGE_DIR
os.makedirs(OFFCHAIN_STORAGE_DIR, exist_ok=True)


class MintRequest(BaseModel):
    totp_code: Optional[str] = None
    to_address: str
    token_id: int
    serial_number: str
    owner_did: str


class DigitalMintRequest(BaseModel):
    totp_code: Optional[str] = None
    to_address: str
    token_id: int
    serial_number: str
    owner_did: str
    file_hash: str
    offchain_uri: str


class MintCalldataResponse(BaseModel):
    calldata: dict
    contract_address: str


class AccessCheckRequest(BaseModel):
    token_id: int
    requester_did: str
    caller_address: str


class TransferRequest(BaseModel):
    to_address: str
    token_id: int
    new_owner_did: str

@router.post("/transfer/prepare", response_model=MintCalldataResponse)
async def prepare_transfer(request: TransferRequest, current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    """Prepare unsigned transfer transaction calldata.

    Authorization Rules:
    - ADMIN: Can transfer both DIGITAL and PHYSICAL assets
    - MANAGER: Can transfer PHYSICAL assets only (DIGITAL transfer denied)
    - USER: Cannot transfer any assets
    - AUDITOR: Cannot transfer any assets
    """
    # Hierarchy/Permissions Check
    if current_user.role not in ["ADMIN", "MANAGER"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{current_user.role}' is not permitted to transfer assets."
        )

    # Department & Asset Type checks for MANAGER
    if current_user.role == "MANAGER":
        asset = contract_service.get_digital_asset(request.token_id)
        if asset and asset.get("is_digital"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Managers are not permitted to transfer DIGITAL assets. Managers can only transfer PHYSICAL defense hardware."
            )
        await _managed_asset_or_403(db, current_user, request.token_id)

    # AI Risk Check: Block HIGH-risk actors from sensitive transfer operations
    from app.services.ai import check_actor_risk_level
    actor_did = f"did:ethr:13371:{current_user.wallet_address.lower()}"
    risk_check = await check_actor_risk_level(actor_did, db)

    if risk_check["is_high_risk"]:
        # Log blocked attempt to audit
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(
            f"BLOCKED: Asset transfer attempt by {actor_did} due to high risk pattern. "
            f"Reason: {risk_check['reason']}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation blocked due to anomalous behavior pattern detected by AI security system. {risk_check['reason']}. Contact your security administrator for review."
        )

    calldata = contract_service.prepare_transfer_calldata(
        request.to_address,
        request.token_id,
        request.new_owner_did
    )
    return MintCalldataResponse(
        calldata=calldata,
        contract_address=contract_service.contract_address,
    )

@router.post("/revoke/prepare", response_model=MintCalldataResponse)
async def prepare_revoke(request: AccessCheckRequest, current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    """Prepare unsigned revoke transaction calldata.

    Authorization Rules:
    - ADMIN: Can revoke both DIGITAL and PHYSICAL assets
    - MANAGER: Can revoke PHYSICAL assets only (DIGITAL revoke denied)
    - USER: Can revoke only their OWN DIGITAL assets (must be owner)
    - AUDITOR: Cannot revoke any assets
    """
    token_id = request.token_id

    # Get asset information
    asset = contract_service.get_digital_asset(token_id)
    if not asset or not asset.get("is_digital"):
        asset = contract_service.get_asset(token_id)

    if not asset:
        raise HTTPException(status_code=404, detail="Token not found")

    is_digital = asset.get("is_digital", False)
    owner_address = asset.get("owner_address", "").lower()

    # AUDITOR cannot revoke anything
    if current_user.role == "AUDITOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Auditors have read-only access and cannot revoke assets."
        )

    # USER restrictions: can only revoke their OWN DIGITAL assets
    if current_user.role == "USER":
        if not is_digital:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Users cannot revoke PHYSICAL assets. Contact a Manager or Administrator."
            )
        if owner_address != current_user.wallet_address.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Users can only revoke their own digital assets."
            )

    # MANAGER restrictions: can only revoke PHYSICAL assets
    elif current_user.role == "MANAGER":
        if is_digital:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Managers are not permitted to revoke DIGITAL assets. Managers can only revoke PHYSICAL defense hardware. Digital assets can only be revoked by their owner or an Administrator."
            )
        await _managed_asset_or_403(db, current_user, token_id)

    # ADMIN: no restrictions (can revoke both types)

    # AI Risk Check: Block HIGH-risk actors from sensitive revoke operations
    from app.services.ai import check_actor_risk_level
    actor_did = f"did:ethr:13371:{current_user.wallet_address.lower()}"
    risk_check = await check_actor_risk_level(actor_did, db)

    if risk_check["is_high_risk"]:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(
            f"BLOCKED: Asset revoke attempt by {actor_did} on token {token_id} due to high risk pattern. "
            f"Reason: {risk_check['reason']}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation blocked due to anomalous behavior pattern detected by AI security system. {risk_check['reason']}. Contact your security administrator for review."
        )

    calldata = contract_service.prepare_revoke_calldata(token_id)
    return MintCalldataResponse(
        calldata=calldata,
        contract_address=contract_service.contract_address,
    )

@router.post("/mint/prepare", response_model=MintCalldataResponse)
async def prepare_mint(request: MintRequest, current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db), step_up_token: Optional[str] = Depends(get_step_up_token)):
    """Prepare unsigned mint transaction calldata for physical asset.

    Authorization Rules:
    - ADMIN, MANAGER: Permitted to mint physical assets
    - USER: Not permitted to mint physical assets (digital only)
    - AUDITOR: Read-only, cannot mint
    """
    if current_user.role in ("USER", "AUDITOR"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{current_user.role}' is not permitted to register physical defense hardware. Only Managers and Administrators can register physical assets."
        )

    record = (await db.execute(select(Asset).where(Asset.serial_number == request.serial_number))).scalar_one_or_none()
    if (not record or not record.is_physical or record.approval_status != "APPROVED" or record.token_id != request.token_id
            or not access.can_manage_asset(current_user, record)):
        raise HTTPException(status_code=409, detail="Only an approved physical asset (matching serial and reserved token ID) can be minted.")

    # Factor 3 Validation
    await mfa.require_factor(db, current_user, "asset.mint", totp_code=request.totp_code, step_up_token=step_up_token)

    calldata = contract_service.prepare_mint_calldata(
        request.to_address,
        request.token_id,
        request.serial_number,
        request.owner_did,
    )
    return MintCalldataResponse(
        calldata=calldata,
        contract_address=contract_service.contract_address,
    )

@router.post("/mint-digital/prepare", response_model=MintCalldataResponse)
async def prepare_mint_digital(request: DigitalMintRequest, current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db), step_up_token: Optional[str] = Depends(get_step_up_token)):
    """Prepare unsigned mint transaction calldata for digital asset with SHA-256 hash.

    Authorization Rules:
    - USER, MANAGER, ADMIN: Permitted to mint digital documents (self-sovereign document anchoring)
    - AUDITOR: Read-only, cannot mint
    """
    if current_user.role not in ("ADMIN", "MANAGER"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{current_user.role}' cannot mint. Documents are minted only after Manager/Admin approval."
        )
    # Minting must follow the approval workflow: only an APPROVED registry record, in scope,
    # with matching reserved token ID and hash, can receive mint calldata.
    record = (await db.execute(select(Asset).where(Asset.serial_number == request.serial_number))).scalar_one_or_none()
    if (not record or record.is_physical or record.approval_status != "APPROVED" or record.token_id != request.token_id
            or (record.file_hash or "") != request.file_hash or not access.can_manage_asset(current_user, record)):
        raise HTTPException(status_code=409, detail="Only an approved document (matching serial, reserved token ID and hash) can be minted.")

    # Factor 3 Validation
    await mfa.require_factor(db, current_user, "asset.mint", totp_code=request.totp_code, step_up_token=step_up_token)


    calldata = contract_service.prepare_mint_digital_calldata(
        request.to_address,
        request.token_id,
        request.serial_number,
        request.owner_did,
        request.file_hash,
        request.offchain_uri,
    )
    return MintCalldataResponse(
        calldata=calldata,
        contract_address=contract_service.contract_address,
    )


class UpdateDigitalAssetRequest(BaseModel):
    totp_code: Optional[str] = None
    token_id: int
    new_file_hash: str
    new_offchain_uri: str


@router.post("/update-digital/prepare", response_model=MintCalldataResponse)
async def prepare_update_digital(
    request: UpdateDigitalAssetRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Prepare unsigned updateDigitalAsset calldata - only for an APPROVED revision whose
    lineage root holds this token and whose hash matches."""
    if current_user.role == "AUDITOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Auditors have read-only access and cannot update digital assets."
        )
    root = (await db.execute(select(Asset).where(Asset.token_id == request.token_id))).scalar_one_or_none()
    revision = root and (await db.execute(select(Asset).where(
        Asset.root_asset_id == root.id, Asset.version_number > 1, Asset.file_hash == request.new_file_hash,
        Asset.approval_status == "APPROVED",
    ))).scalars().first()
    if not revision:
        raise HTTPException(status_code=409, detail="No approved revision with this hash exists for this token.")
    # Anchoring is signed by an approver wallet (ANCHOR_ROLE on-chain); holders cannot anchor.
    if current_user.role not in ("ADMIN", "MANAGER") or not access.can_manage_asset(current_user, root):
        raise HTTPException(status_code=403, detail="Only a Manager/Admin of this department can anchor a revision.")

    # Factor 3 Validation
    await mfa.require_factor(db, current_user, "document.modify", totp_code=request.totp_code, step_up_token=step_up_token)


    calldata = contract_service.prepare_update_digital_asset_calldata(
        request.token_id,
        request.new_file_hash,
        request.new_offchain_uri,
    )
    return MintCalldataResponse(
        calldata=calldata,
        contract_address=contract_service.contract_address,
    )


@router.post("/upload-document")
@limiter.limit("20/minute")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_onboarded_user),
):
    """
    Secure Off-chain File Storage & Cryptographic Hashing.
    The file is stored securely off-chain.
    Its SHA-256 cryptographic hash is calculated and returned to be anchored in the NFT smart contract.
    Enforces active user authentication and payload size limits.
    """
    if current_user.role == "AUDITOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Auditors have read-only access and cannot upload documents."
        )

    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    try:
        # Stream with a hard cap instead of reading an unbounded body into memory.
        chunks, size = [], 0
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="File size exceeds maximum permitted limit (50MB).")
            chunks.append(chunk)
        content = b"".join(chunks)
        if not content:
            raise HTTPException(status_code=400, detail="The file is empty.")

        # Only formats that can be served as a watermarked derivative are accepted; the
        # type is detected from the bytes (magic numbers / OOXML structure), not the name.
        from app.services.watermark import UnsupportedDocumentType, detect_type
        safe_original_name = os.path.basename((file.filename or "unnamed_document").replace("\\", "/"))[:200] or "unnamed_document"
        try:
            kind = detect_type(content, safe_original_name)
        except UnsupportedDocumentType as e:
            raise HTTPException(status_code=415, detail=f"Unsupported document type: {e}. Supported: PDF, DOCX, PPTX, XLSX, PNG/JPEG images, UTF-8 text.")

        sha256_hash = hashlib.sha256(content).hexdigest()
        filename = f"{sha256_hash}_{safe_original_name}"
        filepath = os.path.join(OFFCHAIN_STORAGE_DIR, filename)
        with open(filepath, "wb") as f:
            f.write(content)

        return {
            "filename": safe_original_name,
            "file_hash": sha256_hash,
            "offchain_uri": f"secure-vault://documents/{filename}",
            "file_size": len(content),
            "document_type": kind,
            "status": "SECURELY_STORED_OFFCHAIN",
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Document upload failed")
        raise HTTPException(status_code=500, detail="File processing failed.")


@router.post("/check-access")
async def check_access(
    request: AccessCheckRequest,
    current_user: User = Depends(get_onboarded_user),
):
    """Check the CALLER's on-chain access to a token. Requester identity comes from the
    session; client-supplied requester_did / caller_address are ignored."""
    requester_did = current_user.did or f"did:ethr:13371:{current_user.wallet_address.lower()}"
    result = contract_service.check_asset_access(request.token_id, requester_did, current_user.wallet_address)
    return {
        "token_id": request.token_id,
        "requester_did": requester_did,
        "authorized": result["authorized"],
        "permission_level": result["level"],
        "message": "Access Granted" if result["authorized"] else "Access Denied by Smart Contract"
    }


@router.get("/registry", response_model=List[AssetRead])
async def get_all_assets(
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
):
    """Registry filtered in the database by the caller's role and departments."""
    from sqlalchemy.orm import selectinload

    query = select(Asset).options(selectinload(Asset.owner), selectinload(Asset.custodian))
    clause = await access.asset_scope_clause(db, current_user)
    if clause is not None:
        query = query.where(clause)
    assets = (await db.execute(query.order_by(desc(Asset.created_at)))).scalars().all()
    return [AssetRead.model_validate(_asset_row(a, current_user)) for a in assets]


@router.get("/by-owner/{owner_address}", response_model=List[AssetRead])
async def get_assets_by_owner(
    owner_address: str,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
):
    """Assets owned by, in custody of, or granted to one identity - only if the caller
    may see that identity, and only the assets the caller may see."""
    from web3 import Web3
    from sqlalchemy.orm import selectinload

    try:
        clean_address = Web3.to_checksum_address(owner_address).lower()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid wallet address")
    target = (await db.execute(select(User).where(func.lower(User.wallet_address) == clean_address))).scalar_one_or_none()
    if not target or not access.can_see_user(current_user, target):
        raise HTTPException(status_code=403, detail="You are not authorized to view this identity's assets.")

    target_grants = await access.granted_serials(db, target)
    target_clause = or_(Asset.owner_id == target.id, Asset.custodian_id == target.id,
                        Asset.serial_number.in_(target_grants) if target_grants else false())
    query = select(Asset).options(selectinload(Asset.owner), selectinload(Asset.custodian)).where(target_clause)
    viewer_clause = await access.asset_scope_clause(db, current_user)
    if viewer_clause is not None:
        query = query.where(viewer_clause)
    assets = (await db.execute(query)).scalars().unique().all()
    return [AssetRead.model_validate(_asset_row(a, current_user)) for a in assets]


@router.get("/serial/{serial}")
async def get_asset_by_serial(serial: str, current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    """On-chain metadata for a registry asset the caller may see."""
    asset = await _visible_asset_or_404(db, current_user, serial=serial)
    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None:
        raise HTTPException(status_code=404, detail="Serial not found on chain")
    on_chain = contract_service.get_digital_asset(token_id)
    if not on_chain or not on_chain.get("is_digital"):
        on_chain = contract_service.get_asset(token_id)
    if not on_chain:
        raise HTTPException(status_code=404, detail="Asset metadata not found")
    return on_chain


import socket

def get_lan_ip() -> str:
    """Detect the host machine's local area network (LAN) IPv4 address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        # Connect to a dummy public IP to resolve local interface IP (no data sent)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


@router.get("/serial/{serial}/qr")
async def get_asset_qr(serial: str, host: Optional[str] = "localhost:5173", current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    """Generate and return a QR code PNG pointing to the frontend verify URL for this asset.
    Automatically resolves localhost/127.0.0.1 to the LAN IP so mobile devices can scan and view it.
    """
    await _visible_asset_or_404(db, current_user, serial=serial)
    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None:
        raise HTTPException(status_code=404, detail="Asset with this serial not found on chain")

    # Replace localhost or 127.0.0.1 with actual LAN IP if present
    target_host = host
    if target_host:
        lan_ip = get_lan_ip()
        if "localhost" in target_host:
            target_host = target_host.replace("localhost", lan_ip)
        elif "127.0.0.1" in target_host:
            target_host = target_host.replace("127.0.0.1", lan_ip)

    verify_url = f"http://{target_host}/verify/{serial}"
    png_bytes = generate_qr_for_url(verify_url)

    return Response(content=png_bytes, media_type="image/png")


@router.get("/token/{token_id}/qr")
async def get_asset_qr_by_token(token_id: int, host: Optional[str] = "localhost:5173", current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    """Generate a QR code for the stable token-ID verification URL."""
    await _visible_asset_or_404(db, current_user, token_id=token_id)
    asset = contract_service.get_digital_asset(token_id) or contract_service.get_asset(token_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found on chain")
    target_host = host or "localhost:5173"
    lan_ip = get_lan_ip()
    target_host = target_host.replace("localhost", lan_ip).replace("127.0.0.1", lan_ip)
    png_bytes = generate_qr_for_url(f"http://{target_host}/verify/token/{token_id}")
    return Response(content=png_bytes, media_type="image/png")


class AssignCustodianRequest(BaseModel):
    custodian_did: str
    custodian_department: Optional[str] = None
    lifecycle_status: Optional[str] = "ASSIGNED"


class MaintenanceRecordRequest(BaseModel):
    performed_by_did: str
    action_description: str
    notes: Optional[str] = None
    log_hash: Optional[str] = None
    tx_hash: Optional[str] = None


@router.get("/serial/{serial}/card")
async def get_asset_certificate_card(
    serial: str,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
):
    """Printable physical NFT/QR card: Serial, Token ID, Creation Date, Department, QR only."""
    asset = await _visible_asset_or_404(db, current_user, serial=serial)
    if not asset.is_physical:
        raise HTTPException(status_code=400, detail="Cards are issued for physical assets only.")
    if asset.approval_status not in ("APPROVED", "ACTIVE"):
        raise HTTPException(status_code=409, detail="A card is issued only after the asset is approved.")
    svg = generate_physical_card_svg(
        serial_number=asset.serial_number,
        token_id=asset.token_id,
        creation_date=asset.created_at.strftime("%d %b %Y") if asset.created_at else "",
        department=asset.department or "",
        verify_url=_public_url(f"/verify/token/{asset.token_id}"),
    )
    return Response(content=svg, media_type="image/svg+xml")


@router.post("/serial/{serial}/assign")
async def assign_asset_custodian(
    serial: str,
    req: AssignCustodianRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
):
    """Assign an asset to a custodian division/engineer (ADMIN and MANAGER only)."""
    if current_user.role not in ("ADMIN", "MANAGER"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{current_user.role}' is not authorized to reassign asset custody. Manager or Admin privileges required."
        )

    # Department scoping: Managers can only assign custody within/to their own department
    if current_user.role == "MANAGER":
        if not current_user.department:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Manager has no assigned department and cannot reassign asset custody."
            )
        if req.custodian_department and req.custodian_department not in access.manager_departments(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Managers can only assign custody within their authorized departments."
            )

    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None:
        raise HTTPException(status_code=404, detail="Asset not found on chain")

    res = await db.execute(select(Asset).filter(Asset.serial_number == serial))
    asset_db = res.scalar_one_or_none()

    if not asset_db:
        # Never fabricate a registry record (previously created one owned by the caller).
        raise HTTPException(status_code=404, detail="Asset is not in the LexCorp registry.")
    if not access.can_manage_asset(current_user, asset_db):
        raise HTTPException(status_code=403, detail="Managers can only reassign custody of assets in their authorized departments.")
    previous = {"custodian_did": asset_db.custodian_did, "custodian_department": asset_db.custodian_department}
    asset_db.custodian_did = req.custodian_did
    asset_db.custodian_department = req.custodian_department
    asset_db.lifecycle_status = req.lifecycle_status or "ASSIGNED"
    await record_audit(db, "ASSET_CUSTODIAN_CHANGED", actor_did=current_user.did, target_did=req.custodian_did,
                       asset_serial=serial, details={"previous": previous, "custodian_department": req.custodian_department})

    await db.commit()
    await db.refresh(asset_db)

    # Invalidate cache
    _CACHE.pop("registry", None)

    return {
        "serial_number": serial,
        "custodian_did": asset_db.custodian_did,
        "custodian_department": asset_db.custodian_department,
        "lifecycle_status": asset_db.lifecycle_status
    }


@router.post("/serial/{serial}/maintenance")
async def record_asset_maintenance(
    serial: str,
    req: MaintenanceRecordRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
):
    """Record a field maintenance / calibration / inspection log for an asset."""
    if current_user.role == "AUDITOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Auditors have read-only access and cannot submit maintenance records."
        )

    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None:
        raise HTTPException(status_code=404, detail="Asset not found on chain")

    # Derive performer DID strictly from the authenticated session
    performed_by_did = current_user.did or f"did:ethr:13371:{current_user.wallet_address.lower()}"

    # Verify authorization: ADMIN any asset, MANAGER within departments, USER must be owner or granted on-chain access
    if current_user.role == "MANAGER":
        asset_scope = (await db.execute(select(Asset).filter(Asset.serial_number == serial))).scalar_one_or_none()
        if not asset_scope or not access.can_manage_asset(current_user, asset_scope):
            raise HTTPException(status_code=403, detail="This asset is outside your authorized departments.")
    elif current_user.role != "ADMIN":
        chain_access = contract_service.check_asset_access(
            token_id=token_id,
            requester_did=performed_by_did,
            caller_address=current_user.wallet_address
        )
        if not chain_access.get("authorized"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have authorization to record maintenance on this asset."
            )

    # Compute hash of maintenance notes if not provided
    log_hash = req.log_hash
    if not log_hash:
        raw = f"{serial}:{performed_by_did}:{req.action_description}:{time.time()}"
        log_hash = hashlib.sha256(raw.encode()).hexdigest()

    record = MaintenanceRecord(
        asset_serial=serial,
        performed_by_did=performed_by_did,
        action_description=req.action_description,
        notes=req.notes,
        log_hash=log_hash,
        tx_hash=req.tx_hash
    )
    db.add(record)

    # Update asset lifecycle status to MAINTENANCE or VERIFIED
    res = await db.execute(select(Asset).filter(Asset.serial_number == serial))
    asset_db = res.scalar_one_or_none()
    if asset_db:
        asset_db.lifecycle_status = "MAINTENANCE"
    await record_audit(db, "ASSET_MAINTENANCE_RECORDED", actor_did=performed_by_did, asset_serial=serial,
                       details={"log_hash": log_hash, "action": req.action_description[:200]})

    await db.commit()
    await db.refresh(record)

    return {
        "id": str(record.id),
        "asset_serial": serial,
        "performed_by_did": record.performed_by_did,
        "action_description": record.action_description,
        "log_hash": record.log_hash,
        "created_at": record.created_at.isoformat() if record.created_at else None
    }


@router.get("/serial/{serial}/maintenance")
async def get_asset_maintenance_history(
    serial: str,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve full chronological maintenance logs for an asset the caller may see."""
    await _visible_asset_or_404(db, current_user, serial=serial)
    res = await db.execute(
        select(MaintenanceRecord)
        .filter(MaintenanceRecord.asset_serial == serial)
        .order_by(desc(MaintenanceRecord.created_at))
    )
    records = res.scalars().all()
    return [
        {
            "id": str(r.id),
            "asset_serial": r.asset_serial,
            "performed_by_did": r.performed_by_did,
            "action_description": r.action_description,
            "notes": r.notes,
            "log_hash": r.log_hash,
            "tx_hash": r.tx_hash,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in records
    ]


@router.get("/serial/{serial}/verify-data")
async def get_asset_full_verification_data(
    serial: str,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db)
):
    """QR verification payload. Anyone scanning a QR gets only public fields; signed-in
    employees get the details their role and departments allow."""
    asset_db = (await db.execute(select(Asset).filter(Asset.serial_number == serial))).scalar_one_or_none()
    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None and not asset_db:
        raise HTTPException(status_code=404, detail="Asset not found")

    on_chain = None
    if token_id is not None:
        on_chain = contract_service.get_digital_asset(token_id)
        if not on_chain or not on_chain.get("is_digital"):
            on_chain = contract_service.get_asset(token_id)

    public = {
        "serial_number": serial,
        "token_id": token_id,
        "on_chain_verified": token_id is not None,
        "chain_id": settings.CHAIN_ID,
        "is_digital": bool(on_chain.get("is_digital")) if on_chain else (not asset_db.is_physical if asset_db else False),
        "department": asset_db.department if asset_db else None,
        "lifecycle_status": asset_db.lifecycle_status if asset_db else None,
        "approval_status": asset_db.approval_status if asset_db else None,
        "created_at": asset_db.created_at.isoformat() if asset_db and asset_db.created_at else None,
        "detail_level": "PUBLIC",
    }
    authorized = bool(current_user and asset_db and await access.can_see_asset(db, current_user, asset_db))
    if asset_db and asset_db.is_physical:
        await record_audit(db, "ASSET_VERIFIED", actor_did=current_user.did if current_user else None, asset_serial=serial,
                           details={"detail_level": "AUTHORIZED" if authorized else "PUBLIC"})
        await db.commit()
    if not authorized:
        return public

    maint = (await db.execute(
        select(MaintenanceRecord).filter(MaintenanceRecord.asset_serial == serial).order_by(desc(MaintenanceRecord.created_at))
    )).scalars().all()
    detail = {
        **public,
        "detail_level": "AUTHORIZED",
        "contract_address": contract_service.contract_address,
        "name": asset_db.name,
        "asset_type": asset_db.asset_type,
        "owner_address": on_chain.get("owner_address") if on_chain else None,
        "owner_did": on_chain.get("owner_did") if on_chain else None,
        "custodian_did": asset_db.custodian_did,
        "custodian_department": asset_db.custodian_department,
        "file_hash": (on_chain.get("file_hash") if on_chain else None) or asset_db.file_hash,
        "offchain_uri": on_chain.get("offchain_uri") if on_chain else None,
        "action_id": asset_db.action_id,
        "maintenance_history": [{
            "id": str(r.id), "performed_by_did": r.performed_by_did, "action_description": r.action_description,
            "notes": r.notes, "log_hash": r.log_hash, "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in maint],
    }
    if access.can_see_sensitive_physical(current_user, asset_db):
        detail["mac_address"] = asset_db.mac_address
        detail["device_unique_address"] = asset_db.device_unique_address
        detail["location"] = asset_db.location
    if asset_db.is_physical:
        creation = (await db.execute(select(DocumentAction).where(DocumentAction.action_id == asset_db.action_id))).scalar_one_or_none() if asset_db.action_id else None
        detail["creation_id"] = asset_db.action_id
        detail["approval"] = {"proposed_by": creation.actor_did, "approved_by": creation.approver_did,
                              "status": creation.status} if creation else None
        lifecycle_types = ("PHYSICAL_ASSET_CREATED", "PHYSICAL_ASSET_APPROVED", "PHYSICAL_ASSET_MINTED", "ASSET_TRANSFERRED",
                           "AssetTransferred", "ASSET_CUSTODIAN_CHANGED", "ASSET_STATUS_CHANGED", "ASSET_MAINTENANCE_RECORDED")
        events = (await db.execute(select(AuditEvent).where(AuditEvent.asset_serial == serial, AuditEvent.event_type.in_(lifecycle_types))
                                   .order_by(AuditEvent.created_at))).scalars().all()
        detail["lifecycle"] = [{"event": e.event_type, "at": e.created_at.isoformat() if e.created_at else None,
                                "actor_did": e.actor_did, "tx_hash": e.tx_hash if e.block_number else None} for e in events]
    return detail


@router.get("/token/{token_id}/verify-data")
async def get_asset_full_verification_data_by_token(
    token_id: int,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """Resolve verification by stable token ID instead of a serial string."""
    asset_db = (await db.execute(select(Asset).where(Asset.token_id == token_id))).scalar_one_or_none()
    serial = asset_db.serial_number if asset_db else None
    if serial is None:
        on_chain = contract_service.get_digital_asset(token_id)
        if not on_chain or not on_chain.get("is_digital"):
            on_chain = contract_service.get_asset(token_id)
        if not on_chain:
            raise HTTPException(status_code=404, detail="Asset not found")
        serial = on_chain["serial_number"]
    return await get_asset_full_verification_data(serial, current_user, db)


@router.delete("/{token_id}", status_code=status.HTTP_200_OK)
async def delete_asset(
    token_id: int,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
):
    """Prepare revoke (burn) calldata. ADMIN, or MANAGER within their departments."""
    if current_user.role not in ("ADMIN", "MANAGER"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only Managers and Administrators can revoke assets.")
    await _managed_asset_or_403(db, current_user, token_id)
    if not contract_service.get_asset(token_id):
        raise HTTPException(status_code=404, detail="Token not found on chain")
    calldata = contract_service.prepare_revoke_calldata(token_id)
    return {"message": "Prepare revocation calldata", "calldata": calldata, "token_id": token_id}


async def _resolve_recipient(db: AsyncSession, recipient_address: Optional[str], recipient_did: Optional[str]) -> Optional[User]:
    """The identity an asset is created for must be a registered, active LexCorp2 identity,
    so the registry owner, the on-chain token holder and the on-chain owner DID agree."""
    target = None
    if recipient_did:
        target = (await db.execute(select(User).where(User.did == recipient_did.strip()))).scalar_one_or_none()
    if target is None and recipient_address:
        target = (await db.execute(select(User).where(func.lower(User.wallet_address) == recipient_address.strip().lower()))).scalar_one_or_none()
    if (recipient_did or recipient_address) and (target is None or not target.is_active or target.revoked_at is not None):
        raise HTTPException(status_code=400, detail="The recipient must be a registered, active LexCorp2 identity.")
    if target is not None and recipient_address and target.wallet_address.lower() != recipient_address.strip().lower():
        raise HTTPException(status_code=400, detail="Recipient DID and wallet address belong to different identities.")
    return target


@router.post("/document/propose", response_model=DocumentActionRead)
async def propose_document_creation(
    request: DocumentProposalRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Propose a new digital document for creation and approval."""
    if current_user.role == "AUDITOR":
        raise HTTPException(status_code=403, detail="Auditors cannot propose documents.")
    # Admins/Managers may submit too; separation of duties means someone else must approve.

    dept = request.department or current_user.department
    if current_user.role in ["USER", "AUDITOR"] and dept != current_user.department:
        raise HTTPException(status_code=403, detail="Users can only propose documents for their assigned department.")


    await mfa.require_factor(db, current_user, "document.submit", totp_code=request.totp_code, step_up_token=step_up_token)
    await _resolve_recipient(db, request.recipient_address, request.recipient_did)

    # Creation integrity: the SHA-256 recorded (and later minted) must be the hash of the
    # bytes actually in the vault, computed here - never taken on trust from the client.
    try:
        stored_bytes = _read_vault_file(Asset(metadata_cid=request.offchain_uri))
    except HTTPException:
        raise HTTPException(status_code=400, detail="The referenced document is not in the vault. Upload it first.")
    if hashlib.sha256(stored_bytes).hexdigest() != request.file_hash.strip().lower():
        raise HTTPException(status_code=400, detail="file_hash does not match the stored document (server-computed SHA-256).")

    res = await db.execute(select(Asset).filter(Asset.serial_number == request.serial_number))
    if res.scalar_one_or_none():
         raise HTTPException(status_code=400, detail="Asset serial number already exists.")

    action_id_str = await next_action_id(db, "CRT")
    # Token ID reserved from a DB sequence; the NFT is minted with it after approval.
    reserved_token_id = await next_token_id(db)

    draft_asset = Asset(
        token_id=reserved_token_id,
        version_number=1,
        serial_number=request.serial_number,
        name=request.name,
        asset_type="DOCUMENT",
        file_hash=request.file_hash,
        metadata_cid=request.offchain_uri,
        owner_id=current_user.id,
        department=dept,
        is_physical=False,
        lifecycle_status="CREATED",
        approval_status="PENDING_APPROVAL",
        action_id=action_id_str,
        action_type="CREATION"
    )
    db.add(draft_asset)
    await db.flush()
    draft_asset.root_asset_id = draft_asset.id

    action = DocumentAction(
        action_id=action_id_str,
        action_type="CREATION",
        asset_id=draft_asset.id,
        asset_version=1,
        client_ip=client_ip,
        asset_serial=request.serial_number,
        actor_id=current_user.id,
        actor_did=current_user.did,
        status="PENDING",
        purpose=request.purpose,
        details={
            "name": request.name,
            "file_hash": request.file_hash,
            "offchain_uri": request.offchain_uri,
            "recipient_address": request.recipient_address,
            "recipient_did": request.recipient_did
        }
    )
    db.add(action)

    audit_event = AuditEvent(
        event_type="DocumentProposed",
        tx_hash=f"audit_prop_doc_{uuid.uuid4().hex[:12]}",
        block_number=0,
        actor_did=current_user.did,
        target_did=request.recipient_did,
        asset_serial=request.serial_number,
        client_ip=client_ip,
        risk_score=0.1,
        risk_label="LOW",
        risk_factors={"reason": "Document Proposal Submitted", "action_id": action_id_str}
    )
    db.add(audit_event)

    await db.commit()
    await db.refresh(action)
    return action




async def _lineage_assets(db, asset) -> list:
    root_id = asset.root_asset_id or asset.id
    rows = await db.execute(select(Asset).where(or_(Asset.root_asset_id == root_id, Asset.id == root_id)))
    return list(rows.scalars().all())


async def _grant_share(db, action, asset, approver, max_views, allow_download, expires_at, client_ip):
    """Create the delegated-access grant for a SHARE action (approved, or granted directly by a
    Manager/Admin). Returns optional on-chain calldata mirroring the grant."""
    details = action.details or {}
    target_did = details.get("target_did")
    level = details.get("access_level", 1)
    if not target_did:
        raise HTTPException(status_code=400, detail="Access request has no target identity.")
    serials = details.get("version_serials") or [asset.serial_number]
    versions = (await db.execute(select(Asset).where(Asset.serial_number.in_(serials)))).scalars().all()
    for version in versions:  # one grant per shared version, same limits
        db.add(AssetAccessGrant(
            asset_id=version.id, asset_serial=version.serial_number, grantee_did=target_did,
            granted_by_did=approver.did, requested_by_did=action.actor_did, request_action_id=action.action_id,
            access_level=level, can_view=True, can_download=bool(allow_download), max_views=max_views,
            views_count=0, expires_at=expires_at, is_active=True,
        ))
    details = dict(details)
    details.update({"approved_max_views": max_views, "approved_until": expires_at.isoformat() if expires_at else None,
                    "approved_download": bool(allow_download)})
    action.details = details
    await record_audit(
        db, "ACCESS_GRANTED", actor_did=approver.did, target_did=target_did, asset_serial=asset.serial_number,
        client_ip=client_ip,
        details={"request_action_id": action.action_id, "requested_by": action.actor_did,
                 "max_views": max_views, "expires_at": expires_at.isoformat() if expires_at else None,
                 "can_download": bool(allow_download), "asset_version": asset.version_number,
                 "versions": sorted(v.version_number or 1 for v in versions)},
    )
    token_id = contract_service.get_token_by_serial(asset.serial_number) or asset.token_id
    try:
        return contract_service.prepare_grant_access_calldata(token_id=token_id, target_did=target_did, level=level)
    except Exception:
        return None  # DB grant is authoritative for view counts/expiry; on-chain mirror is optional


def _privileged_for(user, asset) -> bool:
    """Managers/Administrators acting within their scope need no approver."""
    return user.role in ("ADMIN", "MANAGER") and access.can_manage_asset(user, asset)


@router.post("/document/share/propose", response_model=DocumentActionRead)
async def propose_document_share(
    request: ShareProposalRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Delegate access to a document. A normal user's request waits for a Manager/Admin
    (Factor 2 to submit); a Manager/Admin in scope grants it directly with their final limits
    (Factor 3, as for any approval)."""
    res = await db.execute(select(Asset).filter(Asset.serial_number == request.asset_serial))
    asset = res.scalar_one_or_none()
    direct = asset is not None and _privileged_for(current_user, asset)
    await mfa.require_factor(db, current_user, "asset.approve" if direct else "access.request",
                             totp_code=request.totp_code, step_up_token=step_up_token)
    # Only the owner/custodian, or a Manager/Admin with scope, may request access for someone
    # else. Grantees cannot re-share. Nothing is granted until a Manager/Admin approves.
    is_holder = asset is not None and (asset.owner_id == current_user.id or asset.custodian_id == current_user.id)
    if not asset or not (is_holder or access.can_manage_asset(current_user, asset)):
        raise HTTPException(status_code=404, detail="Asset not found.")
    if asset.is_physical:
        raise HTTPException(status_code=400, detail="Delegated document access applies to digital assets only.")
    if asset.approval_status in ("PENDING_APPROVAL", "REJECTED"):
        raise HTTPException(status_code=409, detail="Access can only be requested for an approved document.")
    target = (await db.execute(select(User).where(User.did == request.target_did))).scalar_one_or_none()
    if not target or not target.is_active or target.revoked_at is not None:
        raise HTTPException(status_code=400, detail="Target identity is not an active LexCorp user.")
    if target.id == current_user.id or target.id == asset.owner_id:
        raise HTTPException(status_code=400, detail="The target already holds this document.")
    version_serials = [asset.serial_number]
    if request.version_serials:
        lineage = await _lineage_assets(db, asset)
        allowed = {a.serial_number: a for a in lineage if a.approval_status in ("APPROVED", "ACTIVE")}
        unknown = [v for v in request.version_serials if v not in allowed]
        if unknown:
            raise HTTPException(status_code=400, detail=f"Not an approved version of this document: {', '.join(unknown)}")
        version_serials = sorted(set(request.version_serials), key=lambda v: allowed[v].version_number or 1)

    action_id_str = await next_action_id(db, "ACR")

    action = DocumentAction(
        action_id=action_id_str,
        action_type="SHARE",
        asset_id=asset.id,
        asset_version=asset.version_number,
        client_ip=client_ip,
        asset_serial=request.asset_serial,
        actor_id=current_user.id,
        actor_did=current_user.did,
        status="PENDING",
        purpose=request.purpose,
        details={
            "target_did": request.target_did,
            "access_level": request.access_level,
            "asset_serial": request.asset_serial,
            "requested_max_views": request.max_views,
            "request_download": request.request_download,
            "version_serials": version_serials,
        }
    )
    db.add(action)
    if direct:
        until = request.accessible_until
        if until is not None and (until.tzinfo is None or until <= datetime.now(UTC)):
            raise HTTPException(status_code=400, detail="Accessible until must be a future time with a timezone.")
        action.status = "APPROVED"
        action.approver_id = current_user.id
        action.approver_did = current_user.did
        action.details = {**action.details, "granted_directly": True}
        await _grant_share(db, action, asset, current_user, request.max_views, bool(request.request_download), until, client_ip)

    audit_event = AuditEvent(
        event_type="AssetShareProposed",
        tx_hash=f"audit_share_prop_{uuid.uuid4().hex[:12]}",
        block_number=0,
        actor_did=current_user.did,
        target_did=request.target_did,
        asset_serial=request.asset_serial,
        client_ip=client_ip,
        risk_score=0.1,
        risk_label="LOW",
        risk_factors={"action_id": action_id_str, "target_did": request.target_did, "access_level": request.access_level}
    )
    db.add(audit_event)

    await db.commit()
    await db.refresh(action)
    return action



PHYSICAL_ASSET_TYPES = {"EQUIPMENT", "SENSOR", "COMMUNICATION", "COMPUTE", "VEHICLE", "OTHER"}


def _physical_asset_type(asset_type: Optional[str], other: Optional[str]) -> str:
    """A known type, or for OTHER the person's own description, stored as "OTHER: <description>"."""
    t = (asset_type or "EQUIPMENT").strip().upper()
    if t not in PHYSICAL_ASSET_TYPES:
        raise HTTPException(status_code=400, detail="Unknown asset type.")
    if t != "OTHER":
        return t
    text = " ".join((other or "").split())
    if not 2 <= len(text) <= 40 or any(not (ch.isprintable()) for ch in text):
        raise HTTPException(status_code=400, detail="For asset type Other, describe what the asset is (2 to 40 characters).")
    return f"OTHER: {text}"


@router.post("/physical/propose", response_model=DocumentActionRead)
async def propose_physical_asset_creation(
    request: PhysicalProposalRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Propose a new physical asset for creation and approval."""
    if current_user.role == "AUDITOR":
        raise HTTPException(status_code=403, detail="Auditors cannot propose assets.")
    if current_user.role not in ["ADMIN", "MANAGER"]:
        raise HTTPException(status_code=403, detail="Only Managers and Administrators can propose physical assets.")

    asset_type = _physical_asset_type(request.asset_type, request.asset_type_other)
    dept = request.department or current_user.department
    if current_user.role == "MANAGER" and dept not in access.manager_departments(current_user):
        raise HTTPException(status_code=403, detail="Managers can only propose physical assets for their assigned department.")
    await access.require_assignable_department(db, current_user, dept)


    await mfa.require_factor(db, current_user, "document.submit", totp_code=request.totp_code, step_up_token=step_up_token)
    await _resolve_recipient(db, request.recipient_address, request.recipient_did)

    # Serial + (MAC OR Unique Address), normalised, globally unique across the registry.
    serial = phys.normalize_serial(request.serial_number)
    mac, unique_address = phys.resolve_identifiers(request.has_mac_address, request.mac_address, request.device_unique_address)

    async def _reject_duplicate(field: str):
        event, message = phys.DUPLICATE_EVENTS[field]
        value = {"serial": serial, "mac": mac, "unique_address": unique_address}[field]
        details = {"duplicate_field": field, "value_fingerprint": phys.fingerprint(value or ""), "department": dept}
        # Serials are printed on the public card; MAC / unique address values are never logged.
        # Generic category row for audit filters; the specific event below raises the (single) alert.
        await record_audit(db, "DUPLICATE_PHYSICAL_ASSET_ATTEMPT", actor_did=current_user.did, asset_serial=serial,
                           client_ip=client_ip, details={**details, "specific_event": event})
        await record_audit(db, event, actor_did=current_user.did, asset_serial=serial,
                           client_ip=client_ip, risk_label="HIGH", risk_score=0.85, details=details)
        await db.commit()
        raise HTTPException(status_code=400, detail=message)

    duplicate = await phys.find_duplicate(db, serial, mac, unique_address)
    if duplicate:
        await _reject_duplicate(duplicate)

    action_id_str = await next_action_id(db, "CRT")
    reserved_token_id = await next_token_id(db)

    draft_asset = Asset(
        token_id=reserved_token_id,
        version_number=1,
        serial_number=serial,
        name=request.name,
        asset_type=asset_type,
        is_physical=True,
        mac_address=mac,
        device_unique_address=unique_address,
        location=request.location,
        department=dept,
        owner_id=current_user.id,
        lifecycle_status="CREATED",
        approval_status="PENDING_APPROVAL",
        action_id=action_id_str,
        action_type="CREATION"
    )
    db.add(draft_asset)
    try:
        await db.flush()  # the database's normalised unique indexes are the final arbiter (races)
    except IntegrityError:
        await db.rollback()
        duplicate = await phys.find_duplicate(db, serial, mac, unique_address) or "serial"
        await _reject_duplicate(duplicate)
    draft_asset.root_asset_id = draft_asset.id

    action = DocumentAction(
        action_id=action_id_str,
        action_type="CREATION",
        asset_id=draft_asset.id,
        asset_version=1,
        client_ip=client_ip,
        asset_serial=serial,
        actor_id=current_user.id,
        actor_did=current_user.did,
        status="PENDING",
        purpose=request.purpose,
        details={
            "name": request.name,
            "asset_type": asset_type,
            "is_physical": True,
            "identifier_kind": "MAC" if mac else "UNIQUE_ADDRESS",
            "location": request.location,
            "department": dept,
            "recipient_address": request.recipient_address,
            "recipient_did": request.recipient_did
        }
    )
    db.add(action)

    risk = ai_score("PHYSICAL_ASSET_CREATED", current_user, sensitivity=2)
    await record_audit(db, "PHYSICAL_ASSET_CREATED", actor_did=current_user.did, asset_serial=serial, client_ip=client_ip,
                       risk_label=risk.get("risk_label"), risk_score=risk.get("risk_score"),
                       details={"creation_id": action_id_str, "department": dept, "token_id": reserved_token_id,
                                **({"ai": risk["ai"]} if risk else {})})
    audit_event = AuditEvent(
        event_type="PhysicalAssetProposed",
        tx_hash=f"audit_prop_phys_{uuid.uuid4().hex[:12]}",
        block_number=0,
        actor_did=current_user.did,
        target_did=request.recipient_did,
        asset_serial=serial,
        client_ip=client_ip,
        risk_score=0.1,
        risk_label="LOW",
        risk_factors={"reason": "Physical Hardware Proposal Submitted", "action_id": action_id_str}
    )
    db.add(audit_event)

    await db.commit()
    await db.refresh(action)
    return action


@router.get("/document/pending", response_model=list[DocumentActionRead])
async def get_pending_documents(
    action_type: Optional[str] = None,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve pending document actions awaiting approval."""
    query = select(DocumentAction).filter(DocumentAction.status == "PENDING")
    if action_type:
        query = query.filter(DocumentAction.action_type == action_type)

    if current_user.role == "USER":
        query = query.filter(DocumentAction.actor_id == current_user.id)
    elif current_user.role == "MANAGER":
        query = query.join(Asset, DocumentAction.asset_id == Asset.id).filter(Asset.department.in_(access.manager_departments(current_user)))

    result = await db.execute(query.order_by(desc(DocumentAction.created_at)))
    return result.scalars().all()


@router.get("/physical/pending", response_model=list[DocumentActionRead])
async def get_pending_physical_assets(
    action_type: Optional[str] = None,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve pending physical asset actions awaiting approval."""
    query = select(DocumentAction).join(Asset, DocumentAction.asset_id == Asset.id).filter(
        DocumentAction.status == "PENDING",
        Asset.is_physical == True
    )
    if action_type:
        query = query.filter(DocumentAction.action_type == action_type)

    if current_user.role == "USER":
        query = query.filter(DocumentAction.actor_id == current_user.id)
    elif current_user.role == "MANAGER":
        query = query.filter(Asset.department.in_(access.manager_departments(current_user)))

    result = await db.execute(query.order_by(desc(DocumentAction.created_at)))
    return result.scalars().all()


class ApprovalCalldataResponse(BaseModel):
    calldata: Optional[dict] = None
    contract_address: Optional[str] = None
    decision: str
    status: str
    download_token: Optional[str] = None
    download_url: Optional[str] = None
    token_expires_at: Optional[datetime] = None

@router.post("/document/approval/{action_id}", response_model=ApprovalCalldataResponse)
@router.post("/physical/approval/{action_id}", response_model=ApprovalCalldataResponse)
async def approve_document(
    action_id: str,
    request: DocumentApprovalRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Approve or reject a pending document action."""
    if current_user.role not in ["ADMIN", "MANAGER"]:
        raise HTTPException(status_code=403, detail="Only Managers and Admins can approve documents.")

    res = await db.execute(select(DocumentAction).filter(DocumentAction.action_id == action_id))
    action = res.scalar_one_or_none()

    if not action or action.status != "PENDING":
        raise HTTPException(status_code=404, detail="Action not found or no longer pending.")

    asset_res = await db.execute(select(Asset).filter(Asset.id == action.asset_id))
    asset = asset_res.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Associated asset not found.")

    if not access.can_manage_asset(current_user, asset):
        raise HTTPException(status_code=403, detail="Managers can only approve actions for their own department.")
    # Managers and Administrators decide on their own submissions too (only they can reach this
    # endpoint); a normal user's request always needs a Manager or Administrator. Downloads of a
    # document someone else owns still need that owner's consent first (checked below).

    await mfa.require_factor(db, current_user, "asset.approve", totp_code=request.totp_code, step_up_token=step_up_token)

    if action.action_type == "MODIFICATION" and request.decision.upper() == "APPROVE":
        from app.models.domain import SecurityAlert
        from app.services.alerts import OPEN_STATES
        open_alert = (await db.execute(select(SecurityAlert).where(
            SecurityAlert.related_action_id == action.action_id, SecurityAlert.state.in_(OPEN_STATES)))).scalars().first()
        if open_alert is not None:
            raise HTTPException(status_code=409, detail=f"This revision is under security review ({open_alert.alert_id}). "
                                                        "It can be approved once that alert is closed.")

    # Only creation/modification decisions change the document's own approval state;
    # approving a share or download request must never mark the document approved.
    changes_asset_state = action.action_type in ("CREATION", "MODIFICATION")

    if request.decision.upper() == "APPROVE" and action.action_type == "SHARE" and request.accessible_until is not None:
        # Validate approver-supplied limits before anything is mutated.
        if request.accessible_until.tzinfo is None:
            raise HTTPException(status_code=400, detail="accessible_until must include a timezone (e.g. 2026-10-01T18:00:00+05:30).")
        if request.accessible_until <= datetime.now(UTC):
            raise HTTPException(status_code=400, detail="accessible_until must be in the future.")

    if request.decision.upper() == "APPROVE" and action.action_type == "DOWNLOAD":
        d = action.details or {}
        if d.get("requires_owner_approval") and not d.get("owner_approved_by"):
            raise HTTPException(status_code=409, detail="The document owner has not approved this download yet.")

    if request.decision.upper() == "APPROVE":
        action.status = "APPROVED"
        action.approver_id = current_user.id
        action.approver_did = current_user.did
        if changes_asset_state:
            asset.approval_status = "APPROVED"
        elif asset.approval_status in ("PENDING_APPROVAL", "REJECTED"):
            raise HTTPException(status_code=409, detail="The document itself is not approved; access to it cannot be granted.")

        calldata = None
        download_token = None
        download_url = None
        token_expires_at = None

        if action.action_type == "CREATION":
            details = action.details or {}
            recipient = await _resolve_recipient(db, details.get("recipient_address"), details.get("recipient_did"))
            if recipient is None:
                recipient = (await db.execute(select(User).where(User.id == action.actor_id))).scalar_one()
            asset.owner_id = recipient.id
            owner_address = recipient.wallet_address
            owner_did = recipient.did

            if asset.is_physical:
                await record_audit(db, "PHYSICAL_ASSET_APPROVED", actor_did=current_user.did, target_did=action.actor_did,
                                   asset_serial=asset.serial_number, client_ip=client_ip,
                                   details={"creation_id": action.action_id, "token_id": asset.token_id})
                calldata = contract_service.prepare_mint_calldata(
                    to_address=owner_address,
                    token_id=asset.token_id,
                    serial_number=asset.serial_number,
                    owner_did=owner_did
                )
            else:
                calldata = contract_service.prepare_mint_digital_calldata(
                    to_address=owner_address,
                    token_id=asset.token_id,
                    serial_number=asset.serial_number,
                    owner_did=owner_did,
                    file_hash=asset.file_hash or "",
                    offchain_uri=asset.metadata_cid or ""
                )
        elif action.action_type == "MODIFICATION":
            asset.lifecycle_status = "CREATED"
            if asset.parent_asset_id:
                parent_res = await db.execute(select(Asset).filter(Asset.id == asset.parent_asset_id))
                parent_asset = parent_res.scalar_one_or_none()
                if parent_asset:
                    parent_asset.lifecycle_status = "OBSOLETE"

            root = (await db.execute(select(Asset).where(Asset.id == (asset.root_asset_id or asset.id)))).scalar_one_or_none()
            if root is None or root.token_id is None:
                raise HTTPException(status_code=409, detail="The revision's lineage root has no token to anchor to.")
            # A revision is ANCHORED on the root token (never minted as a new token).
            calldata = contract_service.prepare_update_digital_asset_calldata(
                token_id=root.token_id,
                new_file_hash=asset.file_hash or "",
                new_offchain_uri=asset.metadata_cid or "",
            )
        elif action.action_type == "DOWNLOAD":
            # (owner consent verified above, before any state change)
            # No bearer token: only the requester can fetch, with their own Factor 3, before expiry.
            token_expires_at = datetime.now(UTC) + timedelta(hours=settings.DOWNLOAD_APPROVAL_TTL_HOURS)
            action.token_expires_at = token_expires_at
            download_url = f"/api/assets/document/download/{action.action_id}/fetch"
        elif action.action_type == "SHARE":
            # The approver decides the limits (defaults: unlimited views, no expiry, view-only).
            calldata = await _grant_share(db, action, asset, current_user, request.max_views,
                                          bool(request.allow_download), request.accessible_until, client_ip)

        audit_event = AuditEvent(
            event_type="AssetActionApproved",
            tx_hash=f"audit_appr_{uuid.uuid4().hex[:12]}",
            block_number=0,
            actor_did=current_user.did,
            target_did=action.actor_did,
            asset_serial=asset.serial_number,
            client_ip=client_ip,
            risk_score=0.05,
            risk_label="LOW",
            risk_factors={
                "action_id": action.action_id,
                "action_type": action.action_type,
                "decision": "APPROVED",
                "is_physical": asset.is_physical
            }
        )
        db.add(audit_event)

        await db.commit()

        return ApprovalCalldataResponse(
            calldata=calldata,
            contract_address=contract_service.contract_address if calldata else None,
            decision="APPROVE",
            status="APPROVED",
            download_token=download_token,
            download_url=download_url,
            token_expires_at=token_expires_at
        )

    elif request.decision.upper() == "REJECT":
        action.status = "REJECTED"
        action.approver_id = current_user.id
        action.approver_did = current_user.did

        details = dict(action.details) if action.details else {}
        details["rejection_reason"] = request.rejection_reason
        action.details = details
        if changes_asset_state:
            asset.approval_status = "REJECTED"

        audit_event = AuditEvent(
            event_type="AssetActionRejected",
            tx_hash=f"audit_rej_{uuid.uuid4().hex[:12]}",
            block_number=0,
            actor_did=current_user.did,
            target_did=action.actor_did,
            asset_serial=asset.serial_number,
            client_ip=client_ip,
            risk_score=0.25,
            risk_label="LOW",
            risk_factors={
                "action_id": action.action_id,
                "action_type": action.action_type,
                "decision": "REJECTED",
                "rejection_reason": request.rejection_reason
            }
        )
        db.add(audit_event)

        await db.commit()

        return ApprovalCalldataResponse(decision="REJECT", status="REJECTED")
    else:
        raise HTTPException(status_code=400, detail="Invalid decision.")


@router.get("/document/view/{identifier}")
async def view_digital_document(
    identifier: str,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Securely render a document with on-the-fly dynamic watermarking."""

    # 1. MFA Factor 2 Enforcement

    # Factor 2 arrives only as a single-use step-up token header (never a code in the URL,
    # where proxies and access logs would record it).
    await mfa.require_factor(db, current_user, "document.view", step_up_token=step_up_token)

    # 2. Resolve the asset (by creation action ID, serial, or token ID)
    asset = None
    res_a = await db.execute(select(DocumentAction).filter(DocumentAction.action_id == identifier))
    action = res_a.scalar_one_or_none()
    if action:
        asset = (await db.execute(select(Asset).filter(Asset.id == action.asset_id))).scalar_one_or_none()
    if not asset:
        asset = (await db.execute(select(Asset).filter(Asset.serial_number == identifier))).scalar_one_or_none()
    if not asset and identifier.isdigit():
        asset = (await db.execute(select(Asset).filter(Asset.token_id == int(identifier)))).scalar_one_or_none()
    if not asset or asset.is_physical:
        raise HTTPException(status_code=404, detail="Document asset not found.")

    # 3. Authorization: owner/custodian, in-scope Manager, Admin, or an approved grant.
    is_holder = asset.owner_id == current_user.id or asset.custodian_id == current_user.id
    grant = None
    if not (is_holder or access.can_manage_asset(current_user, asset)):
        grant = await grant_svc.usable_grant(db, current_user, asset, "view")
        if grant is None:
            event, message = grant_svc.denial_reason(await grant_svc.latest_grant(db, current_user, asset), "view")
            await record_audit(db, event, actor_did=current_user.did, asset_serial=asset.serial_number,
                               client_ip=client_ip, risk_label="MEDIUM", risk_score=0.4,
                               details={"asset_version": asset.version_number, "attempt": "VIEW"})
            await db.commit()
            raise HTTPException(status_code=403, detail=message)
    if asset.approval_status in ("PENDING_APPROVAL", "REJECTED") and not (is_holder or access.can_manage_asset(current_user, asset)):
        raise HTTPException(status_code=403, detail="This document is not approved for viewing.")

    file_bytes = _read_vault_file(asset)

    # 4. Count this successful view atomically (only grants are metered).
    if grant is not None:
        if await grant_svc.consume_view(db, grant.id) is None:
            # Lost the race (limit reached / expired / revoked meanwhile). The conditional
            # UPDATE changed nothing, so no rollback is needed (a rollback would expire the
            # loaded user/asset objects).
            event, message = grant_svc.denial_reason(await grant_svc.latest_grant(db, current_user, asset), "view")
            await record_audit(db, event, actor_did=current_user.did, asset_serial=asset.serial_number, client_ip=client_ip,
                               risk_label="MEDIUM", risk_score=0.4, details={"attempt": "VIEW"})
            await db.commit()
            raise HTTPException(status_code=403, detail=message)

    # 5. Derived, watermarked copy identifying the VIEWER (never the owner). Nothing is
    #    committed until the copy exists, so a failed render never consumes a view.
    view_id = await next_action_id(db, "VW")
    ctx = WatermarkContext(
        kind="VIEW", actor_name=current_user.name or "Unnamed", actor_wallet=current_user.wallet_address,
        client_ip=client_ip, action_id=view_id, verify_url=_verify_url(view_id),
        history=await _modification_history(db, asset),
    )
    try:
        content, mime, out_name = render_view_copy(file_bytes, _original_filename(asset), ctx)
    except UnsupportedDocumentType as e:
        await db.rollback()
        raise HTTPException(status_code=415, detail=f"This document type cannot be served as a protected copy: {e}")

    db.add(DocumentAction(
        action_id=view_id,
        action_type="VIEW",
        asset_id=asset.id,
        asset_serial=asset.serial_number,
        asset_version=asset.version_number,
        actor_id=current_user.id,
        actor_did=current_user.did,
        status="COMPLETED",
        purpose="View Document",
        client_ip=client_ip,
        watermark_text="\n".join(ctx.all_lines()),
        details={"grant_id": str(grant.id)} if grant is not None else None,
    ))
    owner = (await db.execute(select(User).where(User.id == asset.owner_id))).scalar_one_or_none()
    risk = ai_score("DOCUMENT_VIEWED", current_user, owner_did=owner.did if owner else None)
    await record_audit(db, "DOCUMENT_VIEWED", actor_did=current_user.did, asset_serial=asset.serial_number, client_ip=client_ip,
                       risk_label=risk.get("risk_label"), risk_score=risk.get("risk_score"),
                       details={"action_id": view_id, "asset_version": asset.version_number, "via_grant": grant is not None,
                                **({"ai": risk["ai"]} if risk else {})})
    await db.commit()
    return Response(content=content, media_type=mime, headers={
        "Content-Disposition": f'inline; filename="{out_name}"', "X-LexCorp-Action-Id": view_id, "Cache-Control": "no-store",
    })


@router.get("/document/logs/{asset_serial}", response_model=list[DocumentActionRead])
async def get_document_view_logs(
    asset_serial: str,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve viewing audit logs for a specific document."""
    if current_user.role not in ["ADMIN", "MANAGER", "AUDITOR"]:
        raise HTTPException(status_code=403, detail="Not authorized to view audit logs.")

    asset_res = await db.execute(select(Asset).filter(Asset.serial_number == asset_serial))
    asset = asset_res.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    if current_user.role == "MANAGER" and not access.can_manage_asset(current_user, asset):
        raise HTTPException(status_code=403, detail="Managers can only view logs for their own department.")

    # Retrieve all VIEW actions for this asset
    res = await db.execute(
        select(DocumentAction)
        .filter(DocumentAction.asset_serial == asset_serial, DocumentAction.action_type == "VIEW")
        .order_by(desc(DocumentAction.created_at))
    )
    return res.scalars().all()


@router.post("/document/download/request", response_model=DocumentActionRead)
async def request_document_download(
    request: DownloadRequest,
    req: Request,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Submit a request to download a digital document, pending Manager/Admin approval."""

    # 1. MFA Factor 2 Enforcement

    await mfa.require_factor(db, current_user, "download.request", totp_code=request.totp_code, step_up_token=step_up_token)

    # 2. Asset Verification
    asset_res = await db.execute(select(Asset).filter(Asset.serial_number == request.asset_serial))
    asset = asset_res.scalar_one_or_none()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if asset.asset_type not in ["DIGITAL", "DOCUMENT"]:
        raise HTTPException(status_code=400, detail="Only digital documents can be downloaded")
    mode = (request.mode or "STANDARD").upper()
    if mode not in ("STANDARD", "MODIFICATION"):
        raise HTTPException(status_code=400, detail="mode must be STANDARD or MODIFICATION")
    if asset.approval_status not in ("APPROVED", "ACTIVE"):
        raise HTTPException(status_code=409, detail="Only approved document versions can be downloaded.")

    # 3. RBAC & scoping: download is a separate permission from view.
    if current_user.role == "AUDITOR":
        raise HTTPException(status_code=403, detail="Auditors are not permitted to download operational documents")
    is_holder = asset.owner_id == current_user.id or asset.custodian_id == current_user.id
    # A download copy needs a grant that allows downloads; a modification copy needs any active
    # delegated access (the owner's consent and an approval still follow).
    needed = "download" if mode == "STANDARD" else "view"
    if not (is_holder or access.can_manage_asset(current_user, asset)):
        if await grant_svc.usable_grant(db, current_user, asset, needed) is None:
            event, message = grant_svc.denial_reason(await grant_svc.latest_grant(db, current_user, asset), needed)
            await record_audit(db, event, actor_did=current_user.did, asset_serial=asset.serial_number,
                               client_ip=get_request_client_ip(req), risk_label="MEDIUM", risk_score=0.4,
                               details={"attempt": "DOWNLOAD_REQUEST"})
            await db.commit()
            raise HTTPException(status_code=403, detail=message)

    if mode == "MODIFICATION":
        _, latest, pending = await _lineage_state(db, asset)
        if asset.version_number != latest:
            raise HTTPException(status_code=409, detail=f"Modifications must start from the latest approved version (v{latest}).")
        if pending:
            raise HTTPException(status_code=409, detail="A revision of this document is already pending approval.")
    if mode == "STANDARD" and asset.owner_id == current_user.id:
        raise HTTPException(status_code=409, detail="You own this document: download your watermarked copy directly, no approval needed.")
    requires_owner = settings.DOWNLOAD_REQUIRES_OWNER_APPROVAL and asset.owner_id != current_user.id

    # 4. Action Creation
    action_id = await next_action_id(db, "DL")
    new_action = DocumentAction(
        action_id=action_id,
        action_type="DOWNLOAD",
        asset_id=asset.id,
        asset_serial=asset.serial_number,
        asset_version=asset.version_number,
        actor_id=current_user.id,
        actor_did=current_user.did,
        status="PENDING",
        purpose=request.purpose,
        client_ip=get_request_client_ip(req),
        details={"mode": mode, "requires_owner_approval": requires_owner},
    )

    db.add(new_action)
    if not requires_owner and _privileged_for(current_user, asset):
        _approve_download(new_action, current_user, "requester is a Manager/Administrator in scope")
    await db.commit()
    await db.refresh(new_action)

    return new_action


def _approve_download(action, approver, reason: str) -> None:
    action.status = "APPROVED"
    action.approver_id = approver.id
    action.approver_did = approver.did
    action.token_expires_at = datetime.now(UTC) + timedelta(hours=settings.DOWNLOAD_APPROVAL_TTL_HOURS)
    action.details = {**(action.details or {}), "auto_approved": reason}


@router.post("/document/download/approve/{action_id}")
@router.post("/document/download/approval/{action_id}")
async def approve_document_download(
    action_id: str,
    request: DocumentApprovalRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Alias endpoint for approving download requests. Just routes to approve_document."""
    return await approve_document(action_id, request, current_user, db, client_ip, step_up_token)



async def _require_may_revise(db, user, parent) -> None:
    """Owner/custodian, a Manager/Admin in scope, or someone holding an approved modification
    copy of this version (e.g. a delegated user whose request was accepted)."""
    if parent.owner_id == user.id or parent.custodian_id == user.id or access.can_manage_asset(user, parent):
        return
    rows = (await db.execute(select(DocumentAction).where(
        DocumentAction.actor_id == user.id, DocumentAction.asset_id == parent.id,
        DocumentAction.action_type == "DOWNLOAD", DocumentAction.status.in_(("APPROVED", "COMPLETED")),
    ))).scalars().all()
    if not any((r.details or {}).get("mode") == "MODIFICATION" for r in rows):
        raise HTTPException(status_code=403, detail="Only the owner, a Manager/Admin for its department, or someone given an "
                                                    "approved modification copy may revise this document.")


async def _create_revision(
    db: AsyncSession, current_user: User, parent_asset: Asset, download_action_id: Optional[str],
    content: bytes, filename: str, name: Optional[str], purpose: Optional[str],
    client_ip: str, requested_serial: Optional[str] = None,
) -> DocumentAction:
    """Pending revision = NEW asset row (v+1). Requires an approved, completed MODIFICATION
    download of the parent by this user (owner, Manager/Admin, or a delegated user whose
    request the owner and approvers accepted). The uploaded file must still carry that copy's
    watermark: its QR code and Document Control details are checked against the record.
    The hash is computed server-side; history always comes from the database."""
    if parent_asset.asset_type not in ("DIGITAL", "DOCUMENT") or parent_asset.is_physical:
        raise HTTPException(status_code=400, detail="Only digital documents can be revised.")
    if not download_action_id:
        raise HTTPException(status_code=400, detail="A completed, approved modification download (DL-...) is required before uploading a revision.")
    dl = (await db.execute(select(DocumentAction).where(DocumentAction.action_id == download_action_id))).scalar_one_or_none()
    d = (dl.details or {}) if dl else {}
    if (not dl or dl.action_type != "DOWNLOAD" or d.get("mode") != "MODIFICATION" or dl.actor_id != current_user.id
            or dl.asset_id != parent_asset.id):
        raise HTTPException(status_code=403, detail="That download is not an approved modification download of this version by you.")
    if dl.status != "COMPLETED":
        raise HTTPException(status_code=409, detail="The modification download must be approved and fetched before a revision is uploaded.")
    if d.get("revision_mod_id"):
        raise HTTPException(status_code=409, detail=f"This modification download was already used by {d['revision_mod_id']}.")

    root_id, latest, pending = await _lineage_state(db, parent_asset)
    if parent_asset.version_number != latest or parent_asset.approval_status not in ("APPROVED", "ACTIVE"):
        raise HTTPException(status_code=409, detail=f"Revisions must be based on the latest approved version (v{latest}).")
    if pending:
        raise HTTPException(status_code=409, detail="A revision of this document is already pending approval.")
    # Verify every watermark element against what was issued, then remove LexCorp2's layers:
    # the version is stored clean, so later copies carry one watermark instead of a stack.
    manifest = d.get("watermark_manifest")
    check = copy_integrity.check_copy(content, dl.action_id, dl.watermark_text or "")
    findings = [] if check.ok else [watermark_strip.finding("tamper", "QR code / Document Control", check.reason)]
    if manifest:
        clean, strip_findings = watermark_strip.strip_watermark(content, filename, manifest)
        findings += strip_findings
    else:
        clean = content  # a copy issued before removable layers existed: kept as returned
    file_hash = hashlib.sha256(clean).hexdigest()
    lineage_hashes = set((await db.execute(select(Asset.file_hash).where(or_(Asset.root_asset_id == root_id, Asset.id == root_id)))).scalars().all())
    if file_hash in lineage_hashes or hashlib.sha256(content).hexdigest() in lineage_hashes:
        raise HTTPException(status_code=400, detail="The uploaded file is identical to an existing version (same SHA-256).")
    safe_name = os.path.basename(filename or "revision")
    stored = f"{file_hash}_{safe_name}"
    offchain_uri = f"secure-vault://documents/{stored}"
    path = os.path.join(OFFCHAIN_STORAGE_DIR, stored)
    if not os.path.exists(path):  # content-addressed: never overwrite existing bytes
        with open(path, "xb") as f:
            f.write(clean)

    root = (await db.execute(select(Asset).where(Asset.id == root_id))).scalar_one()
    new_version = latest + 1
    serial = requested_serial or f"{root.serial_number}-V{new_version}"
    if (await db.execute(select(Asset).filter(Asset.serial_number == serial))).scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Asset serial number already exists.")

    action_id_str = await next_action_id(db, "MOD")
    revised = Asset(
        token_id=await next_token_id(db), serial_number=serial, name=name or parent_asset.name,
        asset_type=parent_asset.asset_type, file_hash=file_hash, metadata_cid=offchain_uri,
        owner_id=parent_asset.owner_id, department=parent_asset.department, is_physical=False,
        lifecycle_status="PENDING_APPROVAL", approval_status="PENDING_APPROVAL",
        parent_asset_id=parent_asset.id, root_asset_id=root_id, version_number=new_version,
        action_id=action_id_str, action_type="MODIFICATION",
    )
    db.add(revised)
    await db.flush()
    action = DocumentAction(
        action_id=action_id_str, action_type="MODIFICATION", asset_id=revised.id, asset_serial=serial,
        asset_version=new_version, actor_id=current_user.id, actor_did=current_user.did, status="PENDING",
        purpose=purpose, client_ip=client_ip,
        details={
            "name": revised.name, "parent_asset_serial": parent_asset.serial_number, "parent_asset_id": str(parent_asset.id),
            "parent_version": parent_asset.version_number, "version": new_version, "parent_file_hash": parent_asset.file_hash,
            "file_hash": file_hash, "offchain_uri": offchain_uri, "download_id": dl.action_id,
        },
    )
    db.add(action)
    dl.details = {**d, "revision_mod_id": action_id_str}
    risk = ai_score("REVISION_SUBMITTED", current_user, sensitivity=2)
    await record_audit(db, "REVISION_SUBMITTED", actor_did=current_user.did, asset_serial=serial, client_ip=client_ip,
                       risk_label=risk.get("risk_label"), risk_score=risk.get("risk_score"),
                       details={"modification_id": action_id_str, "parent_version": parent_asset.version_number,
                                "version": new_version, "file_hash": file_hash, "download_id": dl.action_id,
                                **({"ai": risk["ai"]} if risk else {})})
    if any(f["severity"] == "tamper" for f in findings):
        # Silent to the uploader: the revision is accepted as pending, but an alert goes to the
        # Auditor with the evidence, and the revision can't be approved while it is open.
        evidence_name = f"{hashlib.sha256(content).hexdigest()}_{safe_name}"
        evidence_dir = os.path.join(OFFCHAIN_STORAGE_DIR, "evidence")
        os.makedirs(evidence_dir, exist_ok=True)
        evidence_path = os.path.join(evidence_dir, evidence_name)
        if not os.path.exists(evidence_path):
            with open(evidence_path, "xb") as f:
                f.write(content)
        tampered = [f for f in findings if f["severity"] == "tamper"]
        await record_audit(db, "WATERMARK_TAMPER_DETECTED", actor_did=current_user.did, asset_serial=serial, client_ip=client_ip,
                           risk_label="HIGH", risk_score=0.8,
                           details={"action_id": action_id_str, "modification_id": action_id_str, "download_id": dl.action_id,
                                    "reason": f"Revision {action_id_str}: watermark of {dl.action_id} altered or removed "
                                              f"({'; '.join(f['where'] for f in tampered)[:300]})",
                                    "findings": findings, "recorded_watermark": dl.watermark_text,
                                    "evidence": {"file": f"evidence/{evidence_name}", "filename": safe_name},
                                    "source": "revision upload"})
    elif findings:
        await record_audit(db, "REVISION_WATERMARK_NOTES", actor_did=current_user.did, asset_serial=serial, client_ip=client_ip,
                           details={"modification_id": action_id_str, "download_id": dl.action_id, "findings": findings})
    return action


@router.post("/document/revise", response_model=DocumentActionRead)
async def revise_document(
    request: DocumentRevisionRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    step_up_token: Optional[str] = Depends(get_step_up_token),
    client_ip: str = Depends(get_request_client_ip),
):
    """Submit a revision whose file is already in the vault (see /upload-document).
    The server re-hashes the stored bytes; a client-supplied hash is never trusted."""
    if current_user.role == "AUDITOR":
        raise HTTPException(status_code=403, detail="Auditors cannot revise documents.")
    parent_asset = (await db.execute(select(Asset).filter(Asset.serial_number == request.parent_asset_serial))).scalar_one_or_none()
    if not parent_asset:
        raise HTTPException(status_code=404, detail="Parent asset not found.")
    await _require_may_revise(db, current_user, parent_asset)
    await mfa.require_factor(db, current_user, "document.modify", totp_code=request.totp_code, step_up_token=step_up_token)
    probe = Asset(metadata_cid=request.new_offchain_uri)
    stored_bytes = _read_vault_file(probe)
    actual = hashlib.sha256(stored_bytes).hexdigest()
    if actual != request.new_file_hash:
        raise HTTPException(status_code=400, detail="new_file_hash does not match the stored file (server-computed SHA-256).")
    action = await _create_revision(db, current_user, parent_asset, request.modification_download_id, stored_bytes,
                                    _original_filename(probe), request.name, request.purpose, client_ip,
                                    requested_serial=request.new_serial_number)
    await db.commit()
    await db.refresh(action)
    return action


@router.post("/document/revise/upload", response_model=DocumentActionRead)
@limiter.limit("20/minute")
async def upload_revision(
    request: Request,
    file: UploadFile = File(...),
    parent_asset_serial: str = Form(...),
    modification_download_id: str = Form(...),
    name: Optional[str] = Form(None),
    purpose: Optional[str] = Form(None),
    totp_code: Optional[str] = Form(None),
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Upload an externally modified file as a PENDING revision (Factor 3). The new bytes
    are stored under their own SHA-256; the original and older versions are untouched."""
    if current_user.role == "AUDITOR":
        raise HTTPException(status_code=403, detail="Auditors cannot revise documents.")
    parent_asset = (await db.execute(select(Asset).filter(Asset.serial_number == parent_asset_serial))).scalar_one_or_none()
    if not parent_asset:
        raise HTTPException(status_code=404, detail="Parent asset not found.")
    await _require_may_revise(db, current_user, parent_asset)
    await mfa.require_factor(db, current_user, "document.modify", totp_code=totp_code, step_up_token=step_up_token)
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File size exceeds maximum permitted limit (50MB).")
    action = await _create_revision(db, current_user, parent_asset, modification_download_id, content,
                                    os.path.basename(file.filename or "revision"), name, purpose, get_request_client_ip(request))
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/document/lineage/{asset_serial}")
async def get_document_lineage(
    asset_serial: str,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db)
):
    """Fetch complete revision tree/history for a document the caller may see."""
    asset = await _visible_asset_or_404(db, current_user, serial=asset_serial)

    # Find root asset
    current = asset
    visited = set()
    while current.parent_asset_id and str(current.id) not in visited:
        visited.add(str(current.id))
        parent_res = await db.execute(select(Asset).filter(Asset.id == current.parent_asset_id))
        parent = parent_res.scalar_one_or_none()
        if not parent:
            break
        current = parent

    root_asset = current

    # Now collect all descendants from root
    def asset_to_dict(a: Asset):
        return {
            "id": str(a.id),
            "token_id": a.token_id,
            "serial_number": a.serial_number,
            "name": a.name,
            "lifecycle_status": a.lifecycle_status,
            "approval_status": a.approval_status,
            "file_hash": a.file_hash,
            "version_number": a.version_number,
            "action_id": a.action_id,
            "parent_asset_id": str(a.parent_asset_id) if a.parent_asset_id else None,
            "created_at": a.created_at.isoformat() if a.created_at else None
        }

    lineage = [asset_to_dict(root_asset)]
    to_explore = [root_asset.id]

    while to_explore:
        curr_id = to_explore.pop(0)
        children_res = await db.execute(select(Asset).filter(Asset.parent_asset_id == curr_id).order_by(Asset.created_at))
        children = children_res.scalars().all()
        for child in children:
            lineage.append(asset_to_dict(child))
            to_explore.append(child.id)

    return {
        "root_serial": root_asset.serial_number,
        "current_serial": asset.serial_number,
        "lineage": lineage
    }


@router.get("/verify/{serial_number}")
async def verify_asset(
    serial_number: str,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db)
):
    """
     Phase 8: Digital QR Verification & Role-Based Redaction
     QR codes resolve here to verify the asset and return redacted data based on the caller's role.
    """
    res = await db.execute(select(Asset).filter(Asset.serial_number == serial_number))
    asset = res.scalar_one_or_none()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Standard info (visible to all)
    data = {
        "serial_number": asset.serial_number,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "lifecycle_status": asset.lifecycle_status,
        "is_physical": asset.is_physical,
        "approval_status": asset.approval_status
    }

    # Redaction Logic
    is_owner_or_custodian = (
        str(asset.owner_id) == str(current_user.id) or
        (asset.custodian_id and str(asset.custodian_id) == str(current_user.id))
    )
    is_in_department = access.can_manage_asset(current_user, asset)

    # Detailed info visibility:
    # - ADMIN / AUDITOR: Always see full details
    # - MANAGER / USER: See full details IF in their department or they own it/custody it.

    show_details = False
    if current_user.role in ["ADMIN", "AUDITOR"]:
        show_details = True
    elif current_user.role in ["MANAGER", "USER"]:
        if is_in_department or is_owner_or_custodian:
            show_details = True

    if show_details:
        data.update({
            "token_id": asset.token_id,
            "department": asset.department,
            "file_hash": asset.file_hash,
            "metadata_cid": asset.metadata_cid,
            "mac_address": asset.mac_address if access.can_see_sensitive_physical(current_user, asset) else None,
            "device_unique_address": asset.device_unique_address if access.can_see_sensitive_physical(current_user, asset) else None,
            "location": asset.location,
            "owner_id": str(asset.owner_id),
            "custodian_id": str(asset.custodian_id) if asset.custodian_id else None,
            "custodian_did": asset.custodian_did,
            "action_id": asset.action_id,
            "action_type": asset.action_type
        })

    return data


@router.get("/document/download-token/{token}")
async def download_document_with_token(token: str):
    """Removed: possession of a URL token alone released the document with no session
    and no Factor 3. Use POST /document/download/{action_id}/fetch."""
    raise HTTPException(status_code=410, detail="Token URL downloads are disabled. The requester fetches an approved download with Factor 3.")


@router.post("/document/download/{action_id}/owner-approval")
async def owner_decision_on_download(
    action_id: str,
    body: OwnerDecisionRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """The document owner consents to (or refuses) someone else's download (Factor 3)."""
    action = (await db.execute(select(DocumentAction).where(DocumentAction.action_id == action_id))).scalar_one_or_none()
    asset = action and (await db.execute(select(Asset).where(Asset.id == action.asset_id))).scalar_one_or_none()
    if not action or action.action_type != "DOWNLOAD" or not asset or asset.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Download request not found.")
    d = dict(action.details or {})
    if action.status != "PENDING" or not d.get("requires_owner_approval") or d.get("owner_approved_by"):
        raise HTTPException(status_code=409, detail="This request is not awaiting owner approval.")
    await mfa.require_factor(db, current_user, "asset.approve", totp_code=body.totp_code, step_up_token=step_up_token)
    if body.decision.upper() == "APPROVE":
        d.update({"owner_approved_by": current_user.did, "owner_approved_at": datetime.now(UTC).isoformat()})
        event = "DOWNLOAD_OWNER_APPROVED"
        requester = (await db.execute(select(User).where(User.id == action.actor_id))).scalar_one_or_none()
        if (requester is not None and _privileged_for(requester, asset)) or _privileged_for(current_user, asset):
            # A Manager/Administrator's request needs only the owner's consent; and when the owner is
            # a Manager/Administrator, their consent is the approval.
            action.details = d
            _approve_download(action, current_user, "owner consented to a Manager/Administrator request")
            d = dict(action.details)
    elif body.decision.upper() == "REJECT":
        action.status = "REJECTED"
        d.update({"owner_rejected_by": current_user.did, "rejection_reason": body.rejection_reason})
        event = "DOWNLOAD_OWNER_REJECTED"
    else:
        raise HTTPException(status_code=400, detail="Invalid decision.")
    action.details = d
    await record_audit(db, event, actor_did=current_user.did, target_did=action.actor_did, asset_serial=asset.serial_number,
                       client_ip=client_ip, details={"download_id": action.action_id})
    await db.commit()
    return {"action_id": action.action_id, "status": action.status, "owner_approved": bool(d.get("owner_approved_by"))}


@router.get("/document/download/pending", response_model=list[DocumentActionRead])
async def pending_download_requests(current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    """Manager/Admin: pending downloads in scope. Owner: requests awaiting their consent. Everyone: their own."""
    query = select(DocumentAction).join(Asset, Asset.id == DocumentAction.asset_id).where(
        DocumentAction.action_type == "DOWNLOAD", DocumentAction.status == "PENDING")
    if current_user.role != "ADMIN":
        mine = or_(DocumentAction.actor_id == current_user.id, Asset.owner_id == current_user.id)
        if current_user.role == "MANAGER":
            mine = or_(mine, Asset.department.in_(access.manager_departments(current_user)))
        query = query.where(mine)
    return (await db.execute(query.order_by(desc(DocumentAction.created_at)))).scalars().all()


@router.get("/document/downloads/mine", response_model=list[DocumentActionRead])
async def my_download_requests(current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(DocumentAction).where(
        DocumentAction.action_type == "DOWNLOAD", DocumentAction.actor_id == current_user.id
    ).order_by(desc(DocumentAction.created_at)))
    return rows.scalars().all()


@router.post("/document/download/{action_id}/fetch")
async def fetch_approved_download(
    action_id: str,
    req: Request,
    body: FetchDownloadRequest = FetchDownloadRequest(),
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Single-use controlled download by the requester: approval + Factor 3 (TOTP 3 or
    Passkey 3) + Download ID. Returns a derived watermarked copy; the original is untouched."""
    action = (await db.execute(select(DocumentAction).where(DocumentAction.action_id == action_id))).scalar_one_or_none()
    if not action or action.action_type != "DOWNLOAD" or action.actor_id != current_user.id:
        raise HTTPException(status_code=404, detail="Download not found.")
    if action.status == "COMPLETED":
        raise HTTPException(status_code=409, detail="This download has already been used.")
    if action.status != "APPROVED":
        raise HTTPException(status_code=403, detail="This download has not been approved.")
    if action.token_expires_at and action.token_expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=410, detail="This download approval has expired. Request a new download.")
    await mfa.require_factor(db, current_user, "document.download", totp_code=body.totp_code, step_up_token=step_up_token)

    asset = (await db.execute(select(Asset).where(Asset.id == action.asset_id))).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Document not found.")
    is_holder = asset.owner_id == current_user.id or asset.custodian_id == current_user.id
    if not (is_holder or access.can_manage_asset(current_user, asset)):
        if await grant_svc.usable_grant(db, current_user, asset, "download") is None:
            raise HTTPException(status_code=403, detail="Your download permission is no longer valid.")

    client_ip = get_request_client_ip(req)
    file_bytes = _read_vault_file(asset)
    downloader = current_user
    owner = (await db.execute(select(User).where(User.id == asset.owner_id))).scalar_one_or_none()
    ctx = WatermarkContext(
        kind="DOWNLOAD", actor_name=downloader.name or "Unnamed", actor_wallet=downloader.wallet_address,
        client_ip=client_ip, action_id=action.action_id, verify_url=_verify_url(action.action_id),
        owner_name=owner.name if owner else None, owner_wallet=owner.wallet_address if owner else None,
        history=await _modification_history(db, asset),
    )
    try:
        content, mime, out_name, manifest = render_protected_copy_with_manifest(file_bytes, _original_filename(asset), ctx)
    except UnsupportedDocumentType as e:
        raise HTTPException(status_code=415, detail=f"This document type cannot be served as a protected copy: {e}")
    action.status = "COMPLETED"
    action.watermark_text = "\n".join(ctx.all_lines())
    action.details = {**(action.details or {}), "downloaded_at": datetime.now(UTC).isoformat(), "downloaded_from_ip": client_ip,
                      "watermark_manifest": manifest, "copy_filename": out_name}
    risk = ai_score("DOCUMENT_DOWNLOADED", current_user, owner_did=owner.did if owner else None, sensitivity=2)
    await record_audit(db, "DOCUMENT_DOWNLOADED", actor_did=current_user.did, asset_serial=asset.serial_number, client_ip=client_ip,
                       risk_label=risk.get("risk_label"), risk_score=risk.get("risk_score"),
                       details={"download_id": action.action_id, "mode": (action.details or {}).get("mode", "STANDARD"),
                                "asset_version": asset.version_number, **({"ai": risk["ai"]} if risk else {})})
    await db.commit()
    return Response(content=content, media_type=mime, headers={
        "Content-Disposition": f'attachment; filename="{out_name}"', "X-LexCorp-Action-Id": action.action_id, "Cache-Control": "no-store",
    })


@router.post("/document/{serial}/owner-download")
async def owner_download(
    serial: str,
    req: Request,
    body: FetchDownloadRequest = FetchDownloadRequest(),
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """The document's owner downloads a copy without an approval step. Still Factor 3, still a
    new Download ID, and still a watermarked copy naming them; the original file never leaves
    the vault."""
    asset = (await db.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one_or_none()
    if not asset or asset.asset_type not in ("DIGITAL", "DOCUMENT"):
        raise HTTPException(status_code=404, detail="Document not found.")
    if asset.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the document's owner can download without approval. Request a download instead.")
    if asset.approval_status not in ("APPROVED", "ACTIVE"):
        raise HTTPException(status_code=409, detail="Only approved document versions can be downloaded.")
    await mfa.require_factor(db, current_user, "document.download", totp_code=body.totp_code, step_up_token=step_up_token)

    client_ip = get_request_client_ip(req)
    action = DocumentAction(
        action_id=await next_action_id(db, "DL"), action_type="DOWNLOAD", asset_id=asset.id,
        asset_serial=asset.serial_number, asset_version=asset.version_number, actor_id=current_user.id,
        actor_did=current_user.did, status="COMPLETED", purpose="Owner's own copy", client_ip=client_ip,
        details={"mode": "STANDARD", "owner_direct": True, "downloaded_at": datetime.now(UTC).isoformat(),
                 "downloaded_from_ip": client_ip},
    )
    ctx = WatermarkContext(
        kind="DOWNLOAD", actor_name=current_user.name or "Unnamed", actor_wallet=current_user.wallet_address,
        client_ip=client_ip, action_id=action.action_id, verify_url=_verify_url(action.action_id),
        owner_name=current_user.name, owner_wallet=current_user.wallet_address,
        history=await _modification_history(db, asset),
    )
    try:
        content, mime, out_name, manifest = render_protected_copy_with_manifest(_read_vault_file(asset), _original_filename(asset), ctx)
    except UnsupportedDocumentType as e:
        raise HTTPException(status_code=415, detail=f"This document type cannot be served as a protected copy: {e}")
    action.watermark_text = "\n".join(ctx.all_lines())
    action.details = {**action.details, "watermark_manifest": manifest, "copy_filename": out_name}
    db.add(action)
    risk = ai_score("DOCUMENT_DOWNLOADED", current_user, owner_did=current_user.did, sensitivity=2)
    await record_audit(db, "DOCUMENT_DOWNLOADED", actor_did=current_user.did, asset_serial=asset.serial_number, client_ip=client_ip,
                       risk_label=risk.get("risk_label"), risk_score=risk.get("risk_score"),
                       details={"download_id": action.action_id, "mode": "STANDARD", "owner_direct": True,
                                "asset_version": asset.version_number, **({"ai": risk["ai"]} if risk else {})})
    await db.commit()
    return Response(content=content, media_type=mime, headers={
        "Content-Disposition": f'attachment; filename="{out_name}"', "X-LexCorp-Action-Id": action.action_id, "Cache-Control": "no-store",
    })


def _grant_row(g: AssetAccessGrant) -> dict:
    now = datetime.now(UTC)
    exhausted = g.max_views is not None and g.views_count >= g.max_views
    expired = g.expires_at is not None and g.expires_at <= now
    return {
        "id": str(g.id), "asset_serial": g.asset_serial, "grantee_did": g.grantee_did,
        "granted_by_did": g.granted_by_did, "requested_by_did": g.requested_by_did,
        "request_action_id": g.request_action_id, "can_view": g.can_view, "can_download": g.can_download,
        "max_views": g.max_views, "views_count": g.views_count,
        "views_remaining": None if g.max_views is None else max(0, g.max_views - g.views_count),
        "expires_at": g.expires_at.isoformat() if g.expires_at else None,
        "status": "REVOKED" if g.revoked_at or not g.is_active else "EXPIRED" if expired else "EXHAUSTED" if exhausted else "ACTIVE",
        "created_at": g.created_at.isoformat() if g.created_at else None,
    }


@router.get("/access-grants")
async def list_access_grants(
    asset_serial: Optional[str] = None,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
):
    """Grants the caller may see: their own, grants on assets they hold, or (Manager/Admin/Auditor) in scope."""
    query = select(AssetAccessGrant).join(Asset, Asset.serial_number == AssetAccessGrant.asset_serial)
    if asset_serial:
        query = query.where(AssetAccessGrant.asset_serial == asset_serial)
    if current_user.role not in access.UNRESTRICTED_ROLES:
        own = or_(AssetAccessGrant.grantee_did == current_user.did, Asset.owner_id == current_user.id)
        if current_user.role == "MANAGER":
            own = or_(own, Asset.department.in_(access.manager_departments(current_user)))
        query = query.where(own)
    rows = (await db.execute(query.order_by(desc(AssetAccessGrant.created_at)))).scalars().all()
    return [_grant_row(g) for g in rows]


@router.post("/access-grants/{grant_id}/revoke")
async def revoke_access_grant(
    grant_id: str,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
):
    try:
        gid = uuid.UUID(grant_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid grant id")
    grant = (await db.execute(select(AssetAccessGrant).where(AssetAccessGrant.id == gid))).scalar_one_or_none()
    asset = grant and (await db.execute(select(Asset).where(Asset.serial_number == grant.asset_serial))).scalar_one_or_none()
    if not grant or not asset:
        raise HTTPException(status_code=404, detail="Grant not found")
    if not (asset.owner_id == current_user.id or access.can_manage_asset(current_user, asset)):
        raise HTTPException(status_code=403, detail="Not authorized to revoke this grant.")
    if grant.revoked_at is None:
        grant.revoked_at = datetime.now(UTC)
        grant.revoked_by_did = current_user.did
        grant.is_active = False
        await record_audit(db, "ACCESS_REVOKED", actor_did=current_user.did, target_did=grant.grantee_did,
                           asset_serial=grant.asset_serial, client_ip=client_ip, details={"grant_id": str(grant.id)})
        await db.commit()
    return _grant_row(grant)









PHYSICAL_STATUSES = ("ACTIVE", "ASSIGNED", "MAINTENANCE", "IN_STORAGE", "LOST", "RETIRED", "DECOMMISSIONED")


@router.post("/physical/{serial}/status")
async def change_physical_status(
    serial: str,
    body: PhysicalStatusRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Lifecycle status change by Admin / in-scope Manager (Factor 3), audited."""
    asset = (await db.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one_or_none()
    if not asset or not asset.is_physical:
        raise HTTPException(status_code=404, detail="Physical asset not found.")
    if not access.can_manage_asset(current_user, asset):
        raise HTTPException(status_code=403, detail="This asset is outside your authorized departments.")
    new_status = body.status.strip().upper()
    if new_status not in PHYSICAL_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {PHYSICAL_STATUSES}")
    await mfa.require_factor(db, current_user, "asset.manage", totp_code=body.totp_code, step_up_token=step_up_token)
    previous = asset.lifecycle_status
    asset.lifecycle_status = new_status
    await record_audit(db, "ASSET_STATUS_CHANGED", actor_did=current_user.did, asset_serial=serial, client_ip=client_ip,
                       details={"from": previous, "to": new_status, "reason": (body.reason or "")[:500]})
    await db.commit()
    return {"serial_number": serial, "previous_status": previous, "lifecycle_status": new_status}



async def _confirm_on_chain(db: AsyncSession, current_user: User, serial: str, tx_hash: str, client_ip: str) -> dict:
    """Record an on-chain effect ONLY after verifying it against Besu:
    successful receipt, sent to the LexCorp contract, and the resulting chain state:
      physical creation -> getTokenBySerial(serial) == reserved token ID
      digital creation  -> token exists with the approved file hash
      revision          -> the lineage root token now carries this revision's hash
    Nothing is recorded if any check fails (no fake blockchain success)."""
    asset = (await db.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    root = asset if asset.version_number == 1 else (await db.execute(select(Asset).where(Asset.id == asset.root_asset_id))).scalar_one()
    if not access.can_manage_asset(current_user, root):
        raise HTTPException(status_code=403, detail="This asset is outside your authorized departments.")
    if asset.approval_status != "APPROVED":
        raise HTTPException(status_code=409, detail="Only approved assets/revisions can be anchored on-chain.")
    try:
        receipt = contract_service.w3.eth.get_transaction_receipt(tx_hash)
    except Exception:
        raise HTTPException(status_code=409, detail="Transaction receipt not found on the chain.")
    to_addr = (receipt.get("to") or "").lower()
    if receipt.get("status") != 1 or to_addr != (contract_service.contract_address or "").lower():
        raise HTTPException(status_code=409, detail="Transaction failed or was not sent to the LexCorp asset contract.")

    if asset.is_physical:
        if contract_service.get_token_by_serial(serial) != asset.token_id:
            raise HTTPException(status_code=409, detail="The chain does not show this serial minted with the reserved token ID.")
        event, new_state = "PHYSICAL_ASSET_MINTED", "MINTED"
    elif asset.version_number == 1:
        on_chain = contract_service.get_digital_asset(asset.token_id)
        if not on_chain or on_chain.get("serial_number") != serial or on_chain.get("file_hash") != asset.file_hash:
            raise HTTPException(status_code=409, detail="The chain does not show this document minted with the approved hash.")
        event, new_state = "DOCUMENT_MINTED", "MINTED"
    else:
        on_chain = contract_service.get_digital_asset(root.token_id)
        if not on_chain or on_chain.get("file_hash") != asset.file_hash:
            raise HTTPException(status_code=409, detail="The chain does not show the root token updated to this revision's hash.")
        event, new_state = "DOCUMENT_REVISION_ANCHORED", "ANCHORED"

    asset.lifecycle_status = new_state
    asset.watermark_metadata = {**(asset.watermark_metadata or {}), "chain_tx": tx_hash, "block_number": receipt.get("blockNumber")}
    await record_audit(db, event, actor_did=current_user.did, asset_serial=serial, client_ip=client_ip,
                       details={"tx_hash": tx_hash, "block_number": receipt.get("blockNumber"),
                                "token_id": root.token_id, "version": asset.version_number,
                                "chain_id": settings.CHAIN_ID, "contract": contract_service.contract_address})
    await db.commit()
    return {"serial_number": serial, "token_id": root.token_id, "version": asset.version_number,
            "lifecycle_status": new_state, "tx_hash": tx_hash, "block_number": receipt.get("blockNumber")}


@router.post("/physical/{serial}/mint-confirm")
async def confirm_physical_mint(
    serial: str,
    body: MintConfirmRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
):
    asset = (await db.execute(select(Asset).where(Asset.serial_number == serial))).scalar_one_or_none()
    if not asset or not asset.is_physical:
        raise HTTPException(status_code=404, detail="Physical asset not found.")
    return await _confirm_on_chain(db, current_user, serial, body.tx_hash, client_ip)


@router.post("/chain-confirm/{serial}")
async def confirm_chain_effect(
    serial: str,
    body: MintConfirmRequest,
    current_user: User = Depends(get_onboarded_user),
    db: AsyncSession = Depends(get_db),
    client_ip: str = Depends(get_request_client_ip),
):
    """Confirm a mint (physical/digital) or a revision anchor after the approver signed the calldata."""
    return await _confirm_on_chain(db, current_user, serial, body.tx_hash, client_ip)


# Legacy parameterised download path declared late so it never shadows /document/download/pending.
@router.get("/document/download/{filename}")
async def download_document(filename: str, current_user: User = Depends(get_onboarded_user)):
    """Removed: this served the ORIGINAL, unwatermarked file on an on-chain access check
    alone (no approval, no Factor 3, no Download ID)."""
    raise HTTPException(
        status_code=410,
        detail="Direct vault downloads are disabled. Use the controlled download workflow: request -> approval -> Factor 3 fetch.",
    )


# Catch-all token route is declared LAST so it never shadows literal paths (e.g. /access-grants).
@router.get("/{token_id}")
async def get_asset(token_id: int, current_user: User = Depends(get_onboarded_user), db: AsyncSession = Depends(get_db)):
    """On-chain metadata for a registry asset the caller may see."""
    await _visible_asset_or_404(db, current_user, token_id=token_id)
    on_chain = contract_service.get_digital_asset(token_id)
    if not on_chain or not on_chain.get("is_digital"):
        on_chain = contract_service.get_asset(token_id)
    if not on_chain:
        raise HTTPException(status_code=404, detail="Asset not found on chain")
    return on_chain
