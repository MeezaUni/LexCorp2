"""Asset management API endpoints (V2 Enterprise Consortium)."""

import hashlib
import os
import uuid
from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile, File, Form, status, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import time
import secrets
from datetime import datetime, timedelta


from app.core.limiter import limiter
from app.api.dependencies import get_db, get_current_user, get_current_active_user
from app.core.config import settings
from app.services.contract import contract_service
from app.services.watermark import apply_watermark
from app.services.qr import generate_qr_for_url
from app.services.asset_card import generate_asset_certificate_svg
from app.models.domain import Asset, MaintenanceRecord, User, DocumentAction
from app.schemas.domain import DocumentProposalRequest, DocumentApprovalRequest, DocumentActionRead, DownloadRequest, DocumentRevisionRequest
from app.services.security import verify_totp
from sqlalchemy import select, desc

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

router = APIRouter(prefix="/assets", tags=["assets"])

# Storage directory for off-chain encrypted documents
OFFCHAIN_STORAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "offchain_storage")
os.makedirs(OFFCHAIN_STORAGE_DIR, exist_ok=True)


class MintRequest(BaseModel):
    to_address: str
    token_id: int
    serial_number: str
    owner_did: str


class DigitalMintRequest(BaseModel):
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
async def prepare_transfer(request: TransferRequest, current_user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
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
        res = await db.execute(select(Asset).filter(Asset.token_id == request.token_id))
        asset_db = res.scalar_one_or_none()
        if asset_db and asset_db.department and current_user.department:
            if asset_db.department != current_user.department:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Managers can only transfer assets within their own department ({current_user.department})."
                )

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
async def prepare_revoke(request: AccessCheckRequest, current_user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
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
        # Department check
        res = await db.execute(select(Asset).filter(Asset.token_id == token_id))
        asset_db = res.scalar_one_or_none()
        if asset_db and asset_db.department and current_user.department:
            if asset_db.department != current_user.department:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Managers can only revoke assets within their own department ({current_user.department})."
                )

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
async def prepare_mint(request: MintRequest, current_user: User = Depends(get_current_active_user)):
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
async def prepare_mint_digital(request: DigitalMintRequest, current_user: User = Depends(get_current_active_user)):
    """Prepare unsigned mint transaction calldata for digital asset with SHA-256 hash.

    Authorization Rules:
    - USER, MANAGER, ADMIN: Permitted to mint digital documents (self-sovereign document anchoring)
    - AUDITOR: Read-only, cannot mint
    """
    if current_user.role == "AUDITOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Auditors have read-only access and cannot mint digital assets."
        )

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
    token_id: int
    requester_did: str
    new_file_hash: str
    new_offchain_uri: str


@router.post("/update-digital/prepare", response_model=MintCalldataResponse)
async def prepare_update_digital(
    request: UpdateDigitalAssetRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Prepare unsigned updateDigitalAsset transaction calldata."""
    if current_user.role == "AUDITOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Auditors have read-only access and cannot update digital assets."
        )

    calldata = contract_service.prepare_update_digital_asset_calldata(
        request.token_id,
        request.requester_did,
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
    current_user: User = Depends(get_current_active_user),
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
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File size exceeds maximum permitted limit (50MB)."
            )

        # Compute SHA-256 hash
        sha256_hash = hashlib.sha256(content).hexdigest()

        # Sanitize original filename to prevent path traversal issues
        safe_original_name = os.path.basename(file.filename or "unnamed_document")
        filename = f"{sha256_hash}_{safe_original_name}"
        filepath = os.path.join(OFFCHAIN_STORAGE_DIR, filename)

        with open(filepath, "wb") as f:
            f.write(content)

        # Off-chain URI reference
        offchain_uri = f"secure-vault://documents/{filename}"

        return {
            "filename": safe_original_name,
            "file_hash": sha256_hash,
            "offchain_uri": offchain_uri,
            "download_url": f"/api/assets/document/download/{filename}",
            "file_size": len(content),
            "status": "SECURELY_STORED_OFFCHAIN"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File processing failed: {str(e)}")


@router.get("/document/download/{filename}")
async def download_document(
    filename: str,
    token_id: int,
    wallet_address: Optional[str] = None,
    did: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
):
    """
    Download a secured document from the off-chain vault.
    Enforces server-side identity derivation from validated JWT session.
    Verifies on-chain authorization matching the token_id and verified user identity.
    """
    # 1. Derive trusted identity strictly from authenticated session
    caller_address = current_user.wallet_address
    requester_did = current_user.did or f"did:ethr:13371:{current_user.wallet_address.lower()}"

    # 2. Enforce On-Chain Access Control
    access_result = contract_service.check_asset_access(
        token_id=token_id,
        requester_did=requester_did,
        caller_address=caller_address
    )

    if not access_result.get("authorized"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied by Smart Contract"
        )

    # 3. Sanitize filename to prevent directory traversal
    clean_filename = os.path.basename(filename)
    filepath = os.path.abspath(os.path.join(OFFCHAIN_STORAGE_DIR, clean_filename))

    # Ensure filepath stays strictly within OFFCHAIN_STORAGE_DIR
    if not filepath.startswith(os.path.abspath(OFFCHAIN_STORAGE_DIR)):
        raise HTTPException(status_code=400, detail="Invalid filename path")

    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Document not found in off-chain vault")

    original_name = clean_filename.split("_", 1)[-1] if "_" in clean_filename else clean_filename
    return FileResponse(filepath, filename=original_name)


@router.post("/check-access")
async def check_access(request: AccessCheckRequest):
    """
    Verify Asset-Level Access Control against the on-chain Smart Contract.
    Enforces authorization on the blockchain layer.
    """
    result = contract_service.check_asset_access(
        request.token_id,
        request.requester_did,
        request.caller_address
    )
    return {
        "token_id": request.token_id,
        "requester_did": request.requester_did,
        "authorized": result["authorized"],
        "permission_level": result["level"],
        "message": "Access Granted" if result["authorized"] else "Access Denied by Smart Contract"
    }


@router.get("/registry")
async def get_all_assets(db: AsyncSession = Depends(get_db)):
    """Fetch all minted and active assets in the system across all owners."""
    # Check in-memory cache (60s TTL)
    cached = _get_cache("registry")
    if cached is not None:
        return cached
    from sqlalchemy import select
    from app.models.domain import AuditEvent, Asset

    candidate_serials = set()

    # 1. Query database for all known assets and minted audit events
    try:
        query_assets = select(Asset.serial_number, Asset.token_id)
        result = await db.execute(query_assets)
        for row in result.fetchall():
            if row[0]:
                candidate_serials.add(row[0])

        query_events = select(AuditEvent.asset_serial).filter(
            AuditEvent.event_type.in_(["AssetMinted", "DigitalAssetMinted", "AssetTransferred"])
        ).distinct()
        result2 = await db.execute(query_events)
        for row in result2.fetchall():
            if row[0]:
                candidate_serials.add(row[0])
    except Exception:
        pass

    assets = []
    for serial in candidate_serials:
        try:
            # Get token_id from serial number (database has token_id for all assets)
            result = await db.execute(select(Asset.token_id).filter(Asset.serial_number == serial))
            asset_row = result.scalar_one_or_none()
            if not asset_row:
                # Fallback: try contract lookup if not in DB
                token_id = contract_service.get_token_by_serial(serial)
                if token_id is None:
                    continue
            else:
                token_id = asset_row

            # Check if asset is burned/revoked (owner is 0x0)
            try:
                owner = contract_service.contract.functions.ownerOf(token_id).call()
                if owner == "0x0000000000000000000000000000000000000000":
                    continue
            except Exception:
                # Assume burned if owner check fails
                continue

            # Try fetching digital asset metadata first
            asset = contract_service.get_digital_asset(token_id)
            if not asset or not asset.get("is_digital"):
                # Use DB record if available to avoid contract call
                result_db = await db.execute(select(Asset).filter(Asset.token_id == token_id))
                asset_db = result_db.scalar_one_or_none()
                if asset_db:
                    asset = {
                        "token_id": token_id,
                        "serial_number": asset_db.serial_number,
                        "metadata_cid": asset_db.metadata_cid,
                        "is_digital": False
                    }
                else:
                    asset = contract_service.get_asset(token_id)

            if asset:
                assets.append(asset)
        except Exception:
            continue

    assets.sort(key=lambda a: a.get("token_id", 0))
    _set_cache("registry", assets)
    return assets

@router.get("/by-owner/{owner_address}")
async def get_assets_by_owner(owner_address: str, db: AsyncSession = Depends(get_db)):
    """Fetch all assets owned by OR explicitly granted to a specific wallet address/DID."""
    from web3 import Web3
    from sqlalchemy import select, or_, func
    from app.models.domain import AuditEvent, Asset, User

    try:
        owner_address = Web3.to_checksum_address(owner_address)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid wallet address")

    owner_did = f"did:ethr:{contract_service.w3.eth.chain_id}:{owner_address.lower()}"
    candidate_items = []  # list of (serial, token_id)
    seen_serials = set()

    # 1. Query DB for all known candidate assets
    try:
        query_assets = select(Asset.serial_number, Asset.token_id)
        res1 = await db.execute(query_assets)
        for row in res1.fetchall():
            if row[0] and row[0] not in seen_serials:
                candidate_items.append((row[0], row[1]))
                seen_serials.add(row[0])

        query_events = select(AuditEvent.asset_serial).filter(
            AuditEvent.event_type.in_(["AssetMinted", "DigitalAssetMinted", "AssetTransferred", "AccessPermissionGranted"])
        ).distinct()
        res2 = await db.execute(query_events)
        for row in res2.fetchall():
            if row[0] and row[0] not in seen_serials:
                candidate_items.append((row[0], None))
                seen_serials.add(row[0])
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Error fetching candidate assets from DB: %s", e)

    assets = []
    for serial, token_id in candidate_items:
        try:
            if token_id is None:
                token_id = contract_service.get_token_by_serial(serial)
                if token_id is None:
                    continue

            try:
                current_owner = contract_service.contract.functions.ownerOf(token_id).call()
            except Exception:
                continue  # Burned or doesn't exist

            is_owner = (current_owner.lower() == owner_address.lower())

            # Check on-chain access permission
            access_check = contract_service.check_asset_access(
                token_id=token_id,
                requester_did=owner_did,
                caller_address=owner_address
            )
            is_authorized = access_check.get("authorized", False)

            if is_owner or is_authorized:
                asset = contract_service.get_digital_asset(token_id)
                if not asset or not asset.get("is_digital"):
                    asset = contract_service.get_asset(token_id)
                if asset:
                    # Enrich asset with permission level & ownership info
                    asset["is_owner"] = is_owner
                    asset["permission_level"] = "OWNER" if is_owner else ("READ_WRITE" if access_check.get("level") == 2 else "READ")
                    assets.append(asset)
        except Exception:
            continue

    assets.sort(key=lambda a: a.get("token_id", 0))
    return assets


@router.get("/serial/{serial}")
async def get_asset_by_serial(serial: str):
    """Look up asset by serial number."""
    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None:
        raise HTTPException(status_code=404, detail="Serial not found")
    asset = contract_service.get_digital_asset(token_id)
    if not asset or not asset.get("is_digital"):
        asset = contract_service.get_asset(token_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset metadata not found")
    return asset


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
async def get_asset_qr(serial: str, host: Optional[str] = "localhost:5173"):
    """Generate and return a QR code PNG pointing to the frontend verify URL for this asset.
    Automatically resolves localhost/127.0.0.1 to the LAN IP so mobile devices can scan and view it.
    """
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
async def get_asset_qr_by_token(token_id: int, host: Optional[str] = "localhost:5173"):
    """Generate a QR code for the stable token-ID verification URL."""
    asset = contract_service.get_digital_asset(token_id) or contract_service.get_asset(token_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found on chain")
    target_host = host or "localhost:5173"
    lan_ip = get_lan_ip()
    target_host = target_host.replace("localhost", lan_ip).replace("127.0.0.1", lan_ip)
    png_bytes = generate_qr_for_url(f"http://{target_host}/verify/token/{token_id}")
    return Response(content=png_bytes, media_type="image/png")


@router.get("/{token_id}")
async def get_asset(token_id: int):
    """Fetch on-chain asset metadata."""
    asset = contract_service.get_digital_asset(token_id)
    if not asset or not asset.get("is_digital"):
        asset = contract_service.get_asset(token_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


class AssignCustodianRequest(BaseModel):
    custodian_did: str
    custodian_department: Optional[str] = "BEL Field Engineering"
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
    host: Optional[str] = "localhost:5173",
    db: AsyncSession = Depends(get_db)
):
    """Generate and return a high-resolution printable SVG Defense Asset Certificate for the given asset."""
    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None:
        raise HTTPException(status_code=404, detail="Asset with this serial not found on chain")

    # Fetch on-chain metadata
    on_chain = contract_service.get_digital_asset(token_id)
    if not on_chain or not on_chain.get("is_digital"):
        on_chain = contract_service.get_asset(token_id)

    # Fetch DB metadata (if available) for name, custodian, and lifecycle status
    res = await db.execute(select(Asset).filter(Asset.serial_number == serial))
    asset_db = res.scalar_one_or_none()

    owner_did = on_chain.get("owner_did") if on_chain else "did:ethr:13371:unknown"
    name = asset_db.name if asset_db and asset_db.name else f"BEL Defense Hardware {serial}"
    asset_type = asset_db.asset_type if asset_db and asset_db.asset_type else "EQUIPMENT"
    custodian_did = asset_db.custodian_did if asset_db else None
    custodian_dept = asset_db.custodian_department if asset_db else "BEL Radar Division"
    file_hash = (on_chain.get("file_hash") if on_chain else None) or (asset_db.file_hash if asset_db else None)
    lifecycle_status = asset_db.lifecycle_status if asset_db else "VERIFIED"

    # Resolve LAN IP for mobile scan compatibility
    target_host = host
    if target_host:
        lan_ip = get_lan_ip()
        if "localhost" in target_host:
            target_host = target_host.replace("localhost", lan_ip)
        elif "127.0.0.1" in target_host:
            target_host = target_host.replace("127.0.0.1", lan_ip)

    verify_url = f"http://{target_host}/verify/{serial}"

    svg_data = generate_asset_certificate_svg(
        serial_number=serial,
        token_id=token_id,
        name=name,
        asset_type=asset_type,
        owner_did=owner_did,
        custodian_did=custodian_did,
        custodian_department=custodian_dept,
        file_hash=file_hash,
        lifecycle_status=lifecycle_status,
        verify_url=verify_url
    )

    return Response(content=svg_data, media_type="image/svg+xml")


@router.post("/serial/{serial}/assign")
async def assign_asset_custodian(
    serial: str,
    req: AssignCustodianRequest,
    current_user: User = Depends(get_current_active_user),
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
        # If target department is specified, it must match manager's department
        if req.custodian_department and req.custodian_department != current_user.department:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Managers can only assign custody to their own department ({current_user.department})."
            )

    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None:
        raise HTTPException(status_code=404, detail="Asset not found on chain")

    res = await db.execute(select(Asset).filter(Asset.serial_number == serial))
    asset_db = res.scalar_one_or_none()

    if not asset_db:
        # Create DB record if not exists
        asset_db = Asset(
            serial_number=serial,
            token_id=token_id,
            owner_id=current_user.id,
            custodian_did=req.custodian_did,
            custodian_department=req.custodian_department,
            lifecycle_status=req.lifecycle_status or "ASSIGNED"
        )
        db.add(asset_db)
    else:
        asset_db.custodian_did = req.custodian_did
        asset_db.custodian_department = req.custodian_department
        asset_db.lifecycle_status = req.lifecycle_status or "ASSIGNED"

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
    current_user: User = Depends(get_current_active_user),
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

    # Verify authorization: ADMIN/MANAGER can maintain any asset, USER must be owner or granted access
    if current_user.role not in ("ADMIN", "MANAGER"):
        access = contract_service.check_asset_access(
            token_id=token_id,
            requester_did=performed_by_did,
            caller_address=current_user.wallet_address
        )
        if not access.get("authorized"):
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
    db: AsyncSession = Depends(get_db)
):
    """Retrieve full chronological maintenance logs for an asset."""
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
    db: AsyncSession = Depends(get_db)
):
    """Comprehensive on-chain and database verification payload for QR verification page."""
    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None:
        raise HTTPException(status_code=404, detail="Asset not found on Hyperledger Besu blockchain")

    # 1. On-Chain Smart Contract State
    on_chain = contract_service.get_digital_asset(token_id)
    if not on_chain or not on_chain.get("is_digital"):
        on_chain = contract_service.get_asset(token_id)

    # 2. Database Metadata & Custody
    res = await db.execute(select(Asset).filter(Asset.serial_number == serial))
    asset_db = res.scalar_one_or_none()

    # 3. Maintenance History
    maint_res = await db.execute(
        select(MaintenanceRecord)
        .filter(MaintenanceRecord.asset_serial == serial)
        .order_by(desc(MaintenanceRecord.created_at))
    )
    maintenance_records = [
        {
            "id": str(r.id),
            "performed_by_did": r.performed_by_did,
            "action_description": r.action_description,
            "notes": r.notes,
            "log_hash": r.log_hash,
            "created_at": r.created_at.isoformat() if r.created_at else None
        }
        for r in maint_res.scalars().all()
    ]

    return {
        "serial_number": serial,
        "token_id": token_id,
        "on_chain_verified": True,
        "contract_address": contract_service.contract_address,
        "chain_id": contract_service.w3.eth.chain_id,
        "name": asset_db.name if asset_db and asset_db.name else f"BEL Defense Hardware {serial}",
        "asset_type": asset_db.asset_type if asset_db and asset_db.asset_type else "EQUIPMENT",
        "owner_address": on_chain.get("owner_address") if on_chain else None,
        "owner_did": on_chain.get("owner_did") if on_chain else "did:ethr:13371:unknown",
        "custodian_did": asset_db.custodian_did if asset_db else None,
        "custodian_department": asset_db.custodian_department if asset_db else "BEL Radar Division",
        "file_hash": (on_chain.get("file_hash") if on_chain else None) or (asset_db.file_hash if asset_db else None),
        "offchain_uri": on_chain.get("offchain_uri") if on_chain else None,
        "lifecycle_status": asset_db.lifecycle_status if asset_db else "VERIFIED",
        "is_digital": on_chain.get("is_digital", False) if on_chain else False,
        "maintenance_history": maintenance_records
    }


@router.get("/token/{token_id}/verify-data")
async def get_asset_full_verification_data_by_token(
    token_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Resolve verification by stable token ID instead of a serial string."""
    on_chain = contract_service.get_digital_asset(token_id)
    if not on_chain or not on_chain.get("is_digital"):
        on_chain = contract_service.get_asset(token_id)
    if not on_chain:
        raise HTTPException(status_code=404, detail="Asset not found on Hyperledger Besu blockchain")
    return await get_asset_full_verification_data(on_chain["serial_number"], db)


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    token_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke (burn) an asset NFT on-chain."""
    if current_user.role == "AUDITOR":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Auditors cannot revoke assets.")
    try:
        asset = contract_service.get_asset(token_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Token not found on chain")
    except Exception:
        raise HTTPException(status_code=404, detail="Token not found")

    calldata = contract_service.prepare_revoke_calldata(token_id)
    return {"message": "Prepare revocation calldata", "calldata": calldata, "token_id": token_id}

@router.post("/document/propose", response_model=DocumentActionRead)
async def propose_document_creation(
    request: DocumentProposalRequest, 
    current_user: User = Depends(get_current_active_user), 
    db: AsyncSession = Depends(get_db)
):
    """Propose a new digital document for creation and approval."""
    if current_user.role == "AUDITOR":
        raise HTTPException(status_code=403, detail="Auditors cannot propose documents.")

    dept = request.department or current_user.department
    if current_user.role == "USER" and dept != current_user.department:
        raise HTTPException(status_code=403, detail="Users can only propose documents for their assigned department.")

    if current_user.is_totp_factor2_enabled:
        if not request.totp_code or not verify_totp(current_user.totp_factor2_secret, request.totp_code):
            raise HTTPException(status_code=401, detail="Invalid Factor 2 (View/Submission) TOTP code.")

    res = await db.execute(select(Asset).filter(Asset.serial_number == request.serial_number))
    if res.scalar_one_or_none():
         raise HTTPException(status_code=400, detail="Asset serial number already exists.")

    action_id_str = f"CRT-{uuid.uuid4().hex[:12].upper()}"
    
    # Temporarily allocate a unique mock token_id for the draft. Real token_id will be minted later.
    import random
    temp_token_id = random.randint(1000000000, 2000000000)

    draft_asset = Asset(
        token_id=temp_token_id, 
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

    action = DocumentAction(
        action_id=action_id_str,
        action_type="CREATION",
        asset_id=draft_asset.id,
        asset_serial=request.serial_number,
        actor_id=current_user.id,
        actor_did=current_user.did,
        status="PENDING",
        purpose=request.purpose,
        details={"name": request.name, "file_hash": request.file_hash, "offchain_uri": request.offchain_uri}
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/document/pending", response_model=list[DocumentActionRead])
async def get_pending_documents(
    action_type: Optional[str] = None,
    current_user: User = Depends(get_current_active_user), 
    db: AsyncSession = Depends(get_db)
):
    """Retrieve pending document actions awaiting approval."""
    query = select(DocumentAction).filter(DocumentAction.status == "PENDING")
    if action_type:
        query = query.filter(DocumentAction.action_type == action_type)
        
    if current_user.role == "USER":
        query = query.filter(DocumentAction.actor_id == current_user.id)
    elif current_user.role == "MANAGER":
        query = query.join(Asset, DocumentAction.asset_id == Asset.id).filter(Asset.department == current_user.department)
        
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
async def approve_document(
    action_id: str,
    request: DocumentApprovalRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
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

    if current_user.role == "MANAGER":
        if asset.department != current_user.department:
            raise HTTPException(status_code=403, detail="Managers can only approve actions for their own department.")

    if current_user.is_totp_factor3_enabled:
        if not request.totp_code or not verify_totp(current_user.totp_factor3_secret, request.totp_code):
            raise HTTPException(status_code=401, detail="Invalid Factor 3 TOTP code.")

    if request.decision.upper() == "APPROVE":
        action.status = "APPROVED"
        action.approver_id = current_user.id
        action.approver_did = current_user.did
        asset.approval_status = "APPROVED"

        calldata = None
        download_token = None
        download_url = None
        token_expires_at = None

        if action.action_type == "CREATION":
            owner_address = action.actor_did.split(":")[-1]
            calldata = contract_service.prepare_mint_digital_calldata(
                to_address=owner_address,
                token_id=asset.token_id,
                serial_number=asset.serial_number,
                owner_did=action.actor_did,
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

            owner_address = action.actor_did.split(":")[-1]
            try:
                calldata = contract_service.prepare_update_digital_asset_calldata(
                    token_id=parent_asset.token_id if (asset.parent_asset_id and parent_asset) else asset.token_id,
                    requester_did=action.actor_did,
                    new_file_hash=asset.file_hash or "",
                    new_offchain_uri=asset.metadata_cid or ""
                )
            except Exception:
                calldata = contract_service.prepare_mint_digital_calldata(
                    to_address=owner_address,
                    token_id=asset.token_id,
                    serial_number=asset.serial_number,
                    owner_did=action.actor_did,
                    file_hash=asset.file_hash or "",
                    offchain_uri=asset.metadata_cid or ""
                )
        elif action.action_type == "DOWNLOAD":
            download_token = f"dlt_{secrets.token_urlsafe(32)}"
            token_expires_at = datetime.utcnow() + timedelta(minutes=15)
            action.download_token = download_token
            action.token_expires_at = token_expires_at
            download_url = f"/api/assets/document/download-token/{download_token}"

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
        asset.approval_status = "REJECTED"
        await db.commit()

        return ApprovalCalldataResponse(decision="REJECT", status="REJECTED")
    else:
        raise HTTPException(status_code=400, detail="Invalid decision.")


@router.get("/document/view/{action_id}")
async def view_digital_document(
    action_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Securely render a document with on-the-fly dynamic watermarking."""
    res = await db.execute(select(DocumentAction).filter(DocumentAction.action_id == action_id))
    action = res.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Document action not found.")
        
    asset_res = await db.execute(select(Asset).filter(Asset.id == action.asset_id))
    asset = asset_res.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    # Authorization logic
    if current_user.role == "USER" and action.actor_id != current_user.id:
        raise HTTPException(status_code=403, detail="Users can only view their own documents.")
    if current_user.role == "MANAGER" and asset.department != current_user.department:
        raise HTTPException(status_code=403, detail="Managers can only view documents in their own department.")

    if not asset.metadata_cid:
        raise HTTPException(status_code=404, detail="No offchain URI stored for this document.")

    offchain_uri = asset.metadata_cid.replace("secure-vault://", "").replace("ipfs://", "").lstrip("/\\")
    filepath = os.path.abspath(os.path.join(OFFCHAIN_STORAGE_DIR, offchain_uri))
    if not os.path.exists(filepath):
        # Fallback check for basename directly in OFFCHAIN_STORAGE_DIR
        alt_filepath = os.path.abspath(os.path.join(OFFCHAIN_STORAGE_DIR, os.path.basename(offchain_uri)))
        if os.path.exists(alt_filepath):
            filepath = alt_filepath
    
    # Check if the file Actually exists
    if not os.path.exists(filepath):
        # We'll just generate a dummy image in memory if not for PoC
        try:
            from PIL import Image
            import io
            img = Image.new('RGB', (800, 600), color=(200, 200, 200))
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            file_bytes = buf.getvalue()
        except ImportError:
            file_bytes = b"MOCK_DOCUMENT_CONTENT"
    else:
        with open(filepath, "rb") as f:
            file_bytes = f.read()

    watermarked_bytes = await apply_watermark(
        file_bytes, 
        user_did=current_user.did, 
        department=current_user.department or "ALL"
    )

    # Log the view action
    # For Phase 5 we reuse DocumentAction with action_type=VIEW
    log_action = DocumentAction(
        action_id=f"VW-{uuid.uuid4().hex[:12].upper()}",
        action_type="VIEW",
        asset_id=asset.id,
        asset_serial=asset.serial_number,
        actor_id=current_user.id,
        actor_did=current_user.did,
        status="COMPLETED",
        purpose="View Document",
        client_ip="internal_log"
    )
    db.add(log_action)
    await db.commit()

    return Response(content=watermarked_bytes, media_type="application/octet-stream")


@router.get("/document/logs/{asset_serial}", response_model=list[DocumentActionRead])
async def get_document_view_logs(
    asset_serial: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve viewing audit logs for a specific document."""
    if current_user.role not in ["ADMIN", "MANAGER", "AUDITOR"]:
        raise HTTPException(status_code=403, detail="Not authorized to view audit logs.")

    asset_res = await db.execute(select(Asset).filter(Asset.serial_number == asset_serial))
    asset = asset_res.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    if current_user.role == "MANAGER" and asset.department != current_user.department:
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
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Submit a request to download a digital document, pending Manager/Admin approval."""
    
    # 1. MFA Factor 2 Enforcement
    if current_user.is_totp_factor2_enabled:
        if not request.totp_code or not verify_totp(current_user.totp_factor2_secret, request.totp_code):
            raise HTTPException(status_code=401, detail="Invalid Factor 2 TOTP code required for download requests")

    # 2. Asset Verification
    asset_res = await db.execute(select(Asset).filter(Asset.serial_number == request.asset_serial))
    asset = asset_res.scalar_one_or_none()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    if asset.asset_type not in ["DIGITAL", "DOCUMENT"]:
        raise HTTPException(status_code=400, detail="Only digital documents can be downloaded")

    # 3. RBAC & Scoping
    if current_user.role == "USER":
        # A USER can only download from their assigned department or if they are owner/custodian
        if (asset.department != current_user.department and 
            str(asset.owner_id) != str(current_user.id) and 
            str(asset.custodian_id) != str(current_user.id)):
            raise HTTPException(status_code=403, detail="Users can only request downloads for their assigned department or owned assets")
            
    if current_user.role == "AUDITOR":
        raise HTTPException(status_code=403, detail="Auditors are not permitted to download operational documents")

    # 4. Action Creation
    action_id = f"DL-{uuid.uuid4().hex[:8].upper()}"
    new_action = DocumentAction(
        action_id=action_id,
        action_type="DOWNLOAD",
        asset_id=asset.id,
        asset_serial=asset.serial_number,
        actor_id=current_user.id,
        actor_did=current_user.did,
        status="PENDING",
        purpose=request.purpose,
        client_ip=req.client.host if req.client else "unknown"
    )
    
    db.add(new_action)
    await db.commit()
    await db.refresh(new_action)
    
    return new_action


@router.post("/document/download/approve/{action_id}")
async def approve_document_download(
    action_id: str,
    request: DocumentApprovalRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Alias endpoint for approving download requests. Just routes to approve_document."""
    return await approve_document(action_id, request, current_user, db)


@router.post("/document/revise", response_model=DocumentActionRead)
async def revise_document(
    request: DocumentRevisionRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Propose a modification/revision to an existing digital document."""
    if current_user.role == "AUDITOR":
        raise HTTPException(status_code=403, detail="Auditors cannot revise documents.")

    # 1. Fetch parent asset
    parent_res = await db.execute(select(Asset).filter(Asset.serial_number == request.parent_asset_serial))
    parent_asset = parent_res.scalar_one_or_none()
    if not parent_asset:
        raise HTTPException(status_code=404, detail="Parent asset not found.")

    if parent_asset.asset_type not in ["DIGITAL", "DOCUMENT"]:
        raise HTTPException(status_code=400, detail="Only digital documents can be revised.")

    # 2. Check department scoping for USER / MANAGER
    if current_user.role == "USER":
        if (parent_asset.department and parent_asset.department != current_user.department and
            str(parent_asset.owner_id) != str(current_user.id) and
            str(parent_asset.custodian_id) != str(current_user.id)):
            raise HTTPException(status_code=403, detail="Users can only revise documents in their own department.")
    elif current_user.role == "MANAGER":
        if parent_asset.department and current_user.department and parent_asset.department != current_user.department:
            raise HTTPException(status_code=403, detail="Managers can only revise documents in their own department.")

    # 3. Factor 2 TOTP Check
    if current_user.is_totp_factor2_enabled:
        if not request.totp_code or not verify_totp(current_user.totp_factor2_secret, request.totp_code):
            raise HTTPException(status_code=401, detail="Invalid Factor 2 (View/Submission) TOTP code.")

    # 4. Uniqueness check for new serial number
    res = await db.execute(select(Asset).filter(Asset.serial_number == request.new_serial_number))
    if res.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Asset serial number already exists.")

    action_id_str = f"MOD-{uuid.uuid4().hex[:12].upper()}"
    import random
    temp_token_id = random.randint(1000000000, 2000000000)

    # 5. Create new draft child asset
    revised_asset = Asset(
        token_id=temp_token_id,
        serial_number=request.new_serial_number,
        name=request.name,
        asset_type=parent_asset.asset_type,
        file_hash=request.new_file_hash,
        metadata_cid=request.new_offchain_uri,
        owner_id=current_user.id,
        department=parent_asset.department or current_user.department,
        is_physical=False,
        lifecycle_status="PENDING_APPROVAL",
        approval_status="PENDING_APPROVAL",
        parent_asset_id=parent_asset.id,
        action_id=action_id_str,
        action_type="MODIFICATION"
    )
    db.add(revised_asset)
    await db.flush()

    action = DocumentAction(
        action_id=action_id_str,
        action_type="MODIFICATION",
        asset_id=revised_asset.id,
        asset_serial=request.new_serial_number,
        actor_id=current_user.id,
        actor_did=current_user.did,
        status="PENDING",
        purpose=request.purpose,
        details={
            "name": request.name,
            "parent_asset_serial": parent_asset.serial_number,
            "parent_asset_id": str(parent_asset.id),
            "file_hash": request.new_file_hash,
            "offchain_uri": request.new_offchain_uri
        }
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/document/lineage/{asset_serial}")
async def get_document_lineage(
    asset_serial: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Fetch complete revision tree/history for a document."""
    res = await db.execute(select(Asset).filter(Asset.serial_number == asset_serial))
    asset = res.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

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
    current_user: User = Depends(get_current_active_user),
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
    is_in_department = (
        asset.department and current_user.department and
        asset.department == current_user.department
    )

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
            "mac_address": asset.mac_address,
            "device_unique_address": asset.device_unique_address,
            "location": asset.location,
            "owner_id": str(asset.owner_id),
            "custodian_id": str(asset.custodian_id) if asset.custodian_id else None,
            "custodian_did": asset.custodian_did,
            "action_id": asset.action_id,
            "action_type": asset.action_type
        })

    return data


@router.get("/document/download-token/{token}")
async def download_document_with_token(
    token: str,
    req: Request,
    db: AsyncSession = Depends(get_db)
):
    """Use a single-use token to download a document, with dynamic watermarking applied on-the-fly."""
    
    # 1. Token validation
    res = await db.execute(select(DocumentAction).filter(DocumentAction.download_token == token))
    action = res.scalar_one_or_none()
    
    if not action:
        raise HTTPException(status_code=404, detail="Invalid or expired download token")
        
    if action.status != "APPROVED":
        raise HTTPException(status_code=403, detail="Download request is not in APPROVED status")
        
    if action.token_expires_at and action.token_expires_at < datetime.utcnow():
        raise HTTPException(status_code=403, detail="Download token has expired")

    # 2. Consume token (single use)
    action.status = "COMPLETED"
    action.download_token = None # Prevent reuse
    
    # 3. Retrieve asset and file
    asset_res = await db.execute(select(Asset).filter(Asset.id == action.asset_id))
    asset = asset_res.scalar_one_or_none()
    
    if not asset or not asset.metadata_cid:
        await db.commit() # Save token consumption early
        raise HTTPException(status_code=404, detail="Document file reference not found")

    await db.commit()
    
    # Resolve file path
    vault_uri = asset.metadata_cid
    # Format: secure-vault://documents/file.pdf
    if not vault_uri.startswith("secure-vault://"):
        raise HTTPException(status_code=500, detail="Invalid storage URI scheme")
        
    file_rel_path = vault_uri.replace("secure-vault://", "")
    file_path = os.path.join(OFFCHAIN_STORAGE_DIR, file_rel_path)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Document file missing in vault")
        
    # 4. Load file, apply dynamic watermark (DID + Dept + Purpose + Token tracking + Time)
    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")
        
    watermark_dept = asset.department or "GENERAL"
    
    # In a real system, the watermark schema here might be more detailed for downloads
    # but we can reuse the generic dynamic watermarker which takes (bytes, DID, Dept).
    # Since we want it robust, we'll call apply_watermark.
    watermarked_bytes = await apply_watermark(file_bytes, action.actor_did, watermark_dept)

    # Note: A bespoke download watermark could include purpose and token.
    # We will just stream back what apply_watermark outputs.
    
    filename = os.path.basename(file_path)
    # If the watermark converted a PDF to PNG, we'd need to adjust name/mime, but for PoC we keep it simple.
    
    return Response(
        content=watermarked_bytes, 
        media_type="application/octet-stream", 
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

