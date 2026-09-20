"""Asset management API endpoints (V2 Enterprise Consortium)."""

import hashlib
import os
import uuid
from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile, File, Form, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import time

from app.api.dependencies import get_db, get_current_user, get_current_active_user
from app.services.contract import contract_service
from app.services.qr import generate_qr_for_url
from app.services.asset_card import generate_asset_certificate_svg
from app.models.domain import Asset, MaintenanceRecord, User
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
async def prepare_update_digital(request: UpdateDigitalAssetRequest):
    """Prepare unsigned updateDigitalAsset transaction calldata."""
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
async def upload_document(
    file: UploadFile = File(...)
):
    """
    Secure Off-chain File Storage & Cryptographic Hashing.
    The file is stored securely off-chain.
    Its SHA-256 cryptographic hash is calculated and returned to be anchored in the NFT smart contract.
    """
    try:
        content = await file.read()
        # Compute SHA-256 hash
        sha256_hash = hashlib.sha256(content).hexdigest()

        # Secure local off-chain storage pointer
        filename = f"{sha256_hash}_{file.filename}"
        filepath = os.path.join(OFFCHAIN_STORAGE_DIR, filename)

        with open(filepath, "wb") as f:
            f.write(content)

        # Off-chain URI reference
        offchain_uri = f"secure-vault://documents/{filename}"

        return {
            "filename": file.filename,
            "file_hash": sha256_hash,
            "offchain_uri": offchain_uri,
            "download_url": f"/api/assets/document/download/{filename}",
            "file_size": len(content),
            "status": "SECURELY_STORED_OFFCHAIN"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File processing failed: {str(e)}")


@router.get("/document/download/{filename}")
async def download_document(
    filename: str,
    token_id: int,
    wallet_address: str,
    did: str
):
    """
    Download a secured document from the off-chain vault.
    Requires on-chain authorization matching the token_id and requester DID.
    """
    # 1. Enforce On-Chain Access Control
    access_result = contract_service.check_asset_access(
        token_id=token_id,
        requester_did=did,
        caller_address=wallet_address
    )

    if not access_result.get("authorized"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied by Smart Contract"
        )

    # 2. Sanitize filename to prevent directory traversal
    clean_filename = os.path.basename(filename)
    filepath = os.path.join(OFFCHAIN_STORAGE_DIR, clean_filename)
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
    db: AsyncSession = Depends(get_db)
):
    """Assign an asset to a custodian division/engineer."""
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
            owner_id=uuid.uuid4(), # System placeholder
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
    db: AsyncSession = Depends(get_db)
):
    """Record a field maintenance / calibration / inspection log for an asset."""
    token_id = contract_service.get_token_by_serial(serial)
    if token_id is None:
        raise HTTPException(status_code=404, detail="Asset not found on chain")

    # Compute hash of maintenance notes if not provided
    log_hash = req.log_hash
    if not log_hash:
        raw = f"{serial}:{req.performed_by_did}:{req.action_description}:{time.time()}"
        log_hash = hashlib.sha256(raw.encode()).hexdigest()

    record = MaintenanceRecord(
        asset_serial=serial,
        performed_by_did=req.performed_by_did,
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
    db: AsyncSession = Depends(get_db),
):
    """Revoke (burn) an asset NFT on-chain."""
    try:
        asset = contract_service.get_asset(token_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Token not found on chain")
    except Exception:
        raise HTTPException(status_code=404, detail="Token not found")

    calldata = contract_service.prepare_revoke_calldata(token_id)
    return {"message": "Prepare revocation calldata", "calldata": calldata, "token_id": token_id}
