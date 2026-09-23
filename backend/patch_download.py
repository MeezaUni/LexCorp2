import os

patch_content = """

@router.post("/document/download/request", response_model=DocumentActionRead)
async def request_document_download(
    request: DownloadRequest,
    req: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    \"\"\"Submit a request to download a digital document, pending Manager/Admin approval.\"\"\"
    
    # 1. MFA Factor 2 Enforcement
    if current_user.is_totp_factor2_enabled:
        if not request.totp_code or not verify_totp(current_user.totp_factor2_secret, request.totp_code):
            raise HTTPException(status_code=401, detail="Invalid Factor 2 TOTP code required for download requests")

    # 2. Asset Verification
    asset_res = await db.execute(select(Asset).filter(Asset.serial_number == request.asset_serial))
    asset = asset_res.scalar_one_or_none()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
        
    if asset.asset_type != "DIGITAL":
        raise HTTPException(status_code=400, detail="Only digital assets can be downloaded")

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
    \"\"\"Alias endpoint for approving download requests. Just routes to approve_document.\"\"\"
    return await approve_document(action_id, request, current_user, db)


@router.get("/document/download-token/{token}")
async def download_document_with_token(
    token: str,
    req: Request,
    db: AsyncSession = Depends(get_db)
):
    \"\"\"Use a single-use token to download a document, with dynamic watermarking applied on-the-fly.\"\"\"
    
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

"""

with open("C:/Users/MAK/Desktop/LexCorp2/backend/app/api/assets.py", "a") as f:
    f.write(patch_content)
