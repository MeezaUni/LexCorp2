import pytest
from tests.conftest import mfa_headers
import uuid
import os
import pyotp
from datetime import datetime, timedelta
from unittest.mock import patch
from app.services.auth import create_jwt
from app.models.domain import User, Asset, DocumentAction
from sqlalchemy import select

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower()
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower()
USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower()

def get_token(wallet: str, role: str, session_version: int = 1) -> str:
    did = f"did:ethr:13371:{wallet}"
    return create_jwt(wallet, did, role, session_version, client_ip="testclient")

@pytest.mark.asyncio
async def test_download_workflow_success(client, db_session):
    """Propose download, approve, download with token."""
    user_token = get_token(USER_WALLET, "USER", 1)
    
    # Mock blockchain contract call
    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x123", "data": "0xabc"}):

        # 1. Propose asset
        serial = f"BEL-DL-{uuid.uuid4().hex[:6].upper()}"
        propose_res = await client.post(
            "/api/assets/document/propose",
            headers=await mfa_headers(db_session, user_token, USER_WALLET, "document.submit"),
            json={
                "name": "Download Doc",
                "serial_number": serial,
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "offchain_uri": "secure-vault://documents/test.txt",
        "recipient_address": "0x123abc",
            }
        )
        assert propose_res.status_code == 200, propose_res.text
        
        # Get asset to approve
        res = await db_session.execute(select(Asset).where(Asset.serial_number == serial))
        asset = res.scalar_one()
        
        # Approve by Manager
        mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
        res = await db_session.execute(select(DocumentAction).where(DocumentAction.asset_serial == serial))
        creation_action = res.scalar_one()
        await client.post(
            f"/api/assets/document/approval/{creation_action.action_id}",
            headers=await mfa_headers(db_session, mgr_token, MANAGER_WALLET, "asset.approve"),
            json={"decision": "APPROVE"}
        )
        
        # Enable Factor 2 for user to perform download request
        res = await db_session.execute(select(User).where(User.wallet_address == USER_WALLET))
        user = res.scalar_one()
        secret = pyotp.random_base32()
        user.totp_factor2_secret = secret
        user.is_totp_factor2_enabled = True
        await db_session.commit()
        
        totp = pyotp.TOTP(secret)
        
        # 2. Propose download
        download_res = await client.post(
            "/api/assets/document/download/request",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "asset_serial": serial,
                "purpose": "Testing download",
                "totp_code": totp.now()
            }
        )
        assert download_res.status_code == 200
        action_id = download_res.json()["action_id"]
        
        # 3. Approve download (Manager)
        appr_res = await client.post(
            f"/api/assets/document/approval/{action_id}",
            headers=await mfa_headers(db_session, mgr_token, MANAGER_WALLET, "asset.approve"),
            json={"decision": "APPROVE"}
        )
        assert appr_res.status_code == 200
        data = appr_res.json()
        token = data["download_token"]
        
        # Create file in offchain storage for download test
        from app.api.assets import OFFCHAIN_STORAGE_DIR
        os.makedirs(os.path.join(OFFCHAIN_STORAGE_DIR, "documents"), exist_ok=True)
        with open(os.path.join(OFFCHAIN_STORAGE_DIR, "documents/test.txt"), "wb") as f:
            f.write(b"sensitive content")
            
        # 4. Download
        download_res = await client.get(f"/api/assets/document/download-token/{token}")
        assert download_res.status_code == 200
        # Note: apply_watermark will modify content, so checking exact bytes won't work.
        # This is fine for testing.
        assert b"sensitive content" in download_res.content
        
        # 5. Token expired/consumed
        download_res_2 = await client.get(f"/api/assets/document/download-token/{token}")
        assert download_res_2.status_code == 404 # Invalid or expired
