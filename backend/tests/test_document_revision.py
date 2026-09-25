"""Test suite for Phase 7: Document Revision Workflow (MOD-)."""

import pytest
from tests.conftest import mfa_headers
import uuid
import os
import pyotp
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
async def test_revise_document_success(client, db_session):
    """Propose revision, approve, and verify lineage."""
    user_token = get_token(USER_WALLET, "USER", 1)

    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x123", "data": "0xabc"}), \
         patch("app.services.contract.contract_service.prepare_update_digital_asset_calldata", return_value={"to": "0x124", "data": "0xdef"}):

        # 1. Propose and approve original asset
        serial1 = f"BEL-DOC-{uuid.uuid4().hex[:6].upper()}"
        propose_res1 = await client.post(
            "/api/assets/document/propose",
            headers=await mfa_headers(db_session, user_token, USER_WALLET, "document.submit"),
            json={
                "name": "Original Doc v1",
                "serial_number": serial1,
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "offchain_uri": "secure-vault://documents/doc_v1.txt",
        "recipient_address": "0x123abc",
                "department": "Avionics"
            }
        )
        assert propose_res1.status_code == 200

        # Approve original
        mgr_token = get_token(MANAGER_WALLET, "MANAGER", 8)
        res = await db_session.execute(select(DocumentAction).where(DocumentAction.asset_serial == serial1))
        creation_action = res.scalar_one()
        appr_res1 = await client.post(
            f"/api/assets/document/approval/{creation_action.action_id}",
            headers=await mfa_headers(db_session, mgr_token, MANAGER_WALLET, "asset.approve"),
            json={"decision": "APPROVE"}
        )
        assert appr_res1.status_code == 200

        # Modification requires Factor 3 (spec: TOTP 3 OR Passkey 3)
        res = await db_session.execute(select(User).where(User.wallet_address == USER_WALLET))
        user = res.scalar_one()
        secret = pyotp.random_base32()
        user.totp_factor3_secret = secret
        user.is_totp_factor3_enabled = True
        await db_session.commit()

        totp = pyotp.TOTP(secret)

        # 2. Propose revision (MOD-)
        serial2 = f"BEL-DOC-{uuid.uuid4().hex[:6].upper()}"
        revise_res = await client.post(
            "/api/assets/document/revise",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "parent_asset_serial": serial1,
                "name": "Revised Doc v2",
                "new_serial_number": serial2,
                "new_file_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
                "new_offchain_uri": "secure-vault://documents/doc_v2.txt",
                "purpose": "Updated specifications",
                "totp_code": totp.now()
            }
        )
        assert revise_res.status_code == 200, revise_res.text
        action_id = revise_res.json()["action_id"]
        assert action_id.startswith("MOD-")

        # 3. Approve revision (Admin or Manager with Factor 3)
        res = await db_session.execute(select(User).where(User.wallet_address == MANAGER_WALLET))
        mgr_user = res.scalar_one()
        secret_mgr = pyotp.random_base32()
        mgr_user.totp_factor3_secret = secret_mgr
        mgr_user.is_totp_factor3_enabled = True
        await db_session.commit()

        totp_mgr = pyotp.TOTP(secret_mgr)

        appr_res2 = await client.post(
            f"/api/assets/document/approval/{action_id}",
            headers={"Authorization": f"Bearer {mgr_token}"},
            json={"decision": "APPROVE", "totp_code": totp_mgr.now()}
        )
        assert appr_res2.status_code == 200, appr_res2.text
        appr_data = appr_res2.json()
        assert appr_data["status"] == "APPROVED"
        assert "calldata" in appr_data

        # Verify lineage tracking
        res1 = await db_session.execute(select(Asset).where(Asset.serial_number == serial1))
        asset1 = res1.scalar_one()
        res2 = await db_session.execute(select(Asset).where(Asset.serial_number == serial2))
        asset2 = res2.scalar_one()

        assert asset1.lifecycle_status == "OBSOLETE"
        assert asset2.lifecycle_status == "CREATED"
        assert asset2.parent_asset_id == asset1.id

@pytest.mark.asyncio
async def test_revise_document_different_department(client, db_session):
    """Users cannot revise documents belonging to other departments."""
    user_token = get_token(USER_WALLET, "USER", 1)  # Avionics

    # Create doc in Cyber dept directly in DB
    res = await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))
    admin_user = res.scalar_one()

    serial1 = f"BEL-DOC-CYBER-{uuid.uuid4().hex[:6].upper()}"
    cyber_asset = Asset(
        token_id=uuid.uuid4().int % 100000000,
        serial_number=serial1,
        name="Cyber Doc",
        asset_type="DIGITAL",
        department="Cyber",
        lifecycle_status="ACTIVE",
        owner_id=admin_user.id
    )
    db_session.add(cyber_asset)
    await db_session.commit()

    # 2. USER (Avionics) tries to revise CYBER doc
    serial2 = f"BEL-DOC-{uuid.uuid4().hex[:6].upper()}"
    revise_res = await client.post(
        "/api/assets/document/revise",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "parent_asset_serial": serial1,
            "name": "Revised Cyber Doc",
            "new_serial_number": serial2,
            "new_file_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
            "new_offchain_uri": "secure-vault://documents/cyber_v2.txt",
            "purpose": "Sneaky update"
        }
    )

    assert revise_res.status_code == 403
    assert "Users can only revise documents in their own department" in revise_res.text
