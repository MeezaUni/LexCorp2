"""Test suite for Mandatory MFA Onboarding and Recipient Mapping in Document Proposals."""

import pytest
from tests.conftest import mfa_headers
from app.core.crypto import verify_pin
import uuid
import pyotp
from unittest.mock import patch
from app.services.auth import create_jwt
from app.models.domain import User, DocumentAction, Asset
from app.core.config import settings
from sqlalchemy import select

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower()
ADMIN_VERSION = 5
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower()
MANAGER_VERSION = 8

def get_token(wallet: str, role: str, version: int = 1) -> str:
    did = f"did:ethr:{settings.CHAIN_ID}:{wallet.lower()}"
    return create_jwt(wallet_address=wallet, did=did, role=role, session_version=version)


@pytest.mark.asyncio
async def test_onboarding_pending_blocks_access(client, db_session):
    """Users with onboarding_pending=True must be blocked from protected operations."""
    new_wallet = f"0x{uuid.uuid4().hex}{uuid.uuid4().hex[:8]}".lower()
    user = User(
        wallet_address=new_wallet,
        did=f"did:ethr:{settings.CHAIN_ID}:{new_wallet}",
        role="USER",
        session_version=1,
        is_active=True,
        department="Avionics",
        name="New Pending User",
        onboarding_pending=True
    )
    db_session.add(user)
    await db_session.commit()

    token = get_token(new_wallet, "USER", 1)

    # Document propose should return 403 due to onboarding_pending
    res = await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Pending User Proposal",
            "serial_number": f"BEL-DOC-{uuid.uuid4().hex[:6].upper()}",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "offchain_uri": "secure-vault://documents/pending.txt",
        "recipient_address": "0x123abc",
        }
    )
    assert res.status_code == 403
    assert "Onboarding incomplete" in res.json()["detail"]


@pytest.mark.asyncio
async def test_admin_creates_user_with_onboarding_pending(client, db_session):
    """When Admin registers a new user, onboarding_pending is set to True by default."""
    admin_token = get_token(ADMIN_WALLET, "ADMIN", ADMIN_VERSION)
    new_wallet = f"0x{uuid.uuid4().hex}{uuid.uuid4().hex[:8]}".lower()

    from tests.conftest import step_up_header
    create_res = await client.post(
        "/api/users",
        headers={"Authorization": f"Bearer {admin_token}", **(await step_up_header(ADMIN_WALLET, "identity.provision"))},
        json={
            "wallet_address": new_wallet,
            "role": "USER",
            "department": "Radar",
            "name": "Radar Operator"
        }
    )
    assert create_res.status_code == 200
    data = create_res.json()
    assert "one_time_pin" in data
    assert data["onboarding_pending"] is True

    # Check database state
    res = await db_session.execute(select(User).where(User.wallet_address == new_wallet))
    created_user = res.scalar_one()
    assert created_user.onboarding_pending is True
    # The PIN is returned once and stored only as a hash, never in plaintext.
    assert created_user.one_time_pin is None
    assert created_user.pin_hash and created_user.pin_hash.startswith("scrypt$")
    assert data["one_time_pin"] not in created_user.pin_hash
    assert verify_pin(data["one_time_pin"], created_user.pin_hash)
    assert created_user.pin_used is False


@pytest.mark.asyncio
async def test_document_proposal_with_recipient(client, db_session):
    """Document proposal should record recipient_did and recipient_address in action details."""
    user_wallet = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower()
    user_token = get_token(user_wallet, "USER", 1)
    recipient_wallet = f"0x{uuid.uuid4().hex}{uuid.uuid4().hex[:8]}".lower()
    recipient_did = f"did:ethr:{settings.CHAIN_ID}:{recipient_wallet}"
    recipient_user = User(
        wallet_address=recipient_wallet,
        did=recipient_did,
        role="USER",
        session_version=1,
        is_active=True,
        department="Avionics",
        name="Target Recipient",
        onboarding_pending=False
    )
    db_session.add(recipient_user)
    await db_session.commit()

    serial = f"BEL-DOC-{uuid.uuid4().hex[:6].upper()}"

    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x123", "data": "0xabc"}):
        # 1. Propose document specifying recipient
        propose_res = await client.post(
            "/api/assets/document/propose",
            headers=await mfa_headers(db_session, user_token, user_wallet, "document.submit"),
            json={
                "name": "Targeted Spec Doc",
                "serial_number": serial,
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "offchain_uri": "secure-vault://documents/spec.pdf",
        "recipient_address": "0x123abc",
                "department": "Avionics",
                "recipient_did": recipient_did,
                "recipient_address": recipient_wallet
            }
        )
        assert propose_res.status_code == 200
        action_id = propose_res.json()["action_id"]

        # Check action in DB
        res = await db_session.execute(select(DocumentAction).where(DocumentAction.action_id == action_id))
        action = res.scalar_one()
        assert action.details.get("recipient_did") == recipient_did
        assert action.details.get("recipient_address") == recipient_wallet

        # 2. Manager approves document
        mgr_token = get_token(MANAGER_WALLET, "MANAGER", MANAGER_VERSION)
        appr_res = await client.post(
            f"/api/assets/document/approval/{action_id}",
            headers=await mfa_headers(db_session, mgr_token, MANAGER_WALLET, "asset.approve"),
            json={"decision": "APPROVE"}
        )
        assert appr_res.status_code == 200
        appr_data = appr_res.json()
        assert appr_data["status"] == "APPROVED"

        # Check created Asset owner mapped to recipient_user
        asset_res = await db_session.execute(select(Asset).where(Asset.serial_number == serial))
        asset = asset_res.scalar_one()
        assert asset.owner_id == recipient_user.id


@pytest.mark.asyncio
async def test_mfa_factor2_not_configured_error(client, db_session):
    """When Factor 2 is not enabled on a user account, proposal should return 403 instructing MFA setup."""
    test_wallet = f"0x{uuid.uuid4().hex[:40]}".lower()
    user = User(
        wallet_address=test_wallet,
        did=f"did:ethr:{settings.CHAIN_ID}:{test_wallet}",
        role="USER",
        session_version=1,
        is_active=True,
        department="Avionics",
        name="No F2 User",
        is_totp_factor2_enabled=False,
        onboarding_pending=False
    )
    db_session.add(user)
    await db_session.commit()

    token = get_token(test_wallet, "USER", 1)

    # Propose should fail with 403 Factor 2 setup required
    res = await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "F2 Test Doc",
            "serial_number": f"BEL-DOC-{uuid.uuid4().hex[:6].upper()}",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "offchain_uri": "secure-vault://documents/f2.pdf",
        "recipient_address": "0x123abc",
        }
    )
    assert res.status_code == 403
    assert "Factor 2 setup required" in res.json()["detail"]
