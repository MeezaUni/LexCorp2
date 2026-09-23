import pytest
import uuid
from datetime import datetime, timedelta, UTC
from unittest.mock import patch, MagicMock
from app.services.auth import verify_assertion, get_challenge, store_challenge, is_assertion_valid, create_jwt
from app.core.config import settings
from app.models.domain import User, WebAuthnCredential
from sqlalchemy import select

ACTIVE_USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
ACTIVE_USER_VERSION = 1
ACTIVE_MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"
ACTIVE_MANAGER_VERSION = 8

def get_token(wallet: str, role: str, version: int) -> str:
    did = f"did:ethr:{settings.CHAIN_ID}:{wallet.lower()}"
    return create_jwt(wallet_address=wallet, did=did, role=role, session_version=version)

@pytest.mark.asyncio
async def test_assertion_purpose_isolation():
    """Ensure Factor 1 login assertion cannot be used for Factor 2 or Factor 3."""
    user_id = "test-user-123"

    verify_assertion(user_id, "factor2")
    assert is_assertion_valid(user_id, "factor2") is True
    # Single-use: should be consumed
    assert is_assertion_valid(user_id, "factor2") is False

    verify_assertion(user_id, "factor3")
    assert is_assertion_valid(user_id, "factor2") is False
    assert is_assertion_valid(user_id, "factor3") is True
    assert is_assertion_valid(user_id, "factor3") is False

    # Challenge store purpose isolation
    store_challenge(user_id, "login", "chal1")
    store_challenge(user_id, "factor2", "chal2")
    store_challenge(user_id, "factor3", "chal3")

    assert get_challenge(user_id, "login") == "chal1"
    assert get_challenge(user_id, "login") is None
    assert get_challenge(user_id, "factor2") == "chal2"
    assert get_challenge(user_id, "factor3") == "chal3"


@pytest.mark.asyncio
async def test_passkey_factor2_and_factor3_workflow(client, db_session, seed_test_users):
    """Test full Factor 2 and Factor 3 options generation and verification flow."""
    token = get_token(ACTIVE_USER_WALLET, "USER", ACTIVE_USER_VERSION)

    # 1. Get user from db
    res = await db_session.execute(select(User).where(User.wallet_address == ACTIVE_USER_WALLET.lower()))
    user = res.scalar_one()

    # Create mock WebAuthnCredential for user
    cred_id = uuid.uuid4().hex
    cred = WebAuthnCredential(
        user_id=user.id,
        credential_id=cred_id,
        public_key="00" * 32,
        sign_count=0,
        device_name="Test YubiKey",
        is_active=True
    )
    db_session.add(cred)
    user.is_totp_factor2_enabled = True
    user.is_totp_factor3_enabled = True
    await db_session.commit()

    # 2. Get Factor 2 Options
    f2_opt_res = await client.post(
        "/api/auth/webauthn/factor2/options",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert f2_opt_res.status_code == 200
    assert "options" in f2_opt_res.json()

    # 3. Verify Factor 2 without valid response should fail WebAuthn verification
    f2_verify_res = await client.post(
        "/api/auth/webauthn/factor2/verify",
        headers={"Authorization": f"Bearer {token}", "Origin": "http://localhost:5173"},
        json={"credential_id": cred_id, "response": {}}
    )
    assert f2_verify_res.status_code == 400

    # 4. Propose document creation without Factor 2 TOTP or valid Factor 2 passkey assertion should fail
    doc_serial = f"DOC-TEST-F2-{uuid.uuid4().hex[:6].upper()}"
    prop_res = await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Classified Defense File",
            "serial_number": doc_serial,
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "offchain_uri": "secure-vault://documents/test_f2.pdf",
            "purpose": "Factor 2 Test",
            "totp_code": ""
        }
    )
    assert prop_res.status_code == 401
    assert "Factor 2" in prop_res.json()["detail"]

    # 5. Successfully simulate verified Factor 2 Passkey assertion
    verify_assertion(str(user.id), "factor2")

    # Now proposing should succeed using the Passkey Factor 2 assertion!
    prop_res2 = await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Classified Defense File",
            "serial_number": doc_serial,
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "offchain_uri": "secure-vault://documents/test_f2.pdf",
            "purpose": "Factor 2 Test",
            "totp_code": ""
        }
    )
    assert prop_res2.status_code == 200
    action_id = prop_res2.json()["action_id"]

    # 6. Manager approves document using Factor 3 Passkey assertion
    mgr_res = await db_session.execute(select(User).where(User.wallet_address == ACTIVE_MANAGER_WALLET.lower()))
    manager = mgr_res.scalar_one()
    manager.is_totp_factor3_enabled = True
    await db_session.commit()

    mgr_token = get_token(ACTIVE_MANAGER_WALLET, "MANAGER", ACTIVE_MANAGER_VERSION)

    # Attempting to approve without Factor 3 TOTP or Passkey should fail (401)
    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x123", "data": "0xabc"}):
        appr_fail = await client.post(
            f"/api/assets/document/approval/{action_id}",
            headers={"Authorization": f"Bearer {mgr_token}"},
            json={"decision": "APPROVE", "totp_code": ""}
        )
        assert appr_fail.status_code == 401
        assert "Factor 3" in appr_fail.json()["detail"]

        # Simulate verified Factor 3 Passkey assertion for manager
        verify_assertion(str(manager.id), "factor3")

        # Now approval succeeds!
        appr_ok = await client.post(
            f"/api/assets/document/approval/{action_id}",
            headers={"Authorization": f"Bearer {mgr_token}"},
            json={"decision": "APPROVE", "totp_code": ""}
        )
        assert appr_ok.status_code == 200
        assert appr_ok.json()["status"] == "APPROVED"
