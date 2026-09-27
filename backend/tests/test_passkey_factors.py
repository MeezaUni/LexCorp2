"""Purpose-bound passkey factors (Factor 2 / Factor 3).

Originally tested the in-memory assertion store, which was replaced by DB-backed
single-use challenges and step-up grants. Same intents, now proven against real
WebAuthn assertions (tests/webauthn_soft.py) and the persisted records.
"""

import uuid
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from sqlalchemy import select

from app.core.config import settings
from app.models.domain import User, WebAuthnCredential
from app.services import mfa
from app.services.auth import create_jwt
from tests.conftest import mfa_headers
from tests.webauthn_soft import ORIGIN, SoftPasskey, b64url

ACTIVE_USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
ACTIVE_USER_VERSION = 1
ACTIVE_MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"
ACTIVE_MANAGER_VERSION = 8


def get_token(wallet: str, role: str, version: int) -> str:
    did = f"did:ethr:{settings.CHAIN_ID}:{wallet.lower()}"
    return create_jwt(wallet_address=wallet, did=did, role=role, session_version=version)


async def enroll(db_session, wallet: str, scope: str) -> SoftPasskey:
    """Store a soft authenticator's real COSE public key as a credential of `scope`."""
    import cbor2
    key = SoftPasskey()
    user = (await db_session.execute(select(User).where(User.wallet_address == wallet.lower()))).scalar_one()
    db_session.add(WebAuthnCredential(
        user_id=user.id, credential_id=key.credential_id_hex,
        public_key=key._cose_public_key().hex(), sign_count=0,
        device_name=f"soft-{scope}", factor_scope=scope,
    ))
    await db_session.commit()
    return key


@pytest.mark.asyncio
async def test_assertion_purpose_isolation(db_session):
    """A grant/challenge for one purpose or action never satisfies another, and each is single-use."""
    user = (await db_session.execute(select(User).where(User.wallet_address == ACTIVE_USER_WALLET))).scalar_one()

    g2 = await mfa.issue_step_up(db_session, user, "factor2", "document.view", "PASSKEY")
    # Wrong purpose / wrong action fail and do not consume the grant
    assert await mfa.consume_step_up(db_session, user, "factor3", "document.view", g2["step_up_token"]) is False
    assert await mfa.consume_step_up(db_session, user, "factor2", "document.submit", g2["step_up_token"]) is False
    assert await mfa.consume_step_up(db_session, user, "factor2", "document.view", g2["step_up_token"]) is True
    # Single-use
    assert await mfa.consume_step_up(db_session, user, "factor2", "document.view", g2["step_up_token"]) is False

    g3 = await mfa.issue_step_up(db_session, user, "factor3", "asset.approve", "PASSKEY")
    assert await mfa.consume_step_up(db_session, user, "factor2", "asset.approve", g3["step_up_token"]) is False
    assert await mfa.consume_step_up(db_session, user, "factor3", "asset.approve", g3["step_up_token"]) is True

    # Grants cannot be minted for an action outside their purpose
    with pytest.raises(Exception):
        await mfa.issue_step_up(db_session, user, "factor2", "asset.approve", "PASSKEY")

    # Challenge purpose isolation
    c = await mfa.create_challenge(db_session, "WEBAUTHN_AUTH", user_id=user.id, purpose="login")
    assert await mfa.consume_challenge(db_session, "WEBAUTHN_AUTH", c, user_id=user.id, purpose="factor2") is None
    assert await mfa.consume_challenge(db_session, "WEBAUTHN_AUTH", c, user_id=user.id, purpose="login") is not None
    assert await mfa.consume_challenge(db_session, "WEBAUTHN_AUTH", c, user_id=user.id, purpose="login") is None
    await db_session.commit()


@pytest.mark.asyncio
async def test_passkey_factor2_and_factor3_workflow(client, db_session):
    """Passkey 2 authorises a submission; Passkey 3 authorises its approval."""
    user_token = get_token(ACTIVE_USER_WALLET, "USER", ACTIVE_USER_VERSION)
    mgr_token = get_token(ACTIVE_MANAGER_WALLET, "MANAGER", ACTIVE_MANAGER_VERSION)
    pk2 = await enroll(db_session, ACTIVE_USER_WALLET, "factor2")
    pk3 = await enroll(db_session, ACTIVE_MANAGER_WALLET, "factor3")

    h = {"Authorization": f"Bearer {user_token}", "Origin": ORIGIN}
    opt = await client.post("/api/auth/webauthn/factor2/options", headers=h, json={"action": "document.submit"})
    assert opt.status_code == 200
    ver = await client.post("/api/auth/webauthn/factor2/verify", headers=h, json={"response": pk2.assert_(opt.json()["options"])})
    assert ver.status_code == 200, ver.text

    serial = f"PK-{uuid.uuid4().hex[:8]}"
    prop = await client.post(
        "/api/assets/document/propose",
        headers={"Authorization": f"Bearer {user_token}", "X-Step-Up-Token": ver.json()["step_up_token"]},
        json={"name": "Passkey doc", "serial_number": serial, "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "offchain_uri": "secure-vault://documents/pk.txt", "totp_code": "",
              "recipient_address": "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"},
    )
    assert prop.status_code == 200, prop.text
    action_id = prop.json()["action_id"]

    # Without a factor the approval is refused
    no = await client.post(f"/api/assets/document/approval/{action_id}",
                           headers={"Authorization": f"Bearer {mgr_token}"}, json={"decision": "APPROVE", "totp_code": ""})
    assert no.status_code == 401

    hm = {"Authorization": f"Bearer {mgr_token}", "Origin": ORIGIN}
    opt3 = await client.post("/api/auth/webauthn/factor3/options", headers=hm, json={"action": "asset.approve"})
    ver3 = await client.post("/api/auth/webauthn/factor3/verify", headers=hm, json={"response": pk3.assert_(opt3.json()["options"])})
    assert ver3.status_code == 200, ver3.text
    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x1", "data": "0x2"}):
        ok = await client.post(f"/api/assets/document/approval/{action_id}",
                               headers={"Authorization": f"Bearer {mgr_token}", "X-Step-Up-Token": ver3.json()["step_up_token"]},
                               json={"decision": "APPROVE", "totp_code": ""})
    assert ok.status_code == 200, ok.text


@pytest.mark.asyncio
async def test_passkeys_belong_to_the_address_they_were_created_on(db_session, monkeypatch):
    """localhost on the server machine and the VPN name remotely are different WebAuthn sites:
    a passkey is offered and verified only on its own site, and each site can have its own."""
    from fastapi import HTTPException
    remote = "https://lexcorp2-app.example.org"
    monkeypatch.setattr(settings, "WEBAUTHN_ORIGINS", [*settings.WEBAUTHN_ORIGINS, remote])
    assert mfa.rp_id_for(ORIGIN) == "localhost"
    assert mfa.rp_id_for(remote) == "lexcorp2-app.example.org"
    assert mfa.rp_id_for("http://127.0.0.1:5173") == settings.RP_ID          # an IP can't be an RP ID
    assert mfa.rp_id_for("https://evil.example") == settings.RP_ID            # not an allowed origin

    wallet = "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    user = User(wallet_address=wallet, did=f"did:ethr:{settings.CHAIN_ID}:{wallet}", name="Two Sites", role="USER",
                onboarding_pending=False)
    db_session.add(user)
    await db_session.commit()
    local_key, remote_key = SoftPasskey(), SoftPasskey(rp_id="lexcorp2-app.example.org", origin=remote)
    db_session.add(WebAuthnCredential(user_id=user.id, credential_id=local_key.credential_id_hex, public_key=local_key._cose_public_key().hex(),
                                      sign_count=0, device_name="laptop (from before 0015)", factor_scope="factor2"))
    await db_session.commit()

    with pytest.raises(HTTPException) as refused:                               # only a localhost passkey so far
        await mfa.passkey_options(db_session, user, "factor2", "document.view", origin=remote)
    assert "another address" in refused.value.detail

    db_session.add(WebAuthnCredential(user_id=user.id, credential_id=remote_key.credential_id_hex, public_key=remote_key._cose_public_key().hex(),
                                      sign_count=0, device_name="laptop over VPN", factor_scope="factor2", rp_id="lexcorp2-app.example.org"))
    await db_session.commit()
    for origin, key in ((remote, remote_key), (ORIGIN, local_key)):
        options = await mfa.passkey_options(db_session, user, "factor2", "document.view", origin=origin)
        offered = {c["id"] for c in options["allowCredentials"]}
        assert offered == {b64url(key.credential_id)}
        challenge = await mfa.verify_passkey_assertion(db_session, user, "factor2", key.assert_(options), origin)
        assert challenge.action == "document.view"
    await db_session.commit()
