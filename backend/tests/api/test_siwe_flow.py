import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from sqlalchemy import select

from app.models.domain import User


@pytest.mark.asyncio
async def test_full_siwe_auth_flow(async_client, db_session):
    """A wallet signature is only a provisioning proof: without a valid PIN for a
    provisioned identity it never yields a session, and unknown wallets are not auto-created."""
    acct = Account.create()

    nonce_res = await async_client.post(f"/api/auth/nonce?address={acct.address}")
    assert nonce_res.status_code == 200
    nonce_data = nonce_res.json()
    signature = acct.sign_message(encode_defunct(text=nonce_data["message"])).signature.hex()

    # Signature alone (legacy /login shape, no PIN) is rejected outright
    no_pin = await async_client.post("/api/auth/login", json={
        "message": nonce_data["message"], "signature": signature, "nonce": nonce_data["nonce"],
    })
    assert no_pin.status_code == 422

    # With a PIN, an unprovisioned wallet is still refused and no user is created
    res = await async_client.post("/api/auth/provision", json={
        "message": nonce_data["message"], "signature": signature, "nonce": nonce_data["nonce"], "pin": "ABCDEFGHJKLM",
    })
    assert res.status_code == 401
    assert "token" not in res.json()
    created = (await db_session.execute(select(User).where(User.wallet_address == acct.address.lower()))).scalar_one_or_none()
    assert created is None
