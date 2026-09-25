"""Identity & authentication test matrix (spec sections 9-15, 55).

Covers wallet provisioning with the one-time PIN, mandatory first-login setup,
login with TOTP 1 / Passkey 1, purpose-specific step-up (Factor 2 / Factor 3)
with real WebAuthn assertions, the admin-assisted reset, and session security.
"""

import uuid
from datetime import timedelta
from unittest.mock import patch

import time
import pyotp
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from sqlalchemy import select

from app.models.domain import User, WebAuthnCredential
from app.services import mfa
from app.services.auth import create_jwt
from tests.conftest import mfa_headers, totp_code
from tests.webauthn_soft import ORIGIN, SoftPasskey

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
ADMIN_VERSION = 5
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"
MANAGER_VERSION = 8

DOC = {
    "name": "Auth Matrix Doc",
    "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "offchain_uri": "secure-vault://documents/auth.txt",
    "recipient_address": "0x0000000000000000000000000000000000000001",
}


def bearer(token: str, **extra) -> dict:
    return {"Authorization": f"Bearer {token}", **extra}


def admin_token() -> str:
    return create_jwt(ADMIN_WALLET, f"did:ethr:13371:{ADMIN_WALLET}", "ADMIN", ADMIN_VERSION, client_ip="127.0.0.1")


async def new_identity(client, role: str = "USER") -> tuple:
    """Admin provisions a fresh identity; returns (account, pin)."""
    acct = Account.create()
    from tests.conftest import step_up_header
    res = await client.post("/api/users", headers=bearer(admin_token(), **(await step_up_header(ADMIN_WALLET, "identity.provision"))), json={
        "wallet_address": acct.address, "role": role, "department": "Avionics", "name": f"Matrix {role}",
    })
    assert res.status_code == 200, res.text
    return acct, res.json()["one_time_pin"]


async def signed_nonce(client, acct) -> dict:
    res = await client.post(f"/api/auth/nonce?address={acct.address}")
    assert res.status_code == 200
    data = res.json()
    sig = acct.sign_message(encode_defunct(text=data["message"])).signature.hex()
    return {"message": data["message"], "signature": sig, "nonce": data["nonce"]}


async def provision(client, acct, pin):
    return await client.post("/api/auth/provision", json={**await signed_nonce(client, acct), "pin": pin})


async def register_passkey(client, token: str, scope: str, headers_extra: dict | None = None) -> SoftPasskey:
    key = SoftPasskey()
    h = bearer(token, Origin=ORIGIN, **(headers_extra or {}))
    opt = await client.post("/api/auth/webauthn/register/options", headers=h, json={"factor_scope": scope})
    assert opt.status_code == 200, opt.text
    ver = await client.post("/api/auth/webauthn/register/verify", headers=h, json={
        "factor_scope": scope, "device_name": f"soft-{scope}", "response": key.register(opt.json()["options"]),
    })
    assert ver.status_code == 200, ver.text
    key.last_result = ver.json()
    key.last_session = ver.cookies.get("session")
    return key


async def enable_totp(client, token: str, path: str) -> str:
    res = await client.post(f"/api/auth/2fa/{path}setup", headers=bearer(token))
    assert res.status_code == 200, res.text
    secret = res.json()["secret"]
    ver = await client.post(f"/api/auth/2fa/{path}verify", headers=bearer(token), json={"token": pyotp.TOTP(secret).now()})
    assert ver.status_code == 200, ver.text
    ver.json()  # noqa
    return secret, ver.json()


async def onboard(client, db_session, role: str = "USER") -> dict:
    """Full first-time flow. Returns identity details with a full-session token."""
    acct, pin = await new_identity(client, role)
    res = await provision(client, acct, pin)
    assert res.status_code == 200, res.text
    setup_token = res.cookies.get("session")
    totp1, _ = await enable_totp(client, setup_token, "")
    pk1 = await register_passkey(client, setup_token, "login")
    assert pk1.last_result.get("setup_complete") is True
    return {"acct": acct, "wallet": acct.address.lower(), "totp1": totp1, "pk1": pk1,
            "token": pk1.last_session}


async def step_up_via_passkey(client, token: str, key: SoftPasskey, factor: str, action: str, *, as_factor: str | None = None):
    """Run options for `factor`+`action`, sign with `key`. Returns the verify response."""
    h = bearer(token, Origin=ORIGIN)
    opt = await client.post(f"/api/auth/webauthn/{factor}/options", headers=h, json={"action": action})
    if opt.status_code != 200:
        return opt
    return await client.post(f"/api/auth/webauthn/{as_factor or factor}/verify", headers=h,
                             json={"response": key.assert_(opt.json()["options"])})


# =============================================================== Provisioning / first login

@pytest.mark.asyncio
async def test_wallet_import_success_gives_setup_only_session(client, db_session):
    acct, pin = await new_identity(client)
    res = await provision(client, acct, pin)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["user"]["session_scope"] == "setup"
    assert body["user"]["onboarding_pending"] is True
    token = res.cookies.get("session")

    # Setup endpoints reachable, application endpoints (and dashboard data) are not.
    assert (await client.get("/api/auth/me", headers=bearer(token))).status_code == 200
    for method, url in [("get", "/api/assets/document/pending"), ("get", "/api/users"),
                        ("get", "/api/assets/physical/pending"), ("post", "/api/auth/step-up/totp")]:
        r = await getattr(client, method)(url, headers=bearer(token), **({"json": {"action": "document.view", "code": "123456"}} if method == "post" else {}))
        assert r.status_code == 403, (url, r.status_code, r.text)


@pytest.mark.asyncio
async def test_invalid_pin_rejected(client, db_session):
    acct, pin = await new_identity(client)
    wrong = ("X" if pin[0] != "X" else "Y") + pin[1:]
    res = await provision(client, acct, wrong)
    assert res.status_code == 401
    # The genuine PIN still works afterwards (a wrong guess does not burn it).
    assert (await provision(client, acct, pin)).status_code == 200


@pytest.mark.asyncio
async def test_pin_expires_after_exactly_three_hours(client, db_session):
    acct, pin = await new_identity(client)
    user = (await db_session.execute(select(User).where(User.wallet_address == acct.address.lower()))).scalar_one()
    lifetime = user.pin_expires_at - user.created_at
    assert timedelta(hours=3) - timedelta(seconds=5) <= lifetime <= timedelta(hours=3) + timedelta(seconds=5)

    user.pin_expires_at = mfa.utcnow() - timedelta(seconds=1)
    await db_session.commit()
    res = await provision(client, acct, pin)
    assert res.status_code == 400
    assert "expired" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_pin_is_single_use(client, db_session):
    acct, pin = await new_identity(client)
    assert (await provision(client, acct, pin)).status_code == 200
    again = await provision(client, acct, pin)
    assert again.status_code == 400
    user = (await db_session.execute(select(User).where(User.wallet_address == acct.address.lower()))).scalar_one()
    await db_session.refresh(user)
    assert user.pin_used is True and user.pin_hash is None


@pytest.mark.asyncio
async def test_pin_bound_to_its_wallet(client, db_session):
    acct_a, pin_a = await new_identity(client)
    acct_b, _ = await new_identity(client)
    # Wallet B signs, presenting A's PIN -> rejected, and A's PIN is not consumed.
    assert (await provision(client, acct_b, pin_a)).status_code == 401
    assert (await provision(client, acct_a, pin_a)).status_code == 200


@pytest.mark.asyncio
async def test_unknown_wallet_cannot_provision_or_autocreate(client, db_session):
    stranger = Account.create()
    res = await provision(client, stranger, "ABCDEFGHJKLM")
    assert res.status_code == 401
    exists = (await db_session.execute(select(User).where(User.wallet_address == stranger.address.lower()))).scalar_one_or_none()
    assert exists is None


@pytest.mark.asyncio
async def test_wallet_signature_alone_never_creates_session(client, db_session):
    acct, _ = await new_identity(client)
    signed = await signed_nonce(client, acct)
    res = await client.post("/api/auth/login", json=signed)  # legacy route without PIN
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_nonce_replay_rejected(client, db_session):
    acct, pin = await new_identity(client)
    signed = await signed_nonce(client, acct)
    wrong = ("X" if pin[0] != "X" else "Y") + pin[1:]
    assert (await client.post("/api/auth/provision", json={**signed, "pin": wrong})).status_code == 401
    # Same signed nonce cannot be replayed, even with the right PIN.
    assert (await client.post("/api/auth/provision", json={**signed, "pin": pin})).status_code == 401


@pytest.mark.asyncio
async def test_setup_requires_both_totp1_and_passkey1(client, db_session):
    acct, pin = await new_identity(client)
    setup = (await provision(client, acct, pin)).cookies.get("session")
    _, totp_result = await enable_totp(client, setup, "")
    assert totp_result.get("setup_complete") is None  # passkey still missing
    # Still setup-only: dashboard data blocked, and TOTP 1 login yields setup scope.
    assert (await client.get("/api/assets/document/pending", headers=bearer(setup))).status_code == 403
    pk = await register_passkey(client, setup, "login")
    assert pk.last_result["setup_complete"] is True
    full = pk.last_session
    assert (await client.get("/api/assets/document/pending", headers=bearer(full))).status_code == 200


@pytest.mark.asyncio
async def test_factor2_and_factor3_cannot_be_enrolled_during_setup(client, db_session):
    acct, pin = await new_identity(client)
    setup = (await provision(client, acct, pin)).cookies.get("session")
    assert (await client.post("/api/auth/2fa/factor2/setup", headers=bearer(setup))).status_code == 403
    r = await client.post("/api/auth/webauthn/register/options", headers=bearer(setup, Origin=ORIGIN), json={"factor_scope": "factor3"})
    assert r.status_code == 403


# =============================================================== Login

@pytest.mark.asyncio
async def test_login_with_totp1_and_manual_wallet(client, db_session):
    ident = await onboard(client, db_session)
    code = pyotp.TOTP(ident["totp1"]).at(pyotp.TOTP(ident["totp1"]).timecode(mfa.utcnow()) * 30 + 30)
    res = await client.post("/api/auth/login/totp", json={"wallet_address": ident["acct"].address, "token": code})
    assert res.status_code == 200, res.text
    assert res.json()["user"]["session_scope"] == "full"
    # Same code again (replay) is rejected.
    again = await client.post("/api/auth/login/totp", json={"wallet_address": ident["acct"].address, "token": code})
    assert again.status_code == 401


@pytest.mark.asyncio
async def test_login_totp_invalid_code_and_wrong_wallet(client, db_session):
    ident = await onboard(client, db_session)
    assert (await client.post("/api/auth/login/totp", json={"wallet_address": ident["wallet"], "token": "000000"})).status_code == 401
    other = Account.create().address
    code = pyotp.TOTP(ident["totp1"]).now()
    assert (await client.post("/api/auth/login/totp", json={"wallet_address": other, "token": code})).status_code == 401
    assert (await client.post("/api/auth/login/totp", json={"wallet_address": "not-a-wallet", "token": code})).status_code == 401


@pytest.mark.asyncio
async def test_login_with_passkey1(client, db_session):
    ident = await onboard(client, db_session)
    opt = await client.post("/api/auth/login/passkey/options", json={"wallet_address": ident["wallet"]}, headers={"Origin": ORIGIN})
    assert opt.status_code == 200
    allowed = {c["id"] for c in opt.json()["options"]["allowCredentials"]}
    assert len(allowed) == 1
    res = await client.post("/api/auth/login/passkey/verify", headers={"Origin": ORIGIN},
                            json={"wallet_address": ident["wallet"], "response": ident["pk1"].assert_(opt.json()["options"])})
    assert res.status_code == 200, res.text
    assert res.json()["user"]["session_scope"] == "full"


@pytest.mark.asyncio
async def test_login_passkey_invalid_assertion_rejected(client, db_session):
    ident = await onboard(client, db_session)
    opt = await client.post("/api/auth/login/passkey/options", json={"wallet_address": ident["wallet"]}, headers={"Origin": ORIGIN})
    bad = ident["pk1"].assert_(opt.json()["options"], tamper=True)
    res = await client.post("/api/auth/login/passkey/verify", headers={"Origin": ORIGIN},
                            json={"wallet_address": ident["wallet"], "response": bad})
    assert res.status_code == 401
    # A different (unregistered) authenticator is rejected too.
    opt2 = await client.post("/api/auth/login/passkey/options", json={"wallet_address": ident["wallet"]}, headers={"Origin": ORIGIN})
    res2 = await client.post("/api/auth/login/passkey/verify", headers={"Origin": ORIGIN},
                             json={"wallet_address": ident["wallet"], "response": SoftPasskey().assert_(opt2.json()["options"])})
    assert res2.status_code == 401


@pytest.mark.asyncio
async def test_login_passkey_requires_user_verification(client, db_session):
    ident = await onboard(client, db_session)
    opt = await client.post("/api/auth/login/passkey/options", json={"wallet_address": ident["wallet"]}, headers={"Origin": ORIGIN})
    no_uv = ident["pk1"].assert_(opt.json()["options"], flags=0x01)
    res = await client.post("/api/auth/login/passkey/verify", headers={"Origin": ORIGIN},
                            json={"wallet_address": ident["wallet"], "response": no_uv})
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_factor_passkey_cannot_log_in(client, db_session):
    ident = await onboard(client, db_session)
    pk2 = await register_passkey(client, ident["token"], "factor2")
    opt = await client.post("/api/auth/login/passkey/options", json={"wallet_address": ident["wallet"]}, headers={"Origin": ORIGIN})
    res = await client.post("/api/auth/login/passkey/verify", headers={"Origin": ORIGIN},
                            json={"wallet_address": ident["wallet"], "response": pk2.assert_(opt.json()["options"])})
    assert res.status_code == 401
    assert "Wrong-purpose" in res.json()["detail"]


# =============================================================== Factor 2 / Factor 3

@pytest.mark.asyncio
async def test_passkey2_view_and_submit(client, db_session):
    ident = await onboard(client, db_session)
    pk2 = await register_passkey(client, ident["token"], "factor2")
    sub = await step_up_via_passkey(client, ident["token"], pk2, "factor2", "document.submit")
    assert sub.status_code == 200, sub.text
    serial = f"AUTH-{uuid.uuid4().hex[:8]}"
    res = await client.post("/api/assets/document/propose", json={**DOC, "serial_number": serial},
                            headers=bearer(ident["token"], **{"X-Step-Up-Token": sub.json()["step_up_token"]}))
    assert res.status_code == 200, res.text

    view = await step_up_via_passkey(client, ident["token"], pk2, "factor2", "document.view")
    assert view.status_code == 200
    r = await client.get(f"/api/assets/document/view/{serial}",
                         headers=bearer(ident["token"], **{"X-Step-Up-Token": view.json()["step_up_token"]}))
    # Factor accepted; the (missing) file then yields 404, never 401.
    assert r.status_code in (200, 404), r.text


@pytest.mark.asyncio
async def test_totp2_accepted_for_submission(client, db_session):
    ident = await onboard(client, db_session)
    secret2, _ = await enable_totp(client, ident["token"], "factor2/")
    code = pyotp.TOTP(secret2).at(pyotp.TOTP(secret2).timecode(mfa.utcnow()) * 30 + 30)
    res = await client.post("/api/assets/document/propose", headers=bearer(ident["token"]),
                            json={**DOC, "serial_number": f"AUTH-{uuid.uuid4().hex[:8]}", "totp_code": code})
    assert res.status_code == 200, res.text


@pytest.mark.asyncio
async def test_factor1_cannot_satisfy_factor2(client, db_session):
    ident = await onboard(client, db_session)
    secret2, _ = await enable_totp(client, ident["token"], "factor2/")
    # Adding Passkey 2 to an already-protected Factor 2 requires proving Factor 2 first
    denied = await client.post("/api/auth/webauthn/register/options", headers=bearer(ident["token"], Origin=ORIGIN), json={"factor_scope": "factor2"})
    assert denied.status_code == 401
    code = pyotp.TOTP(secret2).at(pyotp.TOTP(secret2).timecode(mfa.utcnow()) * 30 + 30)
    su = await client.post("/api/auth/step-up/totp", headers=bearer(ident["token"]), json={"action": "factor2.manage", "code": code})
    assert su.status_code == 200, su.text
    await register_passkey(client, ident["token"], "factor2", {"X-Step-Up-Token": su.json()["step_up_token"]})
    # TOTP 1 code offered as Factor 2
    res = await client.post("/api/assets/document/propose", headers=bearer(ident["token"]),
                            json={**DOC, "serial_number": f"AUTH-{uuid.uuid4().hex[:8]}",
                                  "totp_code": pyotp.TOTP(ident["totp1"]).now()})
    assert res.status_code == 401
    # Passkey 1 assertion against a Factor 2 challenge
    res2 = await step_up_via_passkey(client, ident["token"], ident["pk1"], "factor2", "document.submit")
    assert res2.status_code == 401
    assert "Wrong-purpose" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_passkey3_approve_mint_modify_and_factor2_cannot_satisfy_factor3(client, db_session):
    mgr = await onboard(client, db_session, role="MANAGER")
    pk2 = await register_passkey(client, mgr["token"], "factor2")
    pk3 = await register_passkey(client, mgr["token"], "factor3")
    mgr_user = (await db_session.execute(select(User).where(User.wallet_address == mgr["wallet"]))).scalar_one()

    # A USER proposes a document in Avionics for the manager to approve.
    user_token = create_jwt("0xe1ced2305c7c75618eeb1450e18e2099c15b7d72", "did:ethr:13371:0xe1ced2305c7c75618eeb1450e18e2099c15b7d72", "USER", 1, client_ip="127.0.0.1")
    prop = await client.post("/api/assets/document/propose", json={**DOC, "serial_number": f"AUTH-{uuid.uuid4().hex[:8]}"},
                             headers=await mfa_headers(db_session, user_token, "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72", "document.submit"))
    action_id = prop.json()["action_id"]

    # Factor 2 passkey against a Factor 3 challenge -> wrong purpose
    wrong = await step_up_via_passkey(client, mgr["token"], pk2, "factor3", "asset.approve")
    assert wrong.status_code == 401
    # Factor 2 step-up token presented for a Factor 3 action -> rejected
    f2 = await step_up_via_passkey(client, mgr["token"], pk2, "factor2", "document.submit")
    r = await client.post(f"/api/assets/document/approval/{action_id}", json={"decision": "APPROVE"},
                          headers=bearer(mgr["token"], **{"X-Step-Up-Token": f2.json()["step_up_token"]}))
    assert r.status_code == 401  # Factor 3 is configured (Passkey 3), but a Factor 2 token never satisfies it
    r_ok = None
    with patch("app.services.contract.contract_service.prepare_mint_digital_calldata", return_value={"to": "0x1", "data": "0x2"}):
        approve = await step_up_via_passkey(client, mgr["token"], pk3, "factor3", "asset.approve")
        assert approve.status_code == 200
        r_ok = await client.post(f"/api/assets/document/approval/{action_id}", json={"decision": "APPROVE"},
                                 headers=bearer(mgr["token"], **{"X-Step-Up-Token": approve.json()["step_up_token"]}))
    assert r_ok.status_code == 200, r_ok.text

    # Passkey 3 for mint (of an approved physical asset in the manager's department)
    from app.models.domain import Asset
    phys = Asset(token_id=int(uuid.uuid4().int % 2_000_000_000), serial_number=f"PK3-{uuid.uuid4().hex[:8]}", owner_id=mgr_user.id,
                 is_physical=True, department="Avionics", approval_status="APPROVED", device_unique_address=f"UA-{uuid.uuid4().hex[:8]}")
    db_session.add(phys)
    await db_session.commit()
    mint = await step_up_via_passkey(client, mgr["token"], pk3, "factor3", "asset.mint")
    with patch("app.services.contract.contract_service.prepare_mint_calldata", return_value={"to": "0x1", "data": "0x2"}):
        r_mint = await client.post("/api/assets/mint/prepare", headers=bearer(mgr["token"], **{"X-Step-Up-Token": mint.json()["step_up_token"]}),
                                   json={"to_address": mgr["acct"].address, "token_id": phys.token_id, "serial_number": phys.serial_number, "owner_did": mgr_user.did})
    assert r_mint.status_code == 200, r_mint.text

    # Passkey 3 for modify (revision proposal)
    serial = prop.json()["asset_serial"]
    mod = await step_up_via_passkey(client, mgr["token"], pk3, "factor3", "document.modify")
    import hashlib, os
    from app.api.assets import OFFCHAIN_STORAGE_DIR
    with open(os.path.join(OFFCHAIN_STORAGE_DIR, "documents", "r.txt"), "wb") as f:
        f.write(b"revised by manager")
    r_mod = await client.post("/api/assets/document/revise", headers=bearer(mgr["token"], **{"X-Step-Up-Token": mod.json()["step_up_token"]}),
                              json={"parent_asset_serial": serial, "name": "rev",
                                    "new_file_hash": hashlib.sha256(b"revised by manager").hexdigest(),
                                    "new_offchain_uri": "secure-vault://documents/r.txt"})
    # Passkey 3 satisfied the modify factor; the request then stops at the workflow rule
    # (a revision needs an approved modification download), not at authentication.
    assert r_mod.status_code == 400 and "modification download" in r_mod.json()["detail"], r_mod.text


@pytest.mark.asyncio
async def test_totp3_and_factor2_totp_cannot_satisfy_factor3(client, db_session):
    mgr = await onboard(client, db_session, role="MANAGER")
    secret2, _ = await enable_totp(client, mgr["token"], "factor2/")
    secret3, _ = await enable_totp(client, mgr["token"], "factor3/")
    step = pyotp.TOTP(secret3).timecode(mfa.utcnow()) * 30 + 30
    from app.models.domain import Asset
    mgr_user = (await db_session.execute(select(User).where(User.wallet_address == mgr["wallet"]))).scalar_one()
    phys = Asset(token_id=int(uuid.uuid4().int % 2_000_000_000), serial_number=f"T3-{uuid.uuid4().hex[:8]}", owner_id=mgr_user.id,
                 is_physical=True, department="Avionics", approval_status="APPROVED", device_unique_address=f"UA-{uuid.uuid4().hex[:8]}")
    db_session.add(phys)
    await db_session.commit()
    with patch("app.services.contract.contract_service.prepare_mint_calldata", return_value={"to": "0x1", "data": "0x2"}):
        body = {"to_address": mgr["acct"].address, "token_id": phys.token_id, "serial_number": phys.serial_number, "owner_did": "did:x"}
        f2 = await client.post("/api/assets/mint/prepare", headers=bearer(mgr["token"]), json={**body, "totp_code": pyotp.TOTP(secret2).at(step)})
        assert f2.status_code == 401
        f1 = await client.post("/api/assets/mint/prepare", headers=bearer(mgr["token"]), json={**body, "totp_code": pyotp.TOTP(mgr["totp1"]).at(step)})
        assert f1.status_code == 401
        ok = await client.post("/api/assets/mint/prepare", headers=bearer(mgr["token"]), json={**body, "totp_code": pyotp.TOTP(secret3).at(step)})
        assert ok.status_code == 200, ok.text


@pytest.mark.asyncio
async def test_step_up_token_bound_to_action_and_single_use(client, db_session):
    ident = await onboard(client, db_session)
    pk2 = await register_passkey(client, ident["token"], "factor2")
    view = await step_up_via_passkey(client, ident["token"], pk2, "factor2", "document.view")
    tok = view.json()["step_up_token"]
    # A token minted for viewing cannot be spent on a submission.
    r = await client.post("/api/assets/document/propose", json={**DOC, "serial_number": f"AUTH-{uuid.uuid4().hex[:8]}"},
                          headers=bearer(ident["token"], **{"X-Step-Up-Token": tok}))
    assert r.status_code == 401
    sub = await step_up_via_passkey(client, ident["token"], pk2, "factor2", "document.submit")
    stok = sub.json()["step_up_token"]
    ok = await client.post("/api/assets/document/propose", json={**DOC, "serial_number": f"AUTH-{uuid.uuid4().hex[:8]}"},
                           headers=bearer(ident["token"], **{"X-Step-Up-Token": stok}))
    assert ok.status_code == 200
    reuse = await client.post("/api/assets/document/propose", json={**DOC, "serial_number": f"AUTH-{uuid.uuid4().hex[:8]}"},
                              headers=bearer(ident["token"], **{"X-Step-Up-Token": stok}))
    assert reuse.status_code == 401


@pytest.mark.asyncio
async def test_passkey_challenge_cannot_be_replayed(client, db_session):
    ident = await onboard(client, db_session)
    pk2 = await register_passkey(client, ident["token"], "factor2")
    h = bearer(ident["token"], Origin=ORIGIN)
    opt = await client.post("/api/auth/webauthn/factor2/options", headers=h, json={"action": "document.view"})
    assertion = pk2.assert_(opt.json()["options"])
    assert (await client.post("/api/auth/webauthn/factor2/verify", headers=h, json={"response": assertion})).status_code == 200
    assert (await client.post("/api/auth/webauthn/factor2/verify", headers=h, json={"response": assertion})).status_code == 401


# =============================================================== Reset

@pytest.mark.asyncio
async def test_user_cannot_self_reset_login_factors(client, db_session):
    ident = await onboard(client, db_session)
    t = ident["token"]
    for url in ("/api/auth/2fa/reset", "/api/auth/2fa/disable", "/api/auth/webauthn/reset"):
        r = await client.post(url, headers=bearer(t))
        assert r.status_code == 403 and "ADMIN ASSISTANCE" in r.json()["detail"], url
    r = await client.request("DELETE", f"/api/auth/webauthn/credentials/{ident['pk1'].credential_id_hex}", headers=bearer(t))
    assert r.status_code == 403
    r = await client.post("/api/auth/webauthn/register/options", headers=bearer(t, Origin=ORIGIN), json={"factor_scope": "login"})
    assert r.status_code == 403
    r = await client.post("/api/auth/2fa/setup", headers=bearer(t))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_reset_flow_invalidates_login_factors_and_forces_setup(client, db_session):
    ident = await onboard(client, db_session)
    old_token = ident["token"]
    req = await client.post("/api/auth/reset-request", headers=bearer(old_token), json={"reason": "lost phone"})
    assert req.status_code == 200
    target = (await db_session.execute(select(User).where(User.wallet_address == ident["wallet"]))).scalar_one()

    listed = await client.get("/api/auth/reset-requests", headers=bearer(admin_token()))
    assert any(u["wallet_address"] == ident["wallet"] for u in listed.json())

    # Approval without Factor 3 is refused; Factor 2 does not count.
    no_f3 = await client.post(f"/api/auth/reset-approve/{target.id}", headers=bearer(admin_token()), json={})
    assert no_f3.status_code == 401
    f2_code = totp_code(ADMIN_WALLET, "factor2")
    assert (await client.post(f"/api/auth/reset-approve/{target.id}", headers=bearer(admin_token()), json={"totp_code": f2_code})).status_code == 401

    ok = await client.post(f"/api/auth/reset-approve/{target.id}", headers=bearer(admin_token()),
                           json={"totp_code": totp_code(ADMIN_WALLET, "factor3")})
    assert ok.status_code == 200, ok.text
    new_pin = ok.json()["one_time_pin"]

    # Existing session revoked
    assert (await client.get("/api/auth/me", headers=bearer(old_token))).status_code == 401
    # Old TOTP 1 and Passkey 1 no longer log in
    assert (await client.post("/api/auth/login/totp", json={"wallet_address": ident["wallet"], "token": pyotp.TOTP(ident["totp1"]).now()})).status_code == 401
    opt = await client.post("/api/auth/login/passkey/options", json={"wallet_address": ident["wallet"]}, headers={"Origin": ORIGIN})
    assert opt.status_code == 400
    creds = (await db_session.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == target.id, WebAuthnCredential.factor_scope == "login"))).scalars().all()
    assert creds and all(not c.is_active for c in creds)

    # New PIN -> setup-only session -> must configure new TOTP 1 + Passkey 1
    prov = await provision(client, ident["acct"], new_pin)
    assert prov.status_code == 200
    assert prov.json()["user"]["session_scope"] == "setup"
    setup = prov.cookies.get("session")
    assert (await client.get("/api/assets/document/pending", headers=bearer(setup))).status_code == 403
    await enable_totp(client, setup, "")
    pk = await register_passkey(client, setup, "login")
    assert pk.last_result["setup_complete"] is True


@pytest.mark.asyncio
async def test_admin_cannot_reset_without_request_or_self(client, db_session):
    ident = await onboard(client, db_session)
    target = (await db_session.execute(select(User).where(User.wallet_address == ident["wallet"]))).scalar_one()
    r = await client.post(f"/api/auth/reset-approve/{target.id}", headers=bearer(admin_token()),
                          json={"totp_code": totp_code(ADMIN_WALLET, "factor3")})
    assert r.status_code == 409
    admin = (await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))).scalar_one()
    admin.reset_requested = True
    await db_session.commit()
    r2 = await client.post(f"/api/auth/reset-approve/{admin.id}", headers=bearer(admin_token()), json={})
    assert r2.status_code == 403
    admin.reset_requested = False
    await db_session.commit()


@pytest.mark.asyncio
async def test_non_admin_cannot_approve_reset(client, db_session):
    ident = await onboard(client, db_session)
    target = (await db_session.execute(select(User).where(User.wallet_address == ident["wallet"]))).scalar_one()
    mgr = create_jwt(MANAGER_WALLET, f"did:ethr:13371:{MANAGER_WALLET}", "MANAGER", MANAGER_VERSION, client_ip="127.0.0.1")
    r = await client.post(f"/api/auth/reset-approve/{target.id}", headers=bearer(mgr), json={"totp_code": totp_code(MANAGER_WALLET, "factor3")})
    assert r.status_code == 403


# =============================================================== Session security

@pytest.mark.asyncio
async def test_ip_change_terminates_session(client, db_session):
    ident = await onboard(client, db_session)
    t = ident["token"]
    assert (await client.get("/api/auth/me", headers=bearer(t))).status_code == 200
    # Same token from a different effective client IP (via the trusted local proxy)
    moved = await client.get("/api/auth/me", headers=bearer(t, **{"X-Forwarded-For": "203.0.113.9"}))
    assert moved.status_code == 401
    assert "IP address changed" in moved.json()["detail"]
    # The session is dead even back on the original IP.
    assert (await client.get("/api/auth/me", headers=bearer(t))).status_code == 401


def test_forwarded_for_ignored_from_untrusted_peer():
    from starlette.requests import Request
    from app.api.dependencies import get_request_client_ip

    def req(peer, xff=None):
        headers = [(b"x-forwarded-for", xff.encode())] if xff else []
        return Request({"type": "http", "client": (peer, 5555), "headers": headers})

    assert get_request_client_ip(req("198.51.100.7", "10.0.0.1")) == "198.51.100.7"  # spoof attempt ignored
    assert get_request_client_ip(req("127.0.0.1", "203.0.113.5")) == "203.0.113.5"   # trusted proxy
    assert get_request_client_ip(req("127.0.0.1", "10.1.1.1, 203.0.113.5")) == "203.0.113.5"  # right-most untrusted hop
    assert get_request_client_ip(req("::1")) == "127.0.0.1"


@pytest.mark.asyncio
async def test_inactivity_timeout(client, db_session):
    ident = await onboard(client, db_session)
    user = (await db_session.execute(select(User).where(User.wallet_address == ident["wallet"]))).scalar_one()
    user.last_activity_at = mfa.utcnow() - timedelta(minutes=16)
    await db_session.commit()
    r = await client.get("/api/auth/me", headers=bearer(ident["token"]))
    assert r.status_code == 401 and "inactivity" in r.json()["detail"]


@pytest.mark.asyncio
async def test_single_active_session_and_logout(client, db_session):
    ident = await onboard(client, db_session)
    first = ident["token"]
    code = pyotp.TOTP(ident["totp1"]).at(pyotp.TOTP(ident["totp1"]).timecode(mfa.utcnow()) * 30 + 30)
    second = (await client.post("/api/auth/login/totp", json={"wallet_address": ident["wallet"], "token": code})).cookies.get("session")
    assert (await client.get("/api/auth/me", headers=bearer(first))).status_code == 401
    assert (await client.post("/api/auth/logout", headers=bearer(second))).status_code == 200
    assert (await client.get("/api/auth/me", headers=bearer(second))).status_code == 401


@pytest.mark.asyncio
async def test_disabled_account_rejected(client, db_session):
    ident = await onboard(client, db_session)
    user = (await db_session.execute(select(User).where(User.wallet_address == ident["wallet"]))).scalar_one()
    user.is_active = False
    await db_session.commit()
    assert (await client.get("/api/auth/me", headers=bearer(ident["token"]))).status_code == 403
    assert (await client.post("/api/auth/login/totp", json={"wallet_address": ident["wallet"], "token": pyotp.TOTP(ident["totp1"]).now()})).status_code == 401


@pytest.mark.asyncio
async def totp_secret_fors_encrypted_at_rest(client, db_session):
    ident = await onboard(client, db_session)
    user = (await db_session.execute(select(User).where(User.wallet_address == ident["wallet"]))).scalar_one()
    await db_session.refresh(user)
    assert user.totp_secret.startswith("enc:v1:")
    assert ident["totp1"] not in user.totp_secret


@pytest.mark.asyncio
async def test_login_rate_limit_enforced(client, db_session):
    wallet = Account.create().address
    codes = [(await client.post("/api/auth/login/totp", json={"wallet_address": wallet, "token": "123456"})).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5
    assert 429 in codes[5:]


# =============================================================== Wallet keystore wrapping secret

@pytest.mark.asyncio
async def test_wallet_key_released_only_to_session_and_rotated_on_reset(client, db_session):
    acct, pin = await new_identity(client)
    prov = await provision(client, acct, pin)
    key1 = prov.json()["wallet_key"]
    assert key1 and len(key1) >= 32
    setup = prov.cookies.get("session")
    client.cookies.clear()  # provisioning set the httpOnly session cookie
    assert (await client.get("/api/auth/wallet-key")).status_code == 401
    assert (await client.get("/api/auth/wallet-key", headers=bearer(setup))).json()["wallet_key"] == key1
    user = (await db_session.execute(select(User).where(User.wallet_address == acct.address.lower()))).scalar_one()
    await db_session.refresh(user)
    assert user.wallet_wrap_secret.startswith("enc:v1:") and key1 not in user.wallet_wrap_secret

    # Admin reset clears it; re-provisioning issues a different one
    await enable_totp(client, setup, "")
    pk = await register_passkey(client, setup, "login")
    full = pk.last_session
    await client.post("/api/auth/reset-request", headers=bearer(full), json={})
    ok = await client.post(f"/api/auth/reset-approve/{user.id}", headers=bearer(admin_token()),
                           json={"totp_code": totp_code(ADMIN_WALLET, "factor3")})
    assert ok.status_code == 200
    prov2 = await provision(client, acct, ok.json()["one_time_pin"])
    key2 = prov2.json()["wallet_key"]
    assert key2 != key1
    assert (await client.get("/api/auth/wallet-key", headers=bearer(prov2.cookies.get("session")))).json()["wallet_key"] == key2


@pytest.mark.asyncio
async def test_totp_qr_rendered_locally(client, db_session):
    acct, pin = await new_identity(client)
    setup = (await provision(client, acct, pin)).cookies.get("session")
    res = await client.post("/api/auth/2fa/setup", headers=bearer(setup))
    assert res.status_code == 200
    assert res.json()["qr_data_uri"].startswith("data:image/png;base64,")


@pytest.mark.asyncio
async def test_session_is_httponly_cookie_only(client, db_session):
    """No response body carries the session token; the cookie is HttpOnly + SameSite=Strict."""
    acct, pin = await new_identity(client)
    res = await provision(client, acct, pin)
    assert res.status_code == 200
    assert "token" not in res.json()
    raw = res.headers.get("set-cookie", "")
    assert "session=" in raw and "HttpOnly" in raw and "samesite=strict" in raw.lower()
    ident = await onboard(client, db_session)
    login = await client.post("/api/auth/login/totp", json={"wallet_address": ident["wallet"],
                                                           "token": pyotp.TOTP(ident["totp1"]).at(int(time.time()) + 30)})
    assert login.status_code == 200, login.text
    assert "token" not in login.json() and login.cookies.get("session")
