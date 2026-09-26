"""Opt-in reuse of the login factors for Factor 2 / Factor 3, role-aware login resets for
administrators, and the physical asset type "Other" description."""
import uuid

import pytest
from sqlalchemy import select, update

from app.models.domain import Asset, User, WebAuthnCredential
from app.services import mfa
from app.services.auth import create_jwt
from tests.conftest import mfa_headers, step_up_header, totp_code
from tests.test_passkey_factors import enroll
from tests.webauthn_soft import ORIGIN

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca"
USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
VERSIONS = {ADMIN_WALLET: ("ADMIN", 5), MANAGER_WALLET: ("MANAGER", 8), USER_WALLET: ("USER", 1)}


def token(wallet: str) -> str:
    role, version = VERSIONS[wallet]
    return create_jwt(wallet, f"did:ethr:13371:{wallet}", role, version, client_ip="testclient")


def auth(wallet: str) -> dict:
    return {"Authorization": f"Bearer {token(wallet)}"}


async def unprotect(db, wallet: str, purpose: str) -> None:
    """Give `purpose` no factors of its own, so the person can choose how to protect it."""
    user = (await db.execute(select(User).where(User.wallet_address == wallet))).scalar_one()
    setattr(user, f"is_totp_{purpose}_enabled", False)
    await db.execute(update(WebAuthnCredential)
                     .where(WebAuthnCredential.user_id == user.id, WebAuthnCredential.factor_scope == purpose)
                     .values(is_active=False))
    await db.commit()


async def link(client, wallet: str, purpose: str):
    return await client.post(f"/api/auth/factors/{purpose}/use-login",
                             headers={**auth(wallet), **await step_up_header(wallet, f"{purpose}.link")})


@pytest.mark.asyncio
async def test_choosing_login_factors_needs_login_proof(client, db_session):
    await unprotect(db_session, USER_WALLET, "factor2")
    url = "/api/auth/factors/factor2/use-login"
    assert (await client.post(url, headers=auth(USER_WALLET))).status_code == 401
    # A proof for another purpose is not a login proof
    wrong = {**auth(USER_WALLET), **await step_up_header(USER_WALLET, "factor3.manage")}
    assert (await client.post(url, headers=wrong)).status_code == 401
    ok = await link(client, USER_WALLET, "factor2")
    assert ok.status_code == 200, ok.text
    me = (await client.get("/api/auth/me", headers=auth(USER_WALLET))).json()
    assert me["factor2_uses_login"] is True and me["factor2_ready"] is True and me["factor3_uses_login"] is False


@pytest.mark.asyncio
async def test_linked_factor2_accepts_login_code_once_and_blocks_separate_setup(client, db_session):
    await unprotect(db_session, USER_WALLET, "factor2")
    assert (await link(client, USER_WALLET, "factor2")).status_code == 200
    code = totp_code(USER_WALLET, "login")
    first = await client.post("/api/auth/step-up/totp", headers=auth(USER_WALLET), json={"action": "document.view", "code": code})
    assert first.status_code == 200, first.text
    # The login and linked purposes share one replay counter: the same code is never accepted twice
    again = await client.post("/api/auth/step-up/totp", headers=auth(USER_WALLET), json={"action": "document.submit", "code": code})
    assert again.status_code == 401
    # The old Factor 2 authenticator no longer counts
    f2 = await client.post("/api/auth/step-up/totp", headers=auth(USER_WALLET),
                           json={"action": "document.view", "code": totp_code(USER_WALLET, "factor2")})
    assert f2.status_code == 401
    # Factor 3 is unaffected: a login code does not satisfy it
    f3 = await client.post("/api/auth/step-up/totp", headers=auth(USER_WALLET),
                           json={"action": "document.modify", "code": totp_code(USER_WALLET, "login")})
    assert f3.status_code == 401
    # No separate Factor 2 enrolment while it reuses the login factors
    assert (await client.post("/api/auth/2fa/factor2/setup", headers=auth(USER_WALLET), json={})).status_code == 409


@pytest.mark.asyncio
async def test_linked_factor2_accepts_the_login_passkey(client, db_session):
    await unprotect(db_session, MANAGER_WALLET, "factor2")
    login_key = await enroll(db_session, MANAGER_WALLET, "login")
    assert (await link(client, MANAGER_WALLET, "factor2")).status_code == 200
    h = {**auth(MANAGER_WALLET), "Origin": ORIGIN}
    opt = await client.post("/api/auth/webauthn/factor2/options", headers=h, json={"action": "document.submit"})
    assert opt.status_code == 200, opt.text
    ver = await client.post("/api/auth/webauthn/factor2/verify", headers=h, json={"response": login_key.assert_(opt.json()["options"])})
    assert ver.status_code == 200, ver.text
    assert ver.json()["action"] == "document.submit" and ver.json()["purpose"] == "factor2"


@pytest.mark.asyncio
async def test_use_separate_needs_login_proof_and_leaves_factor_unprotected(client, db_session):
    await unprotect(db_session, USER_WALLET, "factor2")
    assert (await link(client, USER_WALLET, "factor2")).status_code == 200
    url = "/api/auth/factors/factor2/use-separate"
    assert (await client.post(url, headers=auth(USER_WALLET))).status_code == 401
    ok = await client.post(url, headers={**auth(USER_WALLET), **await step_up_header(USER_WALLET, "factor2.link")})
    assert ok.status_code == 200, ok.text
    view = await client.post("/api/auth/step-up/totp", headers=auth(USER_WALLET),
                             json={"action": "document.view", "code": totp_code(USER_WALLET, "login")})
    assert view.status_code == 401
    me = (await client.get("/api/auth/me", headers=auth(USER_WALLET))).json()
    assert me["factor2_uses_login"] is False and me["factor2_ready"] is False


@pytest.mark.asyncio
async def test_login_factors_cannot_replace_a_factor_that_has_its_own(client, db_session):
    # Seeded users have their own Factor 3 authenticator
    assert (await link(client, USER_WALLET, "factor3")).status_code == 409


@pytest.mark.asyncio
async def test_administrator_reset_goes_to_another_administrator_or_the_operator(client, db_session):
    others = (await db_session.execute(select(User).where(
        User.role == "ADMIN", User.is_active.is_(True), User.wallet_address != ADMIN_WALLET))).scalars().all()
    for u in others:
        u.is_active = False
    await db_session.commit()
    try:
        me = (await client.get("/api/auth/me", headers=auth(ADMIN_WALLET))).json()
        assert me["reset_path"] == "server_operator"
        sole = await client.post("/api/auth/reset-request", headers=auth(ADMIN_WALLET), json={"reason": "lost phone"})
        assert sole.status_code == 409 and "--reset-login" in sole.json()["detail"]

        second = User(wallet_address=f"0x{uuid.uuid4().hex}{uuid.uuid4().hex[:8]}", did=f"did:ethr:13371:{uuid.uuid4().hex}",
                      role="ADMIN", department="Cyber", name="Second admin", is_active=True, onboarding_pending=False)
        db_session.add(second)
        await db_session.commit()
        me = (await client.get("/api/auth/me", headers=auth(ADMIN_WALLET))).json()
        assert me["reset_path"] == "another_administrator"
        req = await client.post("/api/auth/reset-request", headers=auth(ADMIN_WALLET), json={"reason": "lost phone"})
        assert req.status_code == 200, req.text
        # The requesting administrator never sees their own request in the approval list
        listed = (await client.get("/api/auth/reset-requests", headers=auth(ADMIN_WALLET))).json()
        assert all(r["wallet_address"] != ADMIN_WALLET for r in listed)
        user_me = (await client.get("/api/auth/me", headers=auth(USER_WALLET))).json()
        assert user_me["reset_path"] == "administrator"
    finally:
        admin = (await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))).scalar_one()
        admin.reset_requested = False
        for u in others:
            u.is_active = True
        await db_session.execute(update(User).where(User.name == "Second admin").values(is_active=False))
        await db_session.commit()


@pytest.mark.asyncio
async def test_reset_login_factors_issues_new_pin_and_ends_sessions(db_session):
    u = User(wallet_address=f"0x{uuid.uuid4().hex}{uuid.uuid4().hex[:8]}", did=f"did:ethr:13371:{uuid.uuid4().hex}",
             role="ADMIN", department="Cyber", name="Reset target", is_active=True, onboarding_pending=False,
             is_totp_enabled=True, session_version=3)
    db_session.add(u)
    await db_session.commit()
    pin, _ = await mfa.reset_login_factors(db_session, u)
    await db_session.commit()
    assert len(pin) >= 12 and u.pin_hash and not u.pin_used and u.onboarding_pending
    assert u.is_totp_enabled is False and u.session_version == 4 and u.wallet_wrap_secret is None
    u.is_active = False
    await db_session.commit()


@pytest.mark.asyncio
async def test_physical_asset_type_other_needs_a_description(client, db_session):
    async def propose(**body):
        return await client.post(
            "/api/assets/physical/propose",
            headers=await mfa_headers(db_session, token(MANAGER_WALLET), MANAGER_WALLET, "document.submit"),
            json={"name": "HW", "serial_number": f"OTH-{uuid.uuid4().hex[:8]}", "has_mac_address": False,
                  "device_unique_address": f"CHIP-{uuid.uuid4().hex[:10]}", "recipient_address": USER_WALLET, **body})

    assert (await propose(asset_type="OTHER")).status_code == 400
    assert (await propose(asset_type="SPACESHIP")).status_code == 400
    ok = await propose(asset_type="OTHER", asset_type_other="  Drone   battery ")
    assert ok.status_code == 200, ok.text
    asset = (await db_session.execute(select(Asset).where(Asset.serial_number == ok.json()["asset_serial"]))).scalar_one()
    assert asset.asset_type == "OTHER: Drone battery"
