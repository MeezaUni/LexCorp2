"""Authentication endpoints.

Identity lifecycle:
  Wallet provisioning (wallet signature + one-time 3-hour PIN)  -> setup session
  Mandatory setup: Login TOTP 1 + Login Passkey 1               -> full session
  Login: typed wallet address + (TOTP 1 OR Passkey 1)           -> full session
  Step-up: TOTP 2 / Passkey 2 (view, submit), TOTP 3 / Passkey 3 (mint, approve,
           modify, download, admin actions), each bound to one named action.

Login factors are never reset self-service; users request admin assistance and an
admin approves with Factor 3, which invalidates the login factors, revokes sessions
and issues a new single-use provisioning PIN.
"""

import json
import logging
import secrets
import uuid
from datetime import timedelta
from typing import List, Optional

import webauthn
from fastapi import Cookie, APIRouter, Body, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, parse_client_data_json
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.api.dependencies import (
    get_admin_user,
    get_current_user,
    get_db,
    get_request_client_ip,
    get_setup_user,
    get_step_up_token,
    record_audit,
)
from app.core.config import settings
from app.core.crypto import decrypt_secret, encrypt_secret, hash_pin, verify_pin
from app.core.limiter import limiter
from app.models.domain import User, WebAuthnCredential
from app.services import auth, mfa, security, vc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_GENERIC_LOGIN_FAILURE = "Authentication failed. Check the wallet address and your Login Authenticator or Login Passkey."


# ============================================================ Schemas

class NonceResponse(BaseModel):
    nonce: str
    message: str


class ProvisionRequest(BaseModel):
    message: str
    signature: str
    nonce: str
    pin: str


class LoginResponse(BaseModel):
    user: dict  # the session itself is set as an httpOnly cookie, never returned in the body


class TotpLoginRequest(BaseModel):
    wallet_address: str
    token: str


class PasskeyLoginOptionsRequest(BaseModel):
    wallet_address: str


class PasskeyLoginVerifyRequest(BaseModel):
    wallet_address: str
    response: dict
    credential_id: Optional[str] = None  # ignored; derived from response.rawId


class TotpCodeRequest(BaseModel):
    token: str


class FactorManageRequest(BaseModel):
    totp_code: Optional[str] = None
    step_up_token: Optional[str] = None


class StepUpTotpRequest(BaseModel):
    action: str
    code: str


class StepUpOptionsRequest(BaseModel):
    action: str


class StepUpVerifyRequest(BaseModel):
    response: dict
    credential_id: Optional[str] = None  # ignored; derived from response.rawId


class WebAuthnRegistrationRequest(BaseModel):
    device_name: Optional[str] = "Biometric Authenticator"
    factor_scope: str = "login"
    totp_code: Optional[str] = None
    step_up_token: Optional[str] = None


class WebAuthnRegisterVerifyRequest(BaseModel):
    response: dict
    device_name: Optional[str] = "Biometric Authenticator"
    factor_scope: str = "login"
    credential_id: Optional[str] = None  # ignored


class ResetRequestPayload(BaseModel):
    reason: Optional[str] = "User requested admin reset assistance"


class WalletResetRequestPayload(BaseModel):
    message: str
    signature: str
    nonce: str
    reason: Optional[str] = "User requested admin reset assistance"


class AdminResetApproveRequest(BaseModel):
    totp_code: Optional[str] = None
    step_up_token: Optional[str] = None


class ResetRequestResponse(BaseModel):
    id: str
    wallet_address: str
    name: Optional[str] = None
    department: Optional[str] = None
    role: str
    reset_requested: bool
    reset_requested_at: Optional[str] = None
    reset_reason: Optional[str] = None


# ============================================================ Helpers

def _user_payload(user: User, scope: str) -> dict:
    return {
        "wallet_address": user.wallet_address,
        "did": user.did,
        "name": user.name,
        "department": user.department,
        "role": user.role,
        "is_active": user.is_active,
        "onboarding_pending": user.onboarding_pending,
        "session_scope": scope,
        "is_totp_enabled": user.is_totp_enabled,
        "is_totp_factor2_enabled": user.is_totp_factor2_enabled,
        "is_totp_factor3_enabled": user.is_totp_factor3_enabled,
    }


async def _issue_session(
    db: AsyncSession, user: User, request: Request, response: Response, method: str
) -> LoginResponse:
    """Start a new (single) session. Scope is full only when login setup is complete."""
    complete = await mfa.login_setup_complete(db, user)
    user.onboarding_pending = not complete
    scope = auth.SCOPE_FULL if complete else auth.SCOPE_SETUP
    user.session_version = (user.session_version or 0) + 1
    user.last_activity_at = mfa.utcnow()
    client_ip = get_request_client_ip(request)
    await record_audit(
        db, "AuthenticationSucceeded",
        actor_did=user.did, target_did=user.did, client_ip=client_ip,
        details={"method": method, "session_scope": scope},
    )
    await db.commit()
    token = auth.create_jwt(
        user.wallet_address, user.did, user.role, user.session_version,
        client_ip=client_ip, scope=scope,
    )
    # The session lives ONLY in an httpOnly, SameSite=Strict cookie (Secure in production):
    # page scripts can never read it, so an injected script cannot exfiltrate it.
    response.set_cookie(
        key="session", value=token, httponly=True, samesite="strict", secure=settings.is_production,
        max_age=settings.JWT_EXPIRE_MINUTES * 60, path="/",
    )
    return LoginResponse(user=_user_payload(user, scope))


async def _audit_failure(db: AsyncSession, event: str, request: Request, wallet: Optional[str], reason: str) -> None:
    client_ip = get_request_client_ip(request)
    label, score, details = "MEDIUM", 0.5, {"reason": reason}
    person = await _find_user(db, wallet) if wallet else None
    if person is not None:
        # Repeated failures (guessing codes, probing factors) are a behaviour pattern the local
        # risk model scores against this person's own history.
        from app.services.alerts import ai_assess
        risk = await ai_assess(db, "STEP_UP_FAILED" if event == "STEP_UP_FAILED" else "LOGIN_FAILED", person,
                               client_ip=client_ip, ok=False)
        if risk.get("risk_label") in ("HIGH", "CRITICAL"):
            label, score = risk["risk_label"], risk.get("risk_score")
            details = {**details, "ai": risk["ai"]}
    await record_audit(
        db, event,
        actor_did=auth.expected_did(wallet) if wallet else None,
        client_ip=client_ip,
        risk_label=label, risk_score=score,
        details=details,
    )
    await db.commit()


async def _find_user(db: AsyncSession, wallet_address: str) -> Optional[User]:
    return (await db.execute(
        select(User).where(func.lower(User.wallet_address) == (wallet_address or "").strip().lower())
    )).scalar_one_or_none()


def _usable(user: Optional[User]) -> bool:
    return bool(user and user.is_active and user.revoked_at is None)


async def _consume_siwe(db: AsyncSession, message: str, signature: str, nonce: str) -> str:
    """Verify the wallet signature over the exact server-built message and consume its nonce."""
    from web3 import Web3
    signer = auth.recover_signer(message, signature)
    if message != auth.build_siwe_message(Web3.to_checksum_address(signer), nonce):
        raise auth.AuthError("Signed message does not match the issued challenge")
    if not await mfa.consume_challenge(db, "SIWE", nonce, wallet_address=signer):
        raise auth.AuthError("Nonce expired, already used, or issued for a different wallet")
    return signer


# ============================================================ Provisioning (first-time wallet import)

@router.post("/nonce", response_model=NonceResponse)
@limiter.limit("10/minute")
async def get_nonce(address: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Issue a single-use signing challenge bound to this wallet address."""
    try:
        from web3 import Web3
        checksummed = Web3.to_checksum_address(address)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid wallet address")
    nonce = auth.generate_nonce()
    await mfa.create_challenge(
        db, "SIWE", wallet_address=checksummed, challenge=nonce,
        ttl_seconds=settings.NONCE_EXPIRY_SECONDS,
    )
    await db.commit()
    return NonceResponse(nonce=nonce, message=auth.build_siwe_message(checksummed, nonce))


@router.post("/provision")
@router.post("/login", include_in_schema=False)
@limiter.limit("5/minute")
async def provision_wallet(
    req: ProvisionRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)
):
    """First-time wallet import: proves possession of the wallet key AND a valid
    admin-issued single-use PIN. Returns a setup-only session."""
    try:
        signer = await _consume_siwe(db, req.message, req.signature, req.nonce)
    except auth.AuthError as e:
        await db.commit()
        await _audit_failure(db, "WALLET_PROVISIONING_FAILED", request, None, "signature/nonce")
        raise HTTPException(status_code=401, detail=str(e))

    user = await _find_user(db, signer)
    if not _usable(user):
        await _audit_failure(db, "WALLET_PROVISIONING_FAILED", request, signer, "unknown or disabled identity")
        raise HTTPException(status_code=401, detail="This wallet is not provisioned in LexCorp or has been revoked. Contact your administrator.")

    now = mfa.utcnow()
    if not user.pin_hash or user.pin_expires_at is None:
        await _audit_failure(db, "WALLET_PROVISIONING_FAILED", request, signer, "no active PIN")
        raise HTTPException(status_code=400, detail="No active provisioning PIN for this identity. Ask your administrator for a new PIN.")
    if user.pin_used:
        await _audit_failure(db, "WALLET_PROVISIONING_FAILED", request, signer, "PIN reuse")
        raise HTTPException(status_code=400, detail="This provisioning PIN has already been used. Ask your administrator for a new PIN.")
    if now > user.pin_expires_at:
        await _audit_failure(db, "WALLET_PROVISIONING_FAILED", request, signer, "PIN expired")
        raise HTTPException(status_code=400, detail="This provisioning PIN has expired (valid for 3 hours). Ask your administrator for a new PIN.")
    if not verify_pin(req.pin.strip(), user.pin_hash):
        await _audit_failure(db, "WALLET_PROVISIONING_FAILED", request, signer, "invalid PIN")
        raise HTTPException(status_code=401, detail="Invalid provisioning PIN.")

    # Atomic single-use consumption: a concurrent second use finds pin_used already true.
    consumed = (await db.execute(
        update(User)
        .where(User.id == user.id, User.pin_used.is_(False), User.pin_hash == user.pin_hash)
        .values(pin_used=True, pin_hash=None)
        .returning(User.id)
    )).scalar_one_or_none()
    if consumed is None:
        await db.rollback()
        raise HTTPException(status_code=400, detail="This provisioning PIN has already been used.")
    await db.refresh(user)
    # Fresh wrapping secret for the newly imported keystore; any older keystore copy stops unlocking.
    wallet_key = secrets.token_urlsafe(32)
    user.wallet_wrap_secret = encrypt_secret(wallet_key)
    await record_audit(db, "WALLET_PROVISIONED", actor_did=user.did, target_did=user.did,
                       client_ip=get_request_client_ip(request))
    session = await _issue_session(db, user, request, response, "WALLET_PROVISIONING")
    return {"user": session.user, "wallet_key": wallet_key}


@router.post("/otp/verify-import", include_in_schema=False)
async def verify_import_otp_removed():
    raise HTTPException(
        status_code=410,
        detail="Removed: the PIN is now verified together with the wallet signature at POST /api/auth/provision.",
    )


# ============================================================ Login (TOTP 1 or Passkey 1)

@router.post("/login/totp", response_model=LoginResponse)
@limiter.limit("5/minute")
async def login_with_totp(totp_req: TotpLoginRequest, response: Response, request: Request, db: AsyncSession = Depends(get_db)):
    user = await _find_user(db, totp_req.wallet_address)
    if not _usable(user) or not user.is_totp_enabled or not mfa.verify_totp_code(user, "login", totp_req.token):
        await _audit_failure(db, "AuthenticationFailed", request, totp_req.wallet_address.strip().lower() or None, "TOTP 1")
        raise HTTPException(status_code=401, detail=_GENERIC_LOGIN_FAILURE)
    return await _issue_session(db, user, request, response, "TOTP1")


@router.post("/login/passkey/options")
@limiter.limit("10/minute")
async def get_passkey_login_options(options_req: PasskeyLoginOptionsRequest, request: Request, db: AsyncSession = Depends(get_db)):
    user = await _find_user(db, options_req.wallet_address)
    if not _usable(user):
        raise HTTPException(status_code=401, detail=_GENERIC_LOGIN_FAILURE)
    options = await mfa.passkey_options(db, user, "login", action="session.login", origin=request.headers.get("origin"))
    await db.commit()
    return {"options": options}


@router.post("/login/passkey/verify", response_model=LoginResponse)
@limiter.limit("5/minute")
async def login_with_passkey(passkey_req: PasskeyLoginVerifyRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    user = await _find_user(db, passkey_req.wallet_address)
    if not _usable(user):
        raise HTTPException(status_code=401, detail=_GENERIC_LOGIN_FAILURE)
    try:
        await mfa.verify_passkey_assertion(db, user, "login", passkey_req.response, request.headers.get("origin"))
    except HTTPException as e:
        await db.commit()
        await _audit_failure(db, "AuthenticationFailed", request, user.wallet_address, f"Passkey 1: {e.detail}")
        raise
    return await _issue_session(db, user, request, response, "PASSKEY1")


@router.post("/logout")
async def logout(response: Response, request: Request, user: User = Depends(get_setup_user), db: AsyncSession = Depends(get_db)):
    user.session_version = (user.session_version or 0) + 1
    await record_audit(db, "LOGOUT", actor_did=user.did, client_ip=get_request_client_ip(request))
    await db.commit()
    response.delete_cookie("session", path="/", httponly=True, samesite="strict", secure=settings.is_production)
    return {"message": "Signed out. Session revoked."}


@router.get("/session")
async def session_state(request: Request, session: Optional[str] = Cookie(None), db: AsyncSession = Depends(get_db)):
    """Whether the caller holds a valid session (200 either way, so a signed-out page
    load does not register as a failed request). Details come from /auth/me."""
    if not session:
        return {"authenticated": False}
    from app.api.dependencies import _authenticate
    try:
        user, payload = await _authenticate(request, session, None, db)
    except HTTPException as e:
        # Tell the holder of the (rejected) cookie why their session ended.
        return {"authenticated": False, "ended": str(e.detail)}
    return {"authenticated": True, "session_scope": payload.get("scope")}


@router.get("/me")
async def get_current_user_profile(user: User = Depends(get_setup_user), db: AsyncSession = Depends(get_db)):
    """Profile and security-setup status. Reachable with a setup-only session."""
    creds = (await db.execute(select(WebAuthnCredential).where(
        WebAuthnCredential.user_id == user.id, WebAuthnCredential.is_active.is_(True)
    ))).scalars().all()
    scopes = {c.factor_scope for c in creds}
    return {
        "id": str(user.id),
        "wallet_address": user.wallet_address,
        "did": user.did,
        "name": user.name,
        "department": user.department,
        "organization": user.organization,
        "role": user.role,
        "is_active": user.is_active,
        "onboarding_pending": user.onboarding_pending,
        "is_totp_enabled": user.is_totp_enabled,
        "is_totp_factor2_enabled": user.is_totp_factor2_enabled,
        "is_totp_factor3_enabled": user.is_totp_factor3_enabled,
        "has_login_passkey": "login" in scopes,
        "has_factor2_passkey": "factor2" in scopes,
        "has_factor3_passkey": "factor3" in scopes,
        "factor2_uses_login": bool(user.factor2_uses_login),
        "factor3_uses_login": bool(user.factor3_uses_login),
        # Ready = the purpose can be proven now (its own factors, or the login factors it reuses).
        "factor2_ready": _purpose_ready(user, "factor2", scopes),
        "factor3_ready": _purpose_ready(user, "factor3", scopes),
        "reset_requested": bool(user.reset_requested),
        # An administrator can't approve their own reset; with no other active administrator
        # the reset is done by the server operator (backend/scripts/bootstrap_admin.py --reset-login).
        "reset_path": await _reset_path(db, user),
    }


def _purpose_ready(user: User, purpose: str, scopes: set) -> bool:
    if mfa.uses_login(user, purpose):
        return bool(user.is_totp_enabled) or "login" in scopes
    return bool(getattr(user, f"is_totp_{purpose}_enabled")) or purpose in scopes


async def _reset_path(db: AsyncSession, user: User) -> str:
    if user.role != "ADMIN":
        return "administrator"
    others = (await db.execute(select(User.id).where(
        User.role == "ADMIN", User.is_active.is_(True), User.onboarding_pending.is_(False), User.id != user.id,
    ))).first()
    return "another_administrator" if others else "server_operator"


@router.get("/wallet-key")
@limiter.limit("20/minute")
async def get_wallet_key(request: Request, user: User = Depends(get_setup_user)):
    """Release the keystore wrapping secret to an authenticated session only."""
    key = decrypt_secret(user.wallet_wrap_secret)
    if not key:
        raise HTTPException(status_code=404, detail="No wallet is provisioned for this identity. Re-import it with a new PIN.")
    return {"wallet_key": key}


# ============================================================ TOTP enrollment

def _totp_purpose(path_factor: Optional[str]) -> str:
    return {None: "login", "factor2": "factor2", "factor3": "factor3"}[path_factor]


async def _totp_setup(user: User, purpose: str, db: AsyncSession) -> dict:
    if mfa.totp_enabled(user, purpose):
        if purpose == "login":
            raise HTTPException(status_code=403, detail="Login Authenticator is already configured. Use REQUEST ADMIN ASSISTANCE to reset it.")
        raise HTTPException(status_code=400, detail=f"{mfa.PURPOSE_LABELS[purpose]} TOTP is already enabled.")
    secret = security.generate_totp_secret()
    issuer = {"login": "LexCorp2 Login (Factor 1)", "factor2": "LexCorp2 Factor 2 (view, submit)",
              "factor3": "LexCorp2 Factor 3 (approve, modify)"}[purpose]
    mfa.set_totp_secret(user, purpose, secret)
    await db.commit()
    # Returned once to the enrolling user only, for their authenticator app. Never logged.
    # The QR is rendered here: the otpauth URI contains the secret and must never go to a third-party QR service.
    import base64
    from app.services.qr import generate_qr_for_url
    uri = security.get_totp_uri(user.name or user.wallet_address, secret, issuer_name=issuer)
    qr = "data:image/png;base64," + base64.b64encode(generate_qr_for_url(uri)).decode()
    return {"secret": secret, "uri": uri, "qr_data_uri": qr}


async def _totp_verify(user: User, purpose: str, code: str, request: Request, response: Response, db: AsyncSession) -> dict:
    if not mfa.get_totp_secret(user, purpose):
        raise HTTPException(status_code=400, detail="TOTP setup not initiated.")
    if mfa.totp_enabled(user, purpose):
        raise HTTPException(status_code=400, detail="TOTP is already enabled.")
    if not mfa.verify_totp_code(user, purpose, code, require_enabled=False):
        # 400, not 401: a mistyped enrolment code is not the end of the session.
        raise HTTPException(status_code=400, detail="That code didn't match. Use the newest LexCorp2 entry for this factor in your "
                                                    "authenticator app (delete older ones from earlier attempts), check your "
                                                    "phone's clock is set automatically, and try the next code.")
    _, enabled_field, _ = mfa._TOTP_FIELDS[purpose]
    setattr(user, enabled_field, True)
    await record_audit(db, "TOTP_ENROLLED", actor_did=user.did, client_ip=get_request_client_ip(request),
                       details={"purpose": purpose})
    await db.commit()
    result = {"message": f"{mfa.PURPOSE_LABELS[purpose]} TOTP enabled.", "onboarding_pending": user.onboarding_pending}
    if purpose == "login" and user.onboarding_pending and await mfa.login_setup_complete(db, user):
        session = await _issue_session(db, user, request, response, "SETUP_COMPLETE")
        result.update({"onboarding_pending": False, "setup_complete": True, "user": session.user})
    return result


@router.post("/2fa/setup")
@limiter.limit("5/minute")
async def setup_totp(request: Request, user: User = Depends(get_setup_user), db: AsyncSession = Depends(get_db)):
    return await _totp_setup(user, "login", db)


@router.post("/2fa/verify")
@limiter.limit("5/minute")
async def verify_totp_setup(request: Request, response: Response, token: str = Body(..., embed=True),
                            user: User = Depends(get_setup_user), db: AsyncSession = Depends(get_db)):
    return await _totp_verify(user, "login", token, request, response, db)


@router.post("/2fa/{factor}/setup")
@limiter.limit("5/minute")
async def setup_totp_factor(factor: str, request: Request, body: FactorManageRequest = Body(default=FactorManageRequest()),
                            step_up_header: Optional[str] = Depends(get_step_up_token),
                            user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if factor not in ("factor2", "factor3"):
        raise HTTPException(status_code=404, detail="Unknown factor")
    if user.onboarding_pending:
        raise HTTPException(status_code=403, detail="Complete login setup first.")
    _refuse_if_linked(user, factor)
    # A purpose already protected by a passkey may only gain a TOTP with that purpose's
    # own proof; a login session alone must never add a higher factor.
    if await mfa.scoped_credentials(db, user, factor):
        await mfa.require_factor(db, user, f"{factor}.manage", totp_code=body.totp_code,
                                 step_up_token=body.step_up_token or step_up_header)
    return await _totp_setup(user, factor, db)


@router.post("/2fa/{factor}/verify")
@limiter.limit("5/minute")
async def verify_totp_factor(factor: str, request: Request, response: Response, token: str = Body(..., embed=True),
                             user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if factor not in ("factor2", "factor3"):
        raise HTTPException(status_code=404, detail="Unknown factor")
    _refuse_if_linked(user, factor)
    return await _totp_verify(user, factor, token, request, response, db)


_ADMIN_ASSIST = "Login factors cannot be reset self-service. Use REQUEST ADMIN ASSISTANCE; an administrator will re-provision your identity."


@router.post("/2fa/disable")
@router.post("/2fa/reset")
async def login_totp_reset_blocked(user: User = Depends(get_setup_user)):
    raise HTTPException(status_code=403, detail=_ADMIN_ASSIST)


@router.post("/2fa/{factor}/disable")
@router.post("/2fa/{factor}/reset")
async def reset_totp_factor(
    factor: str,
    request: Request,
    body: FactorManageRequest = Body(default=FactorManageRequest()),
    step_up_header: Optional[str] = Depends(get_step_up_token),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Reset Factor 2 / Factor 3 TOTP. Requires a step-up with an existing factor of the
    same purpose, so a login session alone can never replace a higher factor."""
    if factor not in ("factor2", "factor3"):
        raise HTTPException(status_code=404, detail="Unknown factor")
    _refuse_if_linked(user, factor)
    await mfa.require_factor(db, user, f"{factor}.manage", totp_code=body.totp_code,
                             step_up_token=body.step_up_token or step_up_header)
    mfa.set_totp_secret(user, factor, None)
    await record_audit(db, "TOTP_RESET", actor_did=user.did, client_ip=get_request_client_ip(request),
                       details={"purpose": factor})
    await db.commit()
    return {"message": f"{mfa.PURPOSE_LABELS[factor]} TOTP reset."}


# ============================================================ Step-up (Factor 2 / Factor 3)

@router.post("/step-up/totp")
@limiter.limit("10/minute")
async def step_up_with_totp(req: StepUpTotpRequest, request: Request, user: User = Depends(get_current_user),
                            db: AsyncSession = Depends(get_db)):
    """Exchange a purpose TOTP code for a single-use step-up token bound to one action."""
    purpose = mfa.ACTION_PURPOSE.get(req.action)
    if not purpose:
        raise HTTPException(status_code=400, detail="Unknown action")
    if not mfa.verify_totp_code(user, purpose, req.code):
        await _audit_failure(db, "STEP_UP_FAILED", request, user.wallet_address, f"{purpose} TOTP for {req.action}")
        raise HTTPException(status_code=401, detail=f"Invalid {mfa.PURPOSE_LABELS[purpose]} TOTP code.")
    grant = await mfa.issue_step_up(db, user, purpose, req.action, "TOTP")
    await db.commit()
    return grant


# ============================================================ Passkey registration

@router.post("/webauthn/register/options")
@limiter.limit("5/minute")
async def get_webauthn_registration_options(
    reg_req: WebAuthnRegistrationRequest,
    request: Request,
    step_up_header: Optional[str] = Depends(get_step_up_token),
    user: User = Depends(get_setup_user),
    db: AsyncSession = Depends(get_db),
):
    scope = reg_req.factor_scope
    if scope not in mfa.PURPOSES:
        raise HTTPException(status_code=400, detail="factor_scope must be login, factor2 or factor3")
    if scope != "login":
        _refuse_if_linked(user, scope)
    # one passkey per purpose per site name: a passkey only works where it was created (localhost
    # on the server machine, the VPN name remotely)
    rp_id = mfa.rp_id_for(request.headers.get("origin"))
    existing = await mfa.scoped_credentials(db, user, scope, rp_id)
    if scope == "login":
        if existing:
            raise HTTPException(status_code=403, detail="Login Passkey is already configured. " + _ADMIN_ASSIST)
        if not user.onboarding_pending:
            # Login is already set up (with a passkey for another address, or the authenticator): a
            # login passkey for this address needs the login factor, not just the session.
            await mfa.require_factor(db, user, "login.manage", totp_code=reg_req.totp_code,
                                     step_up_token=reg_req.step_up_token or step_up_header)
    else:
        if user.onboarding_pending:
            raise HTTPException(status_code=403, detail="Complete login setup (TOTP 1 + Passkey 1) first.")
        if existing or mfa.totp_enabled(user, scope):
            # Adding a credential to an already-protected purpose needs that purpose's factor.
            await mfa.require_factor(db, user, f"{scope}.manage", totp_code=reg_req.totp_code,
                                     step_up_token=reg_req.step_up_token or step_up_header)

    label = mfa.PURPOSE_LABELS[scope]
    options = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name="LexCorp2",
        user_id=f"{user.id}_{scope}".encode(),
        user_name=f"{user.wallet_address} ({label})",
        user_display_name=f"{user.name or user.wallet_address} [{label}]",
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=bytes.fromhex(c.credential_id)) for c in existing],
    )
    options_json = json.loads(webauthn.options_to_json(options))
    await mfa.create_challenge(db, "WEBAUTHN_REG", user_id=user.id, purpose=scope, challenge=options_json["challenge"])
    await db.commit()
    return {"options": options_json}


@router.post("/webauthn/register/verify")
@limiter.limit("5/minute")
async def verify_webauthn_registration(
    request: Request,
    response: Response,
    payload: WebAuthnRegisterVerifyRequest = Body(...),
    user: User = Depends(get_setup_user),
    db: AsyncSession = Depends(get_db),
):
    scope = payload.factor_scope
    if scope in ("factor2", "factor3"):
        _refuse_if_linked(user, scope)
    origin = request.headers.get("origin")
    if not origin or origin not in settings.WEBAUTHN_ORIGINS:
        raise HTTPException(status_code=400, detail="Invalid origin for WebAuthn")
    try:
        client_data = parse_client_data_json(base64url_to_bytes(payload.response["response"]["clientDataJSON"]))
        challenge_value = bytes_to_base64url(client_data.challenge)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed WebAuthn registration response.")
    challenge = await mfa.consume_challenge(db, "WEBAUTHN_REG", challenge_value, user_id=user.id, purpose=scope)
    if challenge is None:
        raise HTTPException(status_code=400, detail="Registration challenge not found, expired, or issued for a different scope.")
    try:
        verification = webauthn.verify_registration_response(
            credential=payload.response,
            expected_challenge=base64url_to_bytes(challenge.challenge),
            expected_origin=origin,
            expected_rp_id=mfa.rp_id_for(origin),
            require_user_verification=True,
        )
    except Exception as e:
        await db.commit()
        logger.warning("Passkey registration rejected: %s", e)
        raise HTTPException(status_code=400, detail="Passkey registration verification failed.")

    provider = mfa.passkey_provider(verification.aaguid)
    db.add(WebAuthnCredential(
        user_id=user.id,
        credential_id=verification.credential_id.hex(),
        public_key=verification.credential_public_key.hex(),
        sign_count=verification.sign_count,
        # Shows where the passkey lives (Windows Hello, iCloud Keychain, a password manager...).
        device_name=f"{provider}: {payload.device_name}"[:100] if payload.device_name else provider,
        factor_scope=scope,
        rp_id=mfa.rp_id_for(origin),
    ))
    await record_audit(db, "PASSKEY_REGISTERED", actor_did=user.did, client_ip=get_request_client_ip(request),
                       details={"purpose": scope, "provider": provider, "aaguid": verification.aaguid})
    await db.commit()
    result = {"message": f"{mfa.PURPOSE_LABELS[scope]} passkey registered.", "factor_scope": scope}
    if scope == "login" and user.onboarding_pending and await mfa.login_setup_complete(db, user):
        session = await _issue_session(db, user, request, response, "SETUP_COMPLETE")
        result.update({"setup_complete": True, "user": session.user})
    return result


@router.get("/webauthn/credentials")
async def list_webauthn_credentials(user: User = Depends(get_setup_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user.id, WebAuthnCredential.is_active.is_(True)
        ).order_by(WebAuthnCredential.created_at.desc())
    )
    return [{
        "credential_id": c.credential_id,
        "device_name": c.device_name,
        "factor_scope": c.factor_scope or "login",
        "site": c.rp_id or settings.RP_ID,       # the address the passkey works on
        "created_at": c.created_at.isoformat(),
    } for c in result.scalars().all()]


@router.delete("/webauthn/credentials/{credential_id}")
async def disable_webauthn_credential(
    credential_id: str,
    request: Request,
    body: FactorManageRequest = Body(default=FactorManageRequest()),
    step_up_header: Optional[str] = Depends(get_step_up_token),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    credential = (await db.execute(select(WebAuthnCredential).where(
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.credential_id == credential_id,
        WebAuthnCredential.is_active.is_(True),
    ))).scalar_one_or_none()
    if not credential:
        raise HTTPException(status_code=404, detail="Passkey not found")
    if credential.factor_scope == "login":
        raise HTTPException(status_code=403, detail=_ADMIN_ASSIST)
    await mfa.require_factor(db, user, f"{credential.factor_scope}.manage", totp_code=body.totp_code,
                             step_up_token=body.step_up_token or step_up_header)
    credential.is_active = False
    await record_audit(db, "PASSKEY_DISABLED", actor_did=user.did, client_ip=get_request_client_ip(request),
                       details={"purpose": credential.factor_scope})
    await db.commit()
    return {"message": "Passkey disabled.", "credential_id": credential_id}


@router.post("/webauthn/reset")
async def reset_webauthn_blocked(user: User = Depends(get_setup_user)):
    raise HTTPException(status_code=403, detail=_ADMIN_ASSIST)


# ------------------------------------------------------------ Step-up passkeys (declared after /webauthn/register/* so 'register' is never read as a factor)

@router.post("/webauthn/{factor}/options")
async def step_up_passkey_options(factor: str, request: Request, req: StepUpOptionsRequest = Body(default=None),
                                  user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # "login" is accepted only for actions that require the login factor (factor2.link / factor3.link).
    if factor not in mfa.PURPOSES:
        raise HTTPException(status_code=404, detail="Unknown factor")
    action = req.action if req else None
    if not action or mfa.ACTION_PURPOSE.get(action) != factor:
        raise HTTPException(status_code=400, detail=f"A {mfa.PURPOSE_LABELS[factor]} action must be specified.")
    options = await mfa.passkey_options(db, user, factor, action, origin=request.headers.get("origin"))
    await db.commit()
    return {"options": options}


@router.post("/webauthn/{factor}/verify")
async def step_up_passkey_verify(factor: str, req: StepUpVerifyRequest, request: Request,
                                 user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Verify a Passkey 2 / Passkey 3 assertion and mint a step-up token for the
    action the challenge was issued for."""
    if factor not in mfa.PURPOSES:
        raise HTTPException(status_code=404, detail="Unknown factor")
    try:
        challenge = await mfa.verify_passkey_assertion(db, user, factor, req.response, request.headers.get("origin"))
    except HTTPException as e:
        await db.commit()
        await _audit_failure(db, "STEP_UP_FAILED", request, user.wallet_address, f"{factor} passkey: {e.detail}")
        raise
    grant = await mfa.issue_step_up(db, user, factor, challenge.action, "PASSKEY")
    await db.commit()
    return {**grant, "valid": True}


# ============================================================ Reusing login factors for Factor 2 / 3

def _refuse_if_linked(user: User, purpose: str) -> None:
    if mfa.uses_login(user, purpose):
        n = {"factor2": 2, "factor3": 3}[purpose]
        raise HTTPException(status_code=409, detail=f"Factor {n} currently uses your login authenticator and passkey. "
                                                    f"Choose \"Use separate factors\" in My identity first.")


class FactorLinkRequest(BaseModel):
    totp_code: Optional[str] = None
    step_up_token: Optional[str] = None


@router.post("/factors/{factor}/use-login")
@limiter.limit("5/minute")
async def use_login_factors(factor: str, request: Request, body: FactorLinkRequest = Body(default=FactorLinkRequest()),
                            step_up_header: Optional[str] = Depends(get_step_up_token),
                            user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """The person chooses to prove Factor 2 or Factor 3 with their login authenticator and
    login passkey instead of separate ones. Requires proof of the login factor now."""
    if factor not in ("factor2", "factor3"):
        raise HTTPException(status_code=404, detail="Unknown factor")
    if mfa.uses_login(user, factor):
        raise HTTPException(status_code=409, detail="This factor already uses your login factors.")
    if mfa.totp_enabled(user, factor) or await mfa.scoped_credentials(db, user, factor):
        raise HTTPException(status_code=409, detail="This factor already has its own authenticator or passkey. "
                                                    "Remove those first if you want to use your login factors instead.")
    await mfa.require_factor(db, user, f"{factor}.link", totp_code=body.totp_code,
                             step_up_token=body.step_up_token or step_up_header)
    setattr(user, f"{factor}_uses_login", True)
    await record_audit(db, "FACTOR_USES_LOGIN_ENABLED", actor_did=user.did, client_ip=get_request_client_ip(request),
                       details={"purpose": factor})
    await db.commit()
    return {"message": f"{mfa.PURPOSE_LABELS[factor]} now uses your login authenticator and passkey.", "factor": factor}


@router.post("/factors/{factor}/use-separate")
@limiter.limit("5/minute")
async def use_separate_factors(factor: str, request: Request, body: FactorLinkRequest = Body(default=FactorLinkRequest()),
                               step_up_header: Optional[str] = Depends(get_step_up_token),
                               user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Stop reusing the login factors for Factor 2 or Factor 3. Requires proof of the login
    factor (the factor currently protecting this purpose). The purpose then needs its own
    authenticator or passkey before it can be used again."""
    if factor not in ("factor2", "factor3"):
        raise HTTPException(status_code=404, detail="Unknown factor")
    if not mfa.uses_login(user, factor):
        raise HTTPException(status_code=409, detail="This factor doesn't use your login factors.")
    await mfa.require_factor(db, user, f"{factor}.link", totp_code=body.totp_code,
                             step_up_token=body.step_up_token or step_up_header)
    setattr(user, f"{factor}_uses_login", False)
    await record_audit(db, "FACTOR_USES_LOGIN_DISABLED", actor_did=user.did, client_ip=get_request_client_ip(request),
                       details={"purpose": factor})
    await db.commit()
    return {"message": f"{mfa.PURPOSE_LABELS[factor]} no longer uses your login factors. Set up its own authenticator or passkey.",
            "factor": factor}


# ============================================================ Admin-assisted login reset

@router.post("/reset-request")
@limiter.limit("5/minute")
async def request_admin_reset(request: Request, payload: ResetRequestPayload = Body(default=ResetRequestPayload()),
                              user: User = Depends(get_setup_user), db: AsyncSession = Depends(get_db)):
    """Signed-in user (My Identity) asks an administrator to reset login factors."""
    if await _reset_path(db, user) == "server_operator":
        raise HTTPException(status_code=409, detail="You are the only administrator, so no one in LexCorp2 can approve a reset for you. "
                                                    "The person who runs the LexCorp2 server resets it with: "
                                                    "python backend/scripts/bootstrap_admin.py --reset-login")
    user.reset_requested = True
    user.reset_requested_at = mfa.utcnow()
    user.reset_reason = (payload.reason or "")[:500]
    await record_audit(db, "LOGIN_RESET_REQUESTED", actor_did=user.did, client_ip=get_request_client_ip(request))
    await db.commit()
    return {"message": "Admin assistance requested. Your administrator will review and issue a new single-use 3-hour provisioning PIN."}


@router.post("/reset-request/wallet")
@limiter.limit("3/minute")
async def request_admin_reset_with_wallet(req: WalletResetRequestPayload, request: Request, db: AsyncSession = Depends(get_db)):
    """Locked-out user proves wallet possession (signature over a server nonce) to ask for a reset."""
    try:
        signer = await _consume_siwe(db, req.message, req.signature, req.nonce)
    except auth.AuthError as e:
        await db.commit()
        raise HTTPException(status_code=401, detail=str(e))
    user = await _find_user(db, signer)
    if _usable(user):
        user.reset_requested = True
        user.reset_requested_at = mfa.utcnow()
        user.reset_reason = (req.reason or "")[:500]
        await record_audit(db, "LOGIN_RESET_REQUESTED", actor_did=user.did, client_ip=get_request_client_ip(request),
                           details={"channel": "wallet-signature"})
    await db.commit()
    # Same response whether or not the wallet is provisioned (no account enumeration).
    return {"message": "If this wallet is provisioned, an administrator has been notified."}


@router.get("/reset-requests", response_model=List[ResetRequestResponse])
async def list_reset_requests(db: AsyncSession = Depends(get_db), admin: User = Depends(get_admin_user)):
    users = (await db.execute(
        # An administrator never sees (and can't approve) their own request.
        select(User).where(User.reset_requested.is_(True), User.is_active.is_(True), User.id != admin.id)
        .order_by(User.created_at.desc())
    )).scalars().all()
    return [ResetRequestResponse(
        id=str(u.id), wallet_address=u.wallet_address, name=u.name, department=u.department, role=u.role,
        reset_requested=bool(u.reset_requested),
        reset_requested_at=u.reset_requested_at.isoformat() if u.reset_requested_at else None,
        reset_reason=u.reset_reason,
    ) for u in users]


@router.post("/reset-approve/{user_id}")
async def approve_user_reset(
    user_id: str,
    request: Request,
    body: AdminResetApproveRequest = Body(default=AdminResetApproveRequest()),
    step_up_header: Optional[str] = Depends(get_step_up_token),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    """Approve a login reset with the admin's Factor 3. Invalidates the user's Login
    TOTP 1 and Login Passkey(s), revokes their sessions and issues a NEW single-use
    3-hour provisioning PIN (any previous PIN stops working)."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    target = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id:
        raise HTTPException(status_code=403, detail="Administrators cannot approve their own login reset.")
    if not target.reset_requested:
        raise HTTPException(status_code=409, detail="This user has no pending reset request.")

    await mfa.require_factor(db, admin, "admin.reset", totp_code=body.totp_code,
                             step_up_token=body.step_up_token or step_up_header)

    new_pin, expires_at = await mfa.reset_login_factors(db, target)
    await record_audit(
        db, "ADMIN_LOGIN_RESET_APPROVED",
        actor_did=admin.did, target_did=target.did, client_ip=get_request_client_ip(request),
        details={"invalidated": ["login_totp", "login_passkeys", "sessions", "wallet_keystore"], "pin_expires_at": expires_at.isoformat()},
    )
    await db.commit()
    return {
        "message": f"Login factors reset for {target.wallet_address}. Give the user this PIN out-of-band; it is shown only once.",
        "user_id": str(target.id),
        "wallet_address": target.wallet_address,
        "one_time_pin": new_pin,
        "pin_expires_at": expires_at.isoformat(),
    }


# ============================================================ Verifiable credentials

@router.post("/vc/issue")
async def issue_kyc_vc(subject_did: str, db: AsyncSession = Depends(get_db), admin: User = Depends(get_admin_user)):
    """Issue a W3C Verifiable Credential (admin only)."""
    subject = (await db.execute(select(User).where(User.did == subject_did))).scalar_one_or_none()
    if not subject:
        raise HTTPException(status_code=404, detail="Subject DID not found")
    vc_jwt, vc_model = vc.create_kyc_vc(admin.did, subject_did)
    vc_model.user_id = subject.id
    db.add(vc_model)
    await db.commit()
    return {"vc_jwt": vc_jwt, "subject_did": subject_did, "type": "KYCCredential"}
