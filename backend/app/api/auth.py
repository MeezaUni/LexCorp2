"""Authentication endpoints: nonce generation + SIWE verification + JWT session + 2FA WebAuthn/TOTP."""

from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Response, status, Body, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
import base64
import json
import uuid
import hashlib
import time

from app.api.dependencies import get_db, get_current_user, get_current_active_user, get_request_client_ip, get_admin_user
from app.services import auth, vc, security
from app.models.domain import User, WebAuthnCredential, AuditEvent
from app.core.config import settings
from app.core.limiter import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


class NonceResponse(BaseModel):
    nonce: str
    message: str  # Pre-built SIWE message for frontend to sign

# --- Reset Request Schemas ---
class ResetRequestPayload(BaseModel):
    wallet_address: str
    reason: Optional[str] = "User requested admin reset assistance"

class AdminResetApproveRequest(BaseModel):
    totp_code: Optional[str] = None

class ResetRequestResponse(BaseModel):
    id: str
    wallet_address: str
    name: Optional[str] = None
    department: Optional[str] = None
    role: str
    reset_requested: bool
    pin_expires_at: Optional[datetime] = None

# --- Import OTP Schema ---
class VerifyImportOTPRequest(BaseModel):
    wallet_address: str
    pin: str

# --- WebAuthn Schemas ---
class WebAuthnRegistrationRequest(BaseModel):
    device_name: Optional[str] = "Biometric Authenticator"
    factor_scope: str = "login" # 'login', 'factor2', 'factor3'

class WebAuthnRegistrationResponse(BaseModel):
    options: dict

class WebAuthnVerifyRequest(BaseModel):
    credential_id: str
    response: dict
    device_name: str
    factor_scope: str = "login"


class LoginRequest(BaseModel):
    message: str
    signature: str
    nonce: str


class LoginResponse(BaseModel):
    token: str
    user: dict


class TotpLoginRequest(BaseModel):
    wallet_address: str
    token: str


class PasskeyLoginOptionsRequest(BaseModel):
    wallet_address: str


class PasskeyLoginVerifyRequest(BaseModel):
    wallet_address: str
    credential_id: str
    response: dict


def _check_onboarding_completion(user: User):
    """Mark onboarding as complete if all 3 TOTP factors are enabled."""
    if user.is_totp_enabled and user.is_totp_factor2_enabled and user.is_totp_factor3_enabled:
        user.onboarding_pending = False

def _login_response(user: User, token: str) -> LoginResponse:
    return LoginResponse(
        token=token,
        user={
            "wallet_address": user.wallet_address,
            "did": user.did,
            "role": user.role,
            "is_active": user.is_active,
            "onboarding_pending": user.onboarding_pending,
            "is_totp_enabled": user.is_totp_enabled,
            "is_totp_factor2_enabled": user.is_totp_factor2_enabled,
            "is_totp_factor3_enabled": user.is_totp_factor3_enabled,
        },
    )


async def _record_login_event(db: AsyncSession, user: User, method: str, client_ip: str) -> None:
    """Record successful authentication, including session replacement logins."""
    tx_hash = "0x" + hashlib.sha256(f"auth:{user.wallet_address}:{method}:{time.time_ns()}".encode()).hexdigest()
    db.add(AuditEvent(
        event_type="AuthenticationSucceeded",
        tx_hash=tx_hash,
        block_number=0,
        actor_did=user.did,
        target_did=user.did,
        asset_serial=method,
        client_ip=client_ip,
    ))
    await db.commit()


@router.post("/nonce", response_model=NonceResponse)
@limiter.limit("5/minute")
async def get_nonce(address: str, request: Request):
    """Generate a fresh nonce for wallet authentication.
    Returns a pre-built SIWE message that the frontend signs.
    """
    if not address:
        raise HTTPException(status_code=400, detail="Wallet address required")

    nonce = auth.generate_nonce()
    auth.store_nonce(address, nonce)

    message = (
        f"lexcorp-sih.example.com wants you to sign in with your Ethereum account.\n"
        f"Wallet: {address}\n"
        f"Nonce: {nonce}\n"
        f"URI: https://lexcorp-sih.example.com\n"
        f"Version: 1\n"
        f"Chain ID: 13371"
    )

    return NonceResponse(nonce=nonce, message=message)


from datetime import datetime
from sqlalchemy import select

@router.post("/otp/verify-import")
@limiter.limit("5/minute")
async def verify_import_otp(
    req: VerifyImportOTPRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Verify a strict 3-hour single-use OTP for wallet import."""
    result = await db.execute(select(User).filter_by(wallet_address=req.wallet_address.lower()))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.one_time_pin or not user.pin_expires_at:
        raise HTTPException(status_code=400, detail="No active import PIN for this user")

    if user.pin_used:
        raise HTTPException(status_code=400, detail="Import PIN has already been used")

    if datetime.utcnow() > user.pin_expires_at:
        raise HTTPException(status_code=400, detail="Import PIN has expired")

    if user.one_time_pin != req.pin:
        raise HTTPException(status_code=401, detail="Invalid import PIN")

    # Mark used
    user.pin_used = True
    await db.commit()

    return {"status": "success", "message": "PIN verified successfully. Wallet import approved."}


@router.post("/vc/issue")
async def issue_kyc_vc(subject_did: str, db: AsyncSession = Depends(get_db)):
    """Issue a W3C-compliant Verifiable Credential for KYC verification."""
    issuer_did = f"did:ethr:{settings.CHAIN_ID}:0x0000000000000000000000000000000000000000"
    vc_jwt, vc_model = vc.create_kyc_vc(issuer_did, subject_did)
    try:
        from sqlalchemy import select
        res = await db.execute(select(User).filter(User.did == subject_did))
        user = res.scalar_one_or_none()
        if user:
            vc_model.user_id = user.id
            db.add(vc_model)
            await db.commit()
    except Exception:
        pass
    return {"vc_jwt": vc_jwt, "subject_did": subject_did, "type": "KYCCredential"}


@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
async def login(login_req: LoginRequest, response: Response, request: Request, db: AsyncSession = Depends(get_db)):
    """Verify SIWE signature and return JWT session token.
    On first login, automatically issues a DID to the user.
    """
    try:
        user = await auth.verify_siwe_message(
            login_req.message,
            login_req.signature,
            login_req.nonce,
            db,
        )
    except auth.AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

    user.session_version = (user.session_version or 0) + 1
    await db.commit()
    await _record_login_event(db, user, "PASSWORD", get_request_client_ip(request))
    token = auth.create_jwt(
        user.wallet_address,
        user.did,
        user.role,
        user.session_version,
        client_ip=get_request_client_ip(request)
    )

    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=1800,  # 30 minutes
    )

    return _login_response(user, token)


@router.post("/login/totp", response_model=LoginResponse)
@limiter.limit("5/minute")
async def login_with_totp(totp_req: TotpLoginRequest, response: Response, request: Request, db: AsyncSession = Depends(get_db)):
    """Authenticate with a registered mobile authenticator without wallet password."""
    from sqlalchemy import func, select

    result = await db.execute(select(User).where(func.lower(User.wallet_address) == totp_req.wallet_address.lower()))
    user = result.scalar_one_or_none()
    if not user or not user.is_active or not user.is_totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=401, detail="Mobile authenticator is not enabled for this wallet.")
    if not security.verify_totp(user.totp_secret, totp_req.token):
        raise HTTPException(status_code=401, detail="Invalid or expired mobile authenticator code.")

    user.session_version = (user.session_version or 0) + 1
    await db.commit()
    await _record_login_event(db, user, "MOBILE_AUTHENTICATOR", get_request_client_ip(request))
    token = auth.create_jwt(
        user.wallet_address,
        user.did,
        user.role,
        user.session_version,
        client_ip=get_request_client_ip(request)
    )
    response.set_cookie(key="session", value=token, httponly=True, samesite="lax", max_age=1800)
    return _login_response(user, token)


@router.post("/login/passkey/options")
@limiter.limit("5/minute")
async def get_passkey_login_options(options_req: PasskeyLoginOptionsRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Create a WebAuthn challenge for passwordless passkey login."""
    from sqlalchemy import func, select
    import webauthn

    result = await db.execute(select(User).where(func.lower(User.wallet_address) == options_req.wallet_address.lower()))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Wallet identity not found.")

    credentials = (await db.execute(select(WebAuthnCredential).where(
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.is_active.is_(True),
    ))).scalars().all()
    if not credentials:
        raise HTTPException(status_code=400, detail="No active passkey is registered for this wallet.")

    # Validate origin and use static RP_ID
    origin = request.headers.get("origin")
    if not origin or origin not in settings.WEBAUTHN_ORIGINS:
        raise HTTPException(status_code=400, detail="Invalid origin")

    rp_id = settings.RP_ID
    options = security.generate_webauthn_login_options(
        [bytes.fromhex(credential.credential_id) for credential in credentials],
        rp_id=rp_id,
    )
    options_json = json.loads(webauthn.options_to_json(options))
    auth.store_challenge(str(user.id), "login", options_json["challenge"])
    return {"options": options_json}


@router.post("/login/passkey/verify", response_model=LoginResponse)
@limiter.limit("5/minute")
async def login_with_passkey(passkey_req: PasskeyLoginVerifyRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """Verify a WebAuthn assertion and issue a passwordless session."""
    from sqlalchemy import func, select
    import webauthn
    from webauthn.helpers import base64url_to_bytes

    result = await db.execute(select(User).where(func.lower(User.wallet_address) == passkey_req.wallet_address.lower()))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Wallet identity not found.")

    credential = (await db.execute(select(WebAuthnCredential).where(
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.credential_id == passkey_req.credential_id,
        WebAuthnCredential.is_active.is_(True),
    ))).scalar_one_or_none()
    challenge = auth.get_challenge(str(user.id), "login")
    if not credential or not challenge:
        raise HTTPException(status_code=401, detail="Passkey challenge or credential not found.")

    origin = request.headers.get("origin")
    if not origin or origin not in settings.WEBAUTHN_ORIGINS:
        raise HTTPException(status_code=400, detail="Invalid origin for WebAuthn")

    rp_id = settings.RP_ID

    try:
        verification = webauthn.verify_authentication_response(
            credential=passkey_req.response,
            expected_challenge=base64url_to_bytes(challenge),
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=bytes.fromhex(credential.public_key),
            credential_current_sign_count=credential.sign_count,
            require_user_verification=False,
        )
    except Exception as error:
        raise HTTPException(status_code=401, detail=f"Passkey verification failed: {error}")

    credential.sign_count = verification.new_sign_count
    await db.commit()
    user.session_version = (user.session_version or 0) + 1
    await db.commit()
    await _record_login_event(db, user, "PASSKEY", get_request_client_ip(request))
    token = auth.create_jwt(
        user.wallet_address,
        user.did,
        user.role,
        user.session_version,
        client_ip=get_request_client_ip(request)
    )
    response.set_cookie(key="session", value=token, httponly=True, samesite="lax", max_age=1800)
    return _login_response(user, token)


@router.get("/me")
async def get_current_user_profile(user: User = Depends(get_current_active_user)):
    """Get current authenticated user's profile and security settings."""
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
        "reset_requested": user.reset_requested or False
    }


# --- TOTP (RFC 6238) Setup & Verification ---

@router.post("/2fa/setup")
@limiter.limit("5/minute")
async def setup_totp(request: Request, user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Generate a new TOTP secret for the user to scan via Google Authenticator."""
    if user.is_totp_enabled:
        raise HTTPException(status_code=400, detail="TOTP 2FA is already enabled.")

    secret = security.generate_totp_secret()
    uri = security.get_totp_uri(user.name or user.wallet_address, secret)

    user.totp_secret = secret
    await db.commit()

    return {"secret": secret, "uri": uri}


@router.post("/2fa/verify")
@limiter.limit("5/minute")
async def verify_totp_setup(request: Request, token: str = Body(..., embed=True), user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Verify the TOTP code to finalize tracking."""
    import logging
    logger = logging.getLogger(__name__)

    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP setup not initiated.")

    logger.info(f"TOTP verification attempt for user {user.wallet_address}")

    if security.verify_totp(user.totp_secret, token):
        user.is_totp_enabled = True

        # Check if user has an active login passkey
        from sqlalchemy import select
        res = await db.execute(
            select(WebAuthnCredential).filter(
                WebAuthnCredential.user_id == user.id,
                WebAuthnCredential.is_active.is_(True),
                WebAuthnCredential.factor_scope == "login"
            )
        )
        has_login_passkey = res.scalars().first() is not None

        _check_onboarding_completion(user)
        if has_login_passkey:
            user.onboarding_pending = False

        await db.commit()
        logger.info(f"TOTP successfully enabled for user {user.wallet_address}")
        return {"message": "TOTP successfully enabled.", "onboarding_pending": user.onboarding_pending}

    raise HTTPException(status_code=401, detail="Invalid or expired TOTP code. Please ensure your device clock is synchronized and try with a fresh code.")


@router.post("/2fa/validate")
@limiter.limit("5/minute")
async def validate_totp(request: Request, token: str = Body(..., embed=True), user: User = Depends(get_current_active_user)):
    """Validate a 2FA code during high-security actions without modifying state."""
    import logging
    logger = logging.getLogger(__name__)

    if not user.is_totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP is not enabled for this user.")

    logger.info(f"TOTP validation attempt for user {user.wallet_address}")

    if security.verify_totp(user.totp_secret, token):
        return {"valid": True}

    raise HTTPException(status_code=401, detail="Invalid or expired TOTP code. Please ensure your device clock is synchronized and try with a fresh code.")


@router.post("/2fa/disable")
async def disable_totp(user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Disable mobile authenticator authentication for the current user."""
    user.is_totp_enabled = False
    user.totp_secret = None
    await db.commit()
    return {"message": "Mobile authenticator disabled.", "is_totp_enabled": False}


@router.post("/2fa/reset")
async def reset_totp(user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Clear the mobile authenticator so a new device can be enrolled."""
    user.is_totp_enabled = False
    user.totp_secret = None
    await db.commit()
    return {"message": "Mobile authenticator reset.", "is_totp_enabled": False}


# --- Factor 2 TOTP (View / Submission Factor) ---

@router.post("/2fa/factor2/setup")
@limiter.limit("5/minute")
async def setup_totp_factor2(request: Request, user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Generate a new Factor 2 TOTP secret for document view & submission authorizations."""
    if user.is_totp_factor2_enabled:
        raise HTTPException(status_code=400, detail="Factor 2 (View/Submission) TOTP is already enabled.")

    secret = security.generate_totp_secret()
    uri = security.get_totp_uri(
        user.name or user.wallet_address,
        secret,
        issuer_name="LexCorp - Factor 2 (View/Submission)"
    )

    user.totp_factor2_secret = secret
    await db.commit()

    return {"secret": secret, "uri": uri}


@router.post("/2fa/factor2/verify")
@limiter.limit("5/minute")
async def verify_totp_factor2_setup(
    request: Request,
    token: str = Body(..., embed=True),
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify Factor 2 TOTP code to finalize enrollment."""
    if not user.totp_factor2_secret:
        raise HTTPException(status_code=400, detail="Factor 2 TOTP setup not initiated.")

    if security.verify_totp(user.totp_factor2_secret, token):
        user.is_totp_factor2_enabled = True
        _check_onboarding_completion(user)
        await db.commit()
        return {"message": "Factor 2 (View/Submission) TOTP successfully enabled.", "is_totp_factor2_enabled": True, "onboarding_pending": user.onboarding_pending}

    raise HTTPException(status_code=401, detail="Invalid or expired Factor 2 TOTP code. Please verify your device clock.")


@router.post("/2fa/factor2/validate")
@limiter.limit("10/minute")
async def validate_totp_factor2(
    request: Request,
    token: str = Body(..., embed=True),
    user: User = Depends(get_current_active_user)
):
    """Validate a Factor 2 TOTP code before allowing document view or submission."""
    if not user.is_totp_factor2_enabled or not user.totp_factor2_secret:
        raise HTTPException(status_code=400, detail="Factor 2 TOTP is not enabled for this user.")

    if security.verify_totp(user.totp_factor2_secret, token):
        return {"valid": True}

    raise HTTPException(status_code=401, detail="Invalid or expired Factor 2 TOTP code.")


@router.post("/2fa/factor2/disable")
async def disable_totp_factor2(user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Disable Factor 2 TOTP for the current user."""
    user.is_totp_factor2_enabled = False
    user.totp_factor2_secret = None
    await db.commit()
    return {"message": "Factor 2 (View/Submission) TOTP disabled.", "is_totp_factor2_enabled": False}


@router.post("/2fa/factor2/reset")
async def reset_totp_factor2(user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Clear Factor 2 TOTP secret for re-enrollment."""
    user.is_totp_factor2_enabled = False
    user.totp_factor2_secret = None
    await db.commit()
    return {"message": "Factor 2 TOTP reset.", "is_totp_factor2_enabled": False}


# --- Factor 3 TOTP (Mint / Approval / Revision Factor) ---

@router.post("/2fa/factor3/setup")
@limiter.limit("5/minute")
async def setup_totp_factor3(request: Request, user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Generate a new Factor 3 TOTP secret for mint, approval, and revision authorizations."""
    if user.is_totp_factor3_enabled:
        raise HTTPException(status_code=400, detail="Factor 3 (Mint/Approval/Revision) TOTP is already enabled.")

    secret = security.generate_totp_secret()
    uri = security.get_totp_uri(
        user.name or user.wallet_address,
        secret,
        issuer_name="LexCorp - Factor 3 (Mint/Approve/Revise)"
    )

    user.totp_factor3_secret = secret
    await db.commit()

    return {"secret": secret, "uri": uri}


@router.post("/2fa/factor3/verify")
@limiter.limit("5/minute")
async def verify_totp_factor3_setup(
    request: Request,
    token: str = Body(..., embed=True),
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify Factor 3 TOTP code to finalize enrollment."""
    if not user.totp_factor3_secret:
        raise HTTPException(status_code=400, detail="Factor 3 TOTP setup not initiated.")

    if security.verify_totp(user.totp_factor3_secret, token):
        user.is_totp_factor3_enabled = True
        _check_onboarding_completion(user)
        await db.commit()
        return {"message": "Factor 3 (Mint/Approval/Revision) TOTP successfully enabled.", "is_totp_factor3_enabled": True, "onboarding_pending": user.onboarding_pending}

    raise HTTPException(status_code=401, detail="Invalid or expired Factor 3 TOTP code. Please verify your device clock.")


@router.post("/2fa/factor3/validate")
@limiter.limit("10/minute")
async def validate_totp_factor3(
    request: Request,
    token: str = Body(..., embed=True),
    user: User = Depends(get_current_active_user)
):
    """Validate a Factor 3 TOTP code before allowing mint, approval, or revision."""
    if not user.is_totp_factor3_enabled or not user.totp_factor3_secret:
        raise HTTPException(status_code=400, detail="Factor 3 TOTP is not enabled for this user.")

    if security.verify_totp(user.totp_factor3_secret, token):
        return {"valid": True}

    raise HTTPException(status_code=401, detail="Invalid or expired Factor 3 TOTP code.")


@router.post("/2fa/factor3/disable")
async def disable_totp_factor3(user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Disable Factor 3 TOTP for the current user."""
    user.is_totp_factor3_enabled = False
    user.totp_factor3_secret = None
    await db.commit()
    return {"message": "Factor 3 (Mint/Approval/Revision) TOTP disabled.", "is_totp_factor3_enabled": False}


@router.post("/2fa/factor3/reset")
async def reset_totp_factor3(user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Clear Factor 3 TOTP secret for re-enrollment."""
    user.is_totp_factor3_enabled = False
    user.totp_factor3_secret = None
    await db.commit()
    return {"message": "Factor 3 TOTP reset.", "is_totp_factor3_enabled": False}


# --- WebAuthn (Passkeys / Biometrics) ---

@router.post("/webauthn/register/options", response_model=WebAuthnRegistrationResponse)
@limiter.limit("5/minute")
async def get_webauthn_registration_options(
    reg_req: WebAuthnRegistrationRequest,
    request: Request,
    user: User = Depends(get_current_active_user)
):
    """Generate options to start WebAuthn registration."""
    # Explicit RP ID from config
    rp_id = settings.RP_ID

    options = security.generate_webauthn_registration_options(
        str(user.id),
        user.name or user.wallet_address,
        rp_id=rp_id
    )

    import webauthn
    options_json = json.loads(webauthn.options_to_json(options))
    auth.store_challenge(str(user.id), "registration", options_json["challenge"])

    return {"options": options_json}

class WebAuthnLoginOptionsResponse(BaseModel):
    options: dict

class WebAuthnLoginVerifyRequest(BaseModel):
    credential_id: str
    response: dict

@router.post("/webauthn/login/options", response_model=WebAuthnLoginOptionsResponse)
async def get_webauthn_login_options(
    req: Request,
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate options to start WebAuthn authentication (login) for 2FA/step-up."""
    from sqlalchemy import select
    res = await db.execute(select(WebAuthnCredential).filter(WebAuthnCredential.user_id == user.id))
    creds = res.scalars().all()
    if not creds:
        raise HTTPException(status_code=400, detail="No WebAuthn credentials registered for this user.")

    # Parse hex credential IDs back to bytes
    cred_ids = [bytes.fromhex(c.credential_id) for c in creds]
    rp_id = settings.RP_ID

    options = security.generate_webauthn_login_options(cred_ids, rp_id=rp_id)

    import webauthn
    options_json = json.loads(webauthn.options_to_json(options))
    auth.store_challenge(str(user.id), "login", options_json["challenge"])

    return {"options": options_json}

@router.post("/webauthn/login/verify")
async def verify_webauthn_login(
    request: WebAuthnLoginVerifyRequest,
    req: Request,
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify WebAuthn authentication response."""
    import logging
    import webauthn
    from webauthn.helpers import base64url_to_bytes
    from sqlalchemy import select

    logger = logging.getLogger(__name__)

    challenge = auth.get_challenge(str(user.id), "login")
    if not challenge:
        logger.warning(f"WebAuthn challenge not found for user {user.id}")
        raise HTTPException(status_code=400, detail="Challenge not found or expired. Please retry.")

    origin = req.headers.get("origin")
    if not origin or origin not in settings.WEBAUTHN_ORIGINS:
        raise HTTPException(status_code=400, detail="Invalid origin for WebAuthn")

    rp_id = settings.RP_ID

    logger.info(f"WebAuthn verify attempt: rp_id={rp_id}, origin={origin}")

    # Retrieve credential from DB
    res = await db.execute(select(WebAuthnCredential).filter(
        WebAuthnCredential.credential_id == request.credential_id,
        WebAuthnCredential.user_id == user.id
    ))
    db_cred = res.scalar_one_or_none()

    if not db_cred:
        logger.warning(f"WebAuthn credential not found: {request.credential_id}")
        raise HTTPException(status_code=404, detail="Credential not found")

    try:
        verification = webauthn.verify_authentication_response(
            credential=request.response,
            expected_challenge=base64url_to_bytes(challenge) if isinstance(challenge, str) else challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=bytes.fromhex(db_cred.public_key) if isinstance(db_cred.public_key, str) and len(db_cred.public_key)>64 else db_cred.public_key.encode() if isinstance(db_cred.public_key, str) else db_cred.public_key,
            credential_current_sign_count=db_cred.sign_count,
            require_user_verification=False
        )

        # Update sign count
        db_cred.sign_count = verification.new_sign_count
        await db.commit()

        logger.info(f"WebAuthn verification successful for user {user.id}")
        return {"message": "WebAuthn authentication successful", "valid": True}

    except Exception as e:
        logger.error(f"WebAuthn verification failed: {e}")
        raise HTTPException(status_code=400, detail=f"WebAuthn verification failed: {str(e)}")


# --- Purpose-Bound Factor 2 (View / Submission) WebAuthn ---

@router.post("/webauthn/factor2/options", response_model=WebAuthnLoginOptionsResponse)
async def get_webauthn_factor2_options(
    req: Request,
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate options to start WebAuthn authentication specifically for Factor 2 (View/Submission)."""
    from sqlalchemy import select
    res = await db.execute(select(WebAuthnCredential).filter(WebAuthnCredential.user_id == user.id, WebAuthnCredential.is_active.is_(True)))
    creds = res.scalars().all()
    if not creds:
        raise HTTPException(status_code=400, detail="No active WebAuthn credentials registered for this user.")

    cred_ids = [bytes.fromhex(c.credential_id) for c in creds]
    rp_id = settings.RP_ID
    options = security.generate_webauthn_login_options(cred_ids, rp_id=rp_id)

    import webauthn
    options_json = json.loads(webauthn.options_to_json(options))
    auth.store_challenge(str(user.id), "factor2", options_json["challenge"])

    return {"options": options_json}


@router.post("/webauthn/factor2/verify")
async def verify_webauthn_factor2(
    request: WebAuthnLoginVerifyRequest,
    req: Request,
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify WebAuthn authentication specifically for Factor 2 (View/Submission)."""
    import logging
    import webauthn
    from webauthn.helpers import base64url_to_bytes
    from sqlalchemy import select

    logger = logging.getLogger(__name__)

    challenge = auth.get_challenge(str(user.id), "factor2")
    if not challenge:
        logger.warning(f"WebAuthn factor 2 challenge not found for user {user.id}")
        raise HTTPException(status_code=400, detail="Factor 2 challenge not found or expired. Please retry.")

    origin = req.headers.get("origin")
    if not origin or origin not in settings.WEBAUTHN_ORIGINS:
        raise HTTPException(status_code=400, detail="Invalid origin for WebAuthn")

    rp_id = settings.RP_ID

    res = await db.execute(select(WebAuthnCredential).filter(
        WebAuthnCredential.credential_id == request.credential_id,
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.is_active.is_(True)
    ))
    db_cred = res.scalar_one_or_none()

    if not db_cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    try:
        verification = webauthn.verify_authentication_response(
            credential=request.response,
            expected_challenge=base64url_to_bytes(challenge) if isinstance(challenge, str) else challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=bytes.fromhex(db_cred.public_key) if isinstance(db_cred.public_key, str) and len(db_cred.public_key)>64 else db_cred.public_key.encode() if isinstance(db_cred.public_key, str) else db_cred.public_key,
            credential_current_sign_count=db_cred.sign_count,
            require_user_verification=False
        )

        db_cred.sign_count = verification.new_sign_count
        await db.commit()

        # Mark assertion as verified for factor2
        auth.verify_assertion(str(user.id), "factor2")

        logger.info(f"WebAuthn Factor 2 verification successful for user {user.id}")
        return {"message": "WebAuthn Factor 2 verification successful", "valid": True}

    except Exception as e:
        logger.error(f"WebAuthn Factor 2 verification failed: {e}")
        raise HTTPException(status_code=400, detail=f"WebAuthn Factor 2 verification failed: {str(e)}")


# --- Purpose-Bound Factor 3 (Mint / Approval / Modification) WebAuthn ---

@router.post("/webauthn/factor3/options", response_model=WebAuthnLoginOptionsResponse)
async def get_webauthn_factor3_options(
    req: Request,
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate options to start WebAuthn authentication specifically for Factor 3 (Mint/Approval/Modification)."""
    from sqlalchemy import select
    res = await db.execute(select(WebAuthnCredential).filter(WebAuthnCredential.user_id == user.id, WebAuthnCredential.is_active.is_(True)))
    creds = res.scalars().all()
    if not creds:
        raise HTTPException(status_code=400, detail="No active WebAuthn credentials registered for this user.")

    cred_ids = [bytes.fromhex(c.credential_id) for c in creds]
    rp_id = settings.RP_ID
    options = security.generate_webauthn_login_options(cred_ids, rp_id=rp_id)

    import webauthn
    options_json = json.loads(webauthn.options_to_json(options))
    auth.store_challenge(str(user.id), "factor3", options_json["challenge"])

    return {"options": options_json}


@router.post("/webauthn/factor3/verify")
async def verify_webauthn_factor3(
    request: WebAuthnLoginVerifyRequest,
    req: Request,
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify WebAuthn authentication specifically for Factor 3 (Mint/Approval/Modification)."""
    import logging
    import webauthn
    from webauthn.helpers import base64url_to_bytes
    from sqlalchemy import select

    logger = logging.getLogger(__name__)

    challenge = auth.get_challenge(str(user.id), "factor3")
    if not challenge:
        logger.warning(f"WebAuthn factor 3 challenge not found for user {user.id}")
        raise HTTPException(status_code=400, detail="Factor 3 challenge not found or expired. Please retry.")

    origin = req.headers.get("origin")
    if not origin or origin not in settings.WEBAUTHN_ORIGINS:
        raise HTTPException(status_code=400, detail="Invalid origin for WebAuthn")

    rp_id = settings.RP_ID

    res = await db.execute(select(WebAuthnCredential).filter(
        WebAuthnCredential.credential_id == request.credential_id,
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.is_active.is_(True)
    ))
    db_cred = res.scalar_one_or_none()

    if not db_cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    try:
        verification = webauthn.verify_authentication_response(
            credential=request.response,
            expected_challenge=base64url_to_bytes(challenge) if isinstance(challenge, str) else challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=bytes.fromhex(db_cred.public_key) if isinstance(db_cred.public_key, str) and len(db_cred.public_key)>64 else db_cred.public_key.encode() if isinstance(db_cred.public_key, str) else db_cred.public_key,
            credential_current_sign_count=db_cred.sign_count,
            require_user_verification=False
        )

        db_cred.sign_count = verification.new_sign_count
        await db.commit()

        # Mark assertion as verified for factor3
        auth.verify_assertion(str(user.id), "factor3")

        logger.info(f"WebAuthn Factor 3 verification successful for user {user.id}")
        return {"message": "WebAuthn Factor 3 verification successful", "valid": True}

    except Exception as e:
        logger.error(f"WebAuthn Factor 3 verification failed: {e}")
        raise HTTPException(status_code=400, detail=f"WebAuthn Factor 3 verification failed: {str(e)}")



@router.post("/webauthn/register/verify")
@limiter.limit("5/minute")
async def verify_webauthn_registration(
    request: Request,
    payload: WebAuthnVerifyRequest = Body(...),
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify WebAuthn registration response and save credential."""
    import logging
    import webauthn
    from webauthn.helpers import base64url_to_bytes

    logger = logging.getLogger(__name__)

    challenge = auth.get_challenge(str(user.id), "registration")
    if not challenge:
        logger.warning(f"WebAuthn registration challenge not found for user {user.id}")
        raise HTTPException(status_code=400, detail="Challenge not found or expired. Please retry registration.")

    origin = request.headers.get("origin")
    if not origin or origin not in settings.WEBAUTHN_ORIGINS:
        raise HTTPException(status_code=400, detail="Invalid origin for WebAuthn")

    rp_id = settings.RP_ID

    logger.info(f"WebAuthn registration verify: rp_id={rp_id}, origin={origin}")

    try:
        verification = webauthn.verify_registration_response(
            credential=payload.response,
            expected_challenge=base64url_to_bytes(challenge) if isinstance(challenge, str) else challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            require_user_verification=False, # Relaxed for some environments
        )
        logger.info("WebAuthn verification succeeded.")

        # Save new credential
        logger.info(f"Credential ID: {verification.credential_id}")
        logger.info(f"Public Key: {verification.credential_public_key}")

        new_cred = WebAuthnCredential(
            user_id=user.id,
            credential_id=verification.credential_id.hex(),
            public_key=verification.credential_public_key.hex() if isinstance(verification.credential_public_key, bytes) else str(verification.credential_public_key),
            sign_count=verification.sign_count,
            device_name=payload.device_name,
            factor_scope=payload.factor_scope
        )
        db.add(new_cred)
        logger.info("Credential added to DB.")

        if user.is_totp_enabled and payload.factor_scope == "login":
            user.onboarding_pending = False

        await db.commit()
        logger.info("Credential committed to DB.")

        logger.info(f"WebAuthn credential registered successfully for user {user.id}")
        return {"message": "WebAuthn credential registered successfully"}
    except Exception as e:
        logger.error(f"WebAuthn registration verification failed: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"WebAuthn verification failed: {str(e)}")


@router.get("/webauthn/credentials")
async def list_webauthn_credentials(
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """List active passkeys without exposing credential public keys."""
    from sqlalchemy import select

    result = await db.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.is_active.is_(True),
        ).order_by(WebAuthnCredential.created_at.desc())
    )
    return [{
        "credential_id": credential.credential_id,
        "device_name": credential.device_name,
        "factor_scope": credential.factor_scope or "login",
        "created_at": credential.created_at.isoformat(),
    } for credential in result.scalars().all()]


@router.delete("/webauthn/credentials/{credential_id}")
async def disable_webauthn_credential(
    credential_id: str,
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable one passkey for the current user."""
    from sqlalchemy import select

    result = await db.execute(select(WebAuthnCredential).where(
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.credential_id == credential_id,
        WebAuthnCredential.is_active.is_(True),
    ))
    credential = result.scalar_one_or_none()
    if not credential:
        raise HTTPException(status_code=404, detail="Passkey not found")
    credential.is_active = False
    await db.commit()
    return {"message": "Passkey disabled.", "credential_id": credential_id}


@router.post("/webauthn/reset")
async def reset_webauthn_credentials(
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable all passkeys so the user can enroll a new authenticator."""
    from sqlalchemy import update

    await db.execute(
        update(WebAuthnCredential)
        .where(WebAuthnCredential.user_id == user.id)
        .values(is_active=False)
    )
    await db.commit()
    return {"message": "All passkeys reset.", "credentials": []}


# --- Admin Assistance Login Factor Reset Workflow ---

@router.post("/reset-request")
@limiter.limit("5/minute")
async def request_admin_reset(
    request: Request,
    payload: ResetRequestPayload,
    db: AsyncSession = Depends(get_db)
):
    """Request admin assistance to reset Login Authenticator and Login Passkey."""
    from sqlalchemy import select, func
    res = await db.execute(select(User).where(func.lower(User.wallet_address) == payload.wallet_address.lower()))
    target_user = res.scalar_one_or_none()

    if not target_user:
        raise HTTPException(status_code=404, detail="User with this wallet address not found")

    target_user.reset_requested = True
    await db.commit()
    return {"message": "Admin assistance requested. Your administrator will review and issue a new single-use 3-hour import PIN."}


@router.get("/reset-requests", response_model=List[ResetRequestResponse])
async def list_reset_requests(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_admin_user)
):
    """List all users who have requested admin assistance for login factor resets."""
    from sqlalchemy import select
    res = await db.execute(
        select(User).where(User.reset_requested.is_(True), User.is_active.is_(True)).order_by(User.created_at.desc())
    )
    users = res.scalars().all()
    return [
        ResetRequestResponse(
            id=str(u.id),
            wallet_address=u.wallet_address,
            name=u.name,
            department=u.department,
            role=u.role,
            reset_requested=u.reset_requested or False,
            pin_expires_at=u.pin_expires_at
        )
        for u in users
    ]


@router.post("/reset-approve/{user_id}")
async def approve_user_reset(
    user_id: str,
    body: AdminResetApproveRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_admin_user)
):
    """Approve user login reset using Admin's Factor 3 authentication."""
    from sqlalchemy import select, update
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    res = await db.execute(select(User).where(User.id == uid))
    target_user = res.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify Admin's Factor 3: either WebAuthn Factor 3 or TOTP Factor 3
    is_passkey_valid = auth.is_assertion_valid(str(admin.id), "factor3")
    is_totp_valid = bool(body.totp_code and admin.totp_factor3_secret and security.verify_totp(admin.totp_factor3_secret, body.totp_code))

    if not (is_totp_valid or is_passkey_valid):
        raise HTTPException(
            status_code=401,
            detail="Admin Factor 3 (Mint/Approve/Modify) TOTP or Passkey validation required to approve reset"
        )

    # Invalidate target user's login factors
    target_user.is_totp_enabled = False
    target_user.totp_secret = None
    target_user.is_totp_factor2_enabled = False
    target_user.totp_factor2_secret = None
    target_user.is_totp_factor3_enabled = False
    target_user.totp_factor3_secret = None

    # Invalidate ALL passkeys for this user
    await db.execute(
        update(WebAuthnCredential)
        .where(WebAuthnCredential.user_id == target_user.id)
        .values(is_active=False)
    )

    # Generate new random 3-hour single-use OTP
    new_pin = security.generate_one_time_pin(12)
    new_expiry = datetime.utcnow() + timedelta(hours=3)

    target_user.one_time_pin = new_pin
    target_user.pin_expires_at = new_expiry
    target_user.pin_used = False
    target_user.onboarding_pending = True
    target_user.reset_requested = False

    await db.commit()
    await db.refresh(target_user)

    return {
        "message": f"Successfully reset login factors for {target_user.wallet_address}.",
        "user_id": str(target_user.id),
        "wallet_address": target_user.wallet_address,
        "one_time_pin": new_pin,
        "pin_expires_at": new_expiry.isoformat() + "Z"
    }


