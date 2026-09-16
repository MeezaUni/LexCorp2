"""Authentication endpoints: nonce generation + SIWE verification + JWT session + 2FA WebAuthn/TOTP."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Response, status, Body, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
import base64
import json
import uuid

from app.api.dependencies import get_db, get_current_user, get_current_active_user
from app.services import auth, vc, security
from app.models.domain import User, WebAuthnCredential
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])


class NonceResponse(BaseModel):
    nonce: str
    message: str  # Pre-built SIWE message for frontend to sign

# --- WebAuthn Schemas ---
class WebAuthnRegistrationRequest(BaseModel):
    device_name: Optional[str] = "Biometric Authenticator"

class WebAuthnRegistrationResponse(BaseModel):
    options: dict

class WebAuthnVerifyRequest(BaseModel):
    credential_id: str
    response: dict
    device_name: str


class LoginRequest(BaseModel):
    message: str
    signature: str
    nonce: str


class LoginResponse(BaseModel):
    token: str
    user: dict


@router.post("/nonce", response_model=NonceResponse)
async def get_nonce(address: str):
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
        f"Chain ID: 31337"
    )

    return NonceResponse(nonce=nonce, message=message)


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    """Verify SIWE signature and return JWT session token.
    On first login, automatically issues a DID to the user.
    """
    try:
        user = await auth.verify_siwe_message(
            request.message,
            request.signature,
            request.nonce,
            db,
        )
    except auth.AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))

    token = auth.create_jwt(user.wallet_address, user.did, user.role)

    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=1800,  # 30 minutes
    )

    return LoginResponse(
        token=token,
        user={
            "wallet_address": user.wallet_address,
            "did": user.did,
            "role": user.role,
            "is_active": user.is_active,
            "is_totp_enabled": user.is_totp_enabled
        },
    )


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
        "is_totp_enabled": user.is_totp_enabled
    }


# --- TOTP (RFC 6238) Setup & Verification ---

@router.post("/2fa/setup")
async def setup_totp(user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Generate a new TOTP secret for the user to scan via Google Authenticator."""
    if user.is_totp_enabled:
        raise HTTPException(status_code=400, detail="TOTP 2FA is already enabled.")

    secret = security.generate_totp_secret()
    uri = security.get_totp_uri(user.name or user.wallet_address, secret)

    user.totp_secret = secret
    await db.commit()

    return {"secret": secret, "uri": uri}


@router.post("/2fa/verify")
async def verify_totp_setup(token: str = Body(..., embed=True), user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    """Verify the TOTP code to finalize tracking."""
    import logging
    logger = logging.getLogger(__name__)

    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP setup not initiated.")

    logger.info(f"TOTP verification attempt for user {user.wallet_address}")

    if security.verify_totp(user.totp_secret, token):
        user.is_totp_enabled = True
        await db.commit()
        logger.info(f"TOTP successfully enabled for user {user.wallet_address}")
        return {"message": "TOTP successfully enabled."}

    raise HTTPException(status_code=401, detail="Invalid or expired TOTP code. Please ensure your device clock is synchronized and try with a fresh code.")


@router.post("/2fa/validate")
async def validate_totp(token: str = Body(..., embed=True), user: User = Depends(get_current_active_user)):
    """Validate a 2FA code during high-security actions without modifying state."""
    import logging
    logger = logging.getLogger(__name__)

    if not user.is_totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP is not enabled for this user.")

    logger.info(f"TOTP validation attempt for user {user.wallet_address}")

    if security.verify_totp(user.totp_secret, token):
        return {"valid": True}

    raise HTTPException(status_code=401, detail="Invalid or expired TOTP code. Please ensure your device clock is synchronized and try with a fresh code.")


# --- WebAuthn (Passkeys / Biometrics) ---

@router.post("/webauthn/register/options", response_model=WebAuthnRegistrationResponse)
async def get_webauthn_registration_options(
    request: WebAuthnRegistrationRequest,
    req: Request,
    user: User = Depends(get_current_active_user)
):
    """Generate options to start WebAuthn registration."""
    # Use localhost or request host as RP ID
    rp_id = req.url.hostname or "localhost"
    if rp_id in ("127.0.0.1", "::1"):
        rp_id = "localhost"

    options = security.generate_webauthn_registration_options(
        str(user.id),
        user.name or user.wallet_address,
        rp_id=rp_id
    )

    import webauthn
    options_json = json.loads(webauthn.options_to_json(options))
    auth.store_challenge(str(user.id), options_json["challenge"])

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
    rp_id = req.url.hostname or "localhost"
    if rp_id in ("127.0.0.1", "::1"):
        rp_id = "localhost"

    options = security.generate_webauthn_login_options(cred_ids, rp_id=rp_id)

    import webauthn
    options_json = json.loads(webauthn.options_to_json(options))
    auth.store_challenge(str(user.id), options_json["challenge"])

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

    challenge = auth.get_challenge(str(user.id))
    if not challenge:
        logger.warning(f"WebAuthn challenge not found for user {user.id}")
        raise HTTPException(status_code=400, detail="Challenge not found or expired. Please retry.")

    origin = req.headers.get("origin", "http://localhost:5173")
    rp_id = req.url.hostname or "localhost"
    if rp_id in ("127.0.0.1", "::1"):
        rp_id = "localhost"

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


@router.post("/webauthn/register/verify")
async def verify_webauthn_registration(
    request: WebAuthnVerifyRequest,
    req: Request,
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify WebAuthn registration response and save credential."""
    import logging
    import webauthn
    from webauthn.helpers import base64url_to_bytes

    logger = logging.getLogger(__name__)

    challenge = auth.get_challenge(str(user.id))
    if not challenge:
        logger.warning(f"WebAuthn registration challenge not found for user {user.id}")
        raise HTTPException(status_code=400, detail="Challenge not found or expired. Please retry registration.")

    origin = req.headers.get("origin", "http://localhost:5173")
    rp_id = req.url.hostname or "localhost"
    if rp_id in ("127.0.0.1", "::1"):
        rp_id = "localhost"

    logger.info(f"WebAuthn registration verify: rp_id={rp_id}, origin={origin}")

    try:
        verification = webauthn.verify_registration_response(
            credential=request.response,
            expected_challenge=base64url_to_bytes(challenge) if isinstance(challenge, str) else challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            require_user_verification=False, # Relaxed for some environments
        )

        # Save new credential
        new_cred = WebAuthnCredential(
            user_id=user.id,
            credential_id=verification.credential_id.hex(),
            public_key=verification.credential_public_key.hex() if isinstance(verification.credential_public_key, bytes) else str(verification.credential_public_key),
            sign_count=verification.sign_count,
            device_name=request.device_name
        )
        db.add(new_cred)
        await db.commit()

        logger.info(f"WebAuthn credential registered successfully for user {user.id}")
        return {"message": "WebAuthn credential registered successfully"}
    except Exception as e:
        logger.error(f"WebAuthn registration verification failed: {e}")
        raise HTTPException(status_code=400, detail=f"WebAuthn verification failed: {str(e)}")

