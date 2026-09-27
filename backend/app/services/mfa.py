"""Purpose-specific authentication: TOTP (with replay protection), WebAuthn passkeys,
server-side challenges and single-use step-up grants.

Three purposes, each with its own TOTP secret and its own passkey scope:
  login    - TOTP 1 / Passkey 1   (session establishment)
  factor2  - TOTP 2 / Passkey 2   (view + document submission)
  factor3  - TOTP 3 / Passkey 3   (mint + approve + modify + download + admin actions)

A factor for one purpose never satisfies another: TOTP codes are checked against
that purpose's secret only, and passkey assertions are accepted only from a
credential registered under that purpose's scope.

Opt-in reuse: a person may choose (with proof of their login factor) that Factor 2
and/or Factor 3 use the login authenticator and login passkey instead of separate
ones (User.factor2_uses_login / factor3_uses_login). Every check then resolves that
purpose to its source, "login" (source_purpose). Step-up proofs stay single-use and
bound to one action, and a linked purpose shares the login replay counter, so a code
accepted once (for sign-in or any action) cannot be accepted again.
"""

import ipaddress
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timedelta, UTC
from typing import Optional
from urllib.parse import urlparse

import pyotp
import webauthn
from fastapi import HTTPException
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, parse_client_data_json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

from app.core.config import settings
from app.core.crypto import decrypt_secret, encrypt_secret, sha256_hex
from app.models.domain import AuthChallenge, StepUpGrant, User, WebAuthnCredential

logger = logging.getLogger(__name__)

PURPOSES = ("login", "factor2", "factor3")

# Which step-up purpose each protected action requires.
ACTION_PURPOSE = {
    "document.view": "factor2",
    "document.submit": "factor2",
    "access.request": "factor2",
    "download.request": "factor2",
    "asset.mint": "factor3",
    "asset.approve": "factor3",
    "document.modify": "factor3",
    "document.download": "factor3",
    "admin.reset": "factor3",
    "identity.revoke": "factor3",
    "identity.provision": "factor3",
    "identity.role": "factor3",
    "asset.manage": "factor3",
    # Adding/removing a credential for an already-protected purpose requires
    # proving an existing factor of that same purpose.
    "factor2.manage": "factor2",
    "factor3.manage": "factor3",
    # Choosing to reuse (or stop reusing) the login factors for Factor 2 / Factor 3
    # requires proving the login factor.
    "factor2.link": "login",
    "factor3.link": "login",
}

_TOTP_FIELDS = {
    "login": ("totp_secret", "is_totp_enabled", "totp_last_step"),
    "factor2": ("totp_factor2_secret", "is_totp_factor2_enabled", "totp_factor2_last_step"),
    "factor3": ("totp_factor3_secret", "is_totp_factor3_enabled", "totp_factor3_last_step"),
}

PURPOSE_LABELS = {
    "login": "Login (Factor 1)",
    "factor2": "Factor 2 (View/Submission)",
    "factor3": "Factor 3 (Mint/Approve/Modify)",
}


def utcnow() -> datetime:
    return datetime.now(UTC)


def _check_purpose(purpose: str) -> None:
    if purpose not in PURPOSES:
        raise HTTPException(status_code=400, detail=f"Unknown authentication purpose '{purpose}'.")


def uses_login(user: User, purpose: str) -> bool:
    """True when the person chose to use their login factors for this purpose."""
    return purpose in ("factor2", "factor3") and bool(getattr(user, f"{purpose}_uses_login", False))


def source_purpose(user: User, purpose: str) -> str:
    """The purpose whose authenticator and passkeys actually satisfy `purpose`."""
    return "login" if uses_login(user, purpose) else purpose


# --------------------------------------------------------------------------- TOTP

def totp_enabled(user: User, purpose: str) -> bool:
    _, enabled_field, _ = _TOTP_FIELDS[source_purpose(user, purpose)]
    return bool(getattr(user, enabled_field))


def get_totp_secret(user: User, purpose: str) -> Optional[str]:
    secret_field, _, _ = _TOTP_FIELDS[purpose]
    return decrypt_secret(getattr(user, secret_field))


def set_totp_secret(user: User, purpose: str, secret: Optional[str]) -> None:
    secret_field, enabled_field, step_field = _TOTP_FIELDS[purpose]
    setattr(user, secret_field, encrypt_secret(secret))
    setattr(user, enabled_field, False)
    setattr(user, step_field, None)


def verify_totp_code(user: User, purpose: str, code: Optional[str], *, require_enabled: bool = True) -> bool:
    """Verify a TOTP code for exactly this purpose. Accepts ±1 time step (30 s) and
    rejects any step at or before the last accepted one (replay protection).
    On success the caller must commit the session to persist the new step."""
    _check_purpose(purpose)
    secret_field, enabled_field, step_field = _TOTP_FIELDS[source_purpose(user, purpose)]
    if require_enabled and not getattr(user, enabled_field):
        return False
    secret = decrypt_secret(getattr(user, secret_field))
    if not secret or not code or not code.isdigit() or len(code) != 6:
        return False
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // totp.interval
    last_step = getattr(user, step_field)
    for step in (now_step - 1, now_step, now_step + 1):
        if secrets.compare_digest(totp.at(step * totp.interval), code):
            if last_step is not None and step <= last_step:
                logger.warning("TOTP replay rejected (purpose=%s)", purpose)
                return False
            setattr(user, step_field, step)
            return True
    return False


# ------------------------------------------------------------------ Challenges

async def create_challenge(
    db: AsyncSession,
    kind: str,
    *,
    user_id: Optional[uuid.UUID] = None,
    wallet_address: Optional[str] = None,
    purpose: Optional[str] = None,
    action: Optional[str] = None,
    challenge: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
) -> str:
    value = challenge or secrets.token_urlsafe(32)
    db.add(AuthChallenge(
        kind=kind,
        user_id=user_id,
        wallet_address=wallet_address.lower() if wallet_address else None,
        purpose=purpose,
        action=action,
        challenge=value,
        expires_at=utcnow() + timedelta(seconds=ttl_seconds or settings.WEBAUTHN_CHALLENGE_TTL_SECONDS),
    ))
    await db.flush()
    return value


async def consume_challenge(
    db: AsyncSession,
    kind: str,
    challenge: str,
    *,
    user_id: Optional[uuid.UUID] = None,
    wallet_address: Optional[str] = None,
    purpose: Optional[str] = None,
) -> Optional[AuthChallenge]:
    """Atomically mark a matching, unexpired, unconsumed challenge as consumed."""
    conditions = [
        AuthChallenge.kind == kind,
        AuthChallenge.challenge == challenge,
        AuthChallenge.consumed_at.is_(None),
        AuthChallenge.expires_at > utcnow(),
    ]
    if user_id is not None:
        conditions.append(AuthChallenge.user_id == user_id)
    if wallet_address is not None:
        conditions.append(AuthChallenge.wallet_address == wallet_address.lower())
    if purpose is not None:
        conditions.append(AuthChallenge.purpose == purpose)
    result = await db.execute(
        update(AuthChallenge).where(*conditions).values(consumed_at=utcnow()).returning(AuthChallenge.id)
    )
    row_id = result.scalar_one_or_none()
    if row_id is None:
        return None
    return (await db.execute(select(AuthChallenge).where(AuthChallenge.id == row_id))).scalar_one()


# ------------------------------------------------------------------ WebAuthn

def _check_origin(origin: Optional[str]) -> str:
    if not origin or origin not in settings.WEBAUTHN_ORIGINS:
        raise HTTPException(status_code=400, detail="Invalid origin for WebAuthn")
    return origin


def rp_id_for(origin: Optional[str]) -> str:
    """The WebAuthn relying-party ID for the page a request came from: the host name of an
    allowed origin (localhost on this machine, the VPN name for remote people, see
    REMOTE_APP_ORIGIN). A passkey only works on the name it was created for. IP-address
    origins, which cannot be RP IDs, and anything else use settings.RP_ID."""
    if origin and origin in settings.WEBAUTHN_ORIGINS:
        host = urlparse(origin).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if host:
                return host
    return settings.RP_ID


def _rp_clause(rp_id: str):
    # passkeys registered before migration 0015 have no stored RP ID: they belong to settings.RP_ID
    if rp_id == settings.RP_ID:
        return or_(WebAuthnCredential.rp_id == rp_id, WebAuthnCredential.rp_id.is_(None))
    return WebAuthnCredential.rp_id == rp_id


async def scoped_credentials(db: AsyncSession, user: User, purpose: str, rp_id: Optional[str] = None) -> list[WebAuthnCredential]:
    """Active passkeys that satisfy `purpose`; only those created for `rp_id` when it is given."""
    conditions = [
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.factor_scope == source_purpose(user, purpose),
        WebAuthnCredential.is_active.is_(True),
    ]
    if rp_id is not None:
        conditions.append(_rp_clause(rp_id))
    return list((await db.execute(select(WebAuthnCredential).where(*conditions))).scalars().all())


async def passkey_options(db: AsyncSession, user: User, purpose: str, action: Optional[str],
                          origin: Optional[str] = None) -> dict:
    """Authentication options that only allow this purpose's passkeys for this address."""
    _check_purpose(purpose)
    rp_id = rp_id_for(origin)
    creds = await scoped_credentials(db, user, purpose, rp_id)
    if not creds:
        elsewhere = await scoped_credentials(db, user, purpose)
        raise HTTPException(
            status_code=400,
            detail=(f"Your {PURPOSE_LABELS[purpose]} passkey was created at another address and only works there. "
                    "Use your authenticator code here, or add a passkey for this address in My identity.")
            if elsewhere else f"No active {PURPOSE_LABELS[purpose]} passkey is registered for this identity.",
        )
    options = webauthn.generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=bytes.fromhex(c.credential_id))
            for c in creds
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    options_json = json.loads(webauthn.options_to_json(options))
    await create_challenge(
        db, "WEBAUTHN_AUTH", user_id=user.id, purpose=purpose, action=action,
        challenge=options_json["challenge"],
    )
    return options_json


def _response_challenge(response: dict) -> str:
    try:
        client_data = parse_client_data_json(
            base64url_to_bytes(response["response"]["clientDataJSON"])
        )
        return bytes_to_base64url(client_data.challenge)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed WebAuthn response.")


def _response_credential_hex(response: dict) -> str:
    try:
        return base64url_to_bytes(response.get("rawId") or response["id"]).hex()
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed WebAuthn credential id.")


async def verify_passkey_assertion(
    db: AsyncSession, user: User, purpose: str, response: dict, origin: Optional[str]
) -> AuthChallenge:
    """Verify an assertion end-to-end for one purpose. Returns the consumed challenge
    (which carries the bound action). Raises 401 on any failure."""
    _check_purpose(purpose)
    origin = _check_origin(origin)
    challenge_value = _response_challenge(response)
    challenge = await consume_challenge(
        db, "WEBAUTHN_AUTH", challenge_value, user_id=user.id, purpose=purpose
    )
    if challenge is None:
        raise HTTPException(status_code=401, detail="Passkey challenge not found, expired, already used, or issued for a different purpose.")

    credential = (await db.execute(select(WebAuthnCredential).where(
        WebAuthnCredential.credential_id == _response_credential_hex(response),
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.is_active.is_(True),
    ))).scalar_one_or_none()
    if credential is None:
        raise HTTPException(status_code=401, detail="Passkey is not registered to this identity.")
    if credential.factor_scope != source_purpose(user, purpose):
        raise HTTPException(
            status_code=401,
            detail=f"Wrong-purpose passkey: this passkey is registered for {PURPOSE_LABELS.get(credential.factor_scope, credential.factor_scope)}, "
                   f"not {PURPOSE_LABELS[purpose]}.",
        )
    try:
        verification = webauthn.verify_authentication_response(
            credential=response,
            expected_challenge=base64url_to_bytes(challenge.challenge),
            expected_origin=origin,
            expected_rp_id=rp_id_for(origin),
            credential_public_key=bytes.fromhex(credential.public_key),
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )
    except Exception as error:
        logger.warning("Passkey assertion rejected (purpose=%s): %s", purpose, error)
        if "user verification is required" in str(error).lower():
            raise HTTPException(status_code=401, detail=(
                "This passkey was used without a PIN, fingerprint or face check, which LexCorp2 requires. "
                "That usually means it is saved in a browser or extension password manager that skips the check. "
                "Use your authenticator code, or use a passkey saved in Windows Hello or on your phone."))
        # Outside production the library's reason (no secrets: e.g. "Unexpected RP ID hash") is
        # returned and audited, so a failing real authenticator can be diagnosed.
        reason = "" if settings.is_production else f" ({type(error).__name__}: {error})"
        raise HTTPException(status_code=401, detail=f"Passkey verification failed.{reason}")
    credential.sign_count = verification.new_sign_count
    return challenge


# ------------------------------------------------------------------ Step-up grants

async def issue_step_up(db: AsyncSession, user: User, purpose: str, action: str, method: str) -> dict:
    if ACTION_PURPOSE.get(action) != purpose:
        raise HTTPException(status_code=400, detail=f"Action '{action}' does not use {PURPOSE_LABELS.get(purpose, purpose)}.")
    token = "sut_" + secrets.token_urlsafe(32)
    expires_at = utcnow() + timedelta(seconds=settings.STEP_UP_TTL_SECONDS)
    db.add(StepUpGrant(
        user_id=user.id, purpose=purpose, action=action, method=method,
        token_hash=sha256_hex(token), session_version=user.session_version or 0,
        expires_at=expires_at,
    ))
    await db.flush()
    return {"step_up_token": token, "purpose": purpose, "action": action, "expires_at": expires_at.isoformat()}


async def consume_step_up(db: AsyncSession, user: User, purpose: str, action: str, token: Optional[str]) -> bool:
    if not token:
        return False
    result = await db.execute(
        update(StepUpGrant)
        .where(
            StepUpGrant.token_hash == sha256_hex(token),
            StepUpGrant.user_id == user.id,
            StepUpGrant.purpose == purpose,
            StepUpGrant.action == action,
            StepUpGrant.session_version == (user.session_version or 0),
            StepUpGrant.consumed_at.is_(None),
            StepUpGrant.expires_at > utcnow(),
        )
        .values(consumed_at=utcnow())
        .returning(StepUpGrant.id)
    )
    return result.scalar_one_or_none() is not None


async def require_factor(
    db: AsyncSession,
    user: User,
    action: str,
    *,
    totp_code: Optional[str] = None,
    step_up_token: Optional[str] = None,
) -> str:
    """Enforce the purpose-specific factor for an action: either a fresh TOTP code for
    that purpose, or a step-up token minted by a passkey of that purpose for this
    exact action. Returns the method used. The caller commits."""
    purpose = ACTION_PURPOSE[action]
    label = PURPOSE_LABELS[purpose]
    if step_up_token and await consume_step_up(db, user, purpose, action, step_up_token):
        return "PASSKEY"
    if not totp_enabled(user, purpose) and not await scoped_credentials(db, user, purpose):
        number = {"login": 1, "factor2": 2, "factor3": 3}[purpose]
        raise HTTPException(
            status_code=403,
            detail=f"Factor {number} setup required: configure {label} TOTP or Passkey in My Identity.",
        )
    if totp_code and verify_totp_code(user, purpose, totp_code):
        await db.flush()
        return "TOTP"
    raise HTTPException(
        status_code=401,
        detail=f"Invalid {label} TOTP or Passkey validation failed.",
    )


async def login_setup_complete(db: AsyncSession, user: User) -> bool:
    """Both Login TOTP 1 and Login Passkey 1 must be configured."""
    return bool(user.is_totp_enabled) and bool(await scoped_credentials(db, user, "login"))


async def reset_login_factors(db: AsyncSession, target: User) -> tuple[str, datetime]:
    """Invalidate the person's Login TOTP 1 and login passkeys, revoke their sessions and
    wallet keystore, and issue a NEW single-use provisioning PIN. Returns (pin, expires_at).
    The caller records the audit event and commits."""
    from app.core.crypto import hash_pin
    from app.services.security import generate_one_time_pin

    set_totp_secret(target, "login", None)
    await db.execute(
        update(WebAuthnCredential)
        .where(WebAuthnCredential.user_id == target.id, WebAuthnCredential.factor_scope == "login")
        .values(is_active=False)
    )
    pin = generate_one_time_pin(12)
    expires_at = utcnow() + timedelta(hours=settings.PROVISIONING_PIN_TTL_HOURS)
    target.wallet_wrap_secret = None  # old keystore copies can no longer be unlocked
    target.pin_hash = hash_pin(pin)
    target.pin_expires_at = expires_at
    target.pin_used = False
    target.onboarding_pending = True
    target.reset_requested = False
    target.session_version = (target.session_version or 0) + 1  # revoke all sessions
    return pin, expires_at


# Well-known passkey providers by AAGUID (the authenticator model id reported at registration;
# public, not secret). Unknown ones are shown by their AAGUID prefix.
PASSKEY_PROVIDERS = {
    "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
    "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
    "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
    "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
    "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
    "d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
    "bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
}


def passkey_provider(aaguid: str) -> str:
    aaguid = (aaguid or "").lower()
    if not aaguid or aaguid == "00000000-0000-0000-0000-000000000000":
        return "Passkey provider not disclosed"
    return PASSKEY_PROVIDERS.get(aaguid, f"Authenticator {aaguid[:8]}")
