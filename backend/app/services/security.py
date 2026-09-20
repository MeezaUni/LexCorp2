"""Secure authentication services including 2FA/TOTP and WebAuthn (Passkey) support.

Security principles:
- TOTP Secrets must be stored encrypted at rest (if using DB).
- WebAuthn credentials must be cryptographically bound to the user.
- Biometric interaction happens on the browser/device; server verifies assertions against registered public keys.
"""

import pyotp
import base64
import os
from typing import Optional, Tuple
from webauthn import generate_registration_options, verify_registration_response
from webauthn.helpers import generate_challenge
from webauthn.helpers.structs import PublicKeyCredentialCreationOptions, AuthenticatorSelectionCriteria, AuthenticatorAttachment, ResidentKeyRequirement, UserVerificationRequirement

from app.core.config import settings

# --- TOTP (Google Authenticator) ---

def generate_totp_secret() -> str:
    """Generate a high-entropy secret for new TOTP enrollment."""
    return pyotp.random_base32()

def get_totp_uri(username: str, secret: str) -> str:
    """Generate OTP Auth URI for QR code generation."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="LexCorp SIH26125"
    )

def verify_totp(secret: str, provided_token: str) -> bool:
    """Verify a 6-digit TOTP token with clock skew tolerance.

    Args:
        secret: Base32-encoded TOTP secret
        provided_token: 6-digit code from authenticator app

    Returns:
        True if code is valid within ±60s window, False otherwise
    """
    import logging
    logger = logging.getLogger(__name__)

    # Validate input format
    if not secret or not provided_token:
        logger.warning("TOTP verification failed: empty secret or token")
        return False

    # Validate token is 6 digits
    if not provided_token.isdigit() or len(provided_token) != 6:
        logger.warning(f"TOTP verification failed: invalid token format (expected 6 digits, got {len(provided_token)} chars)")
        return False

    try:
        totp = pyotp.totp.TOTP(secret)
        # Increase valid_window from 1 to 2 for better clock tolerance (±60s total)
        result = totp.verify(provided_token, valid_window=2)

        if result:
            logger.info("TOTP verification successful")
        else:
            logger.warning("TOTP verification failed: code invalid or expired")

        return result
    except Exception as e:
        logger.error(f"TOTP verification error: {e}")
        return False

# --- WebAuthn (Passkeys / Biometrics) ---

from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import PublicKeyCredentialCreationOptions, AuthenticatorSelectionCriteria, UserVerificationRequirement, PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions

def generate_webauthn_registration_options(user_id: str, username: str, rp_id: str = "localhost") -> PublicKeyCredentialCreationOptions:
    """Generate options to start WebAuthn registration."""
    # Use a secure random challenge
    challenge = generate_challenge()

    return generate_registration_options(
        rp_id=rp_id, # Dynamically determined from request
        rp_name="LexCorp SIH26125",
        user_id=user_id.encode(),
        user_name=username,
        challenge=challenge,
        # Prefer the laptop's built-in platform authenticator, such as Windows Hello.
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.REQUIRED,
        )
    )

def generate_webauthn_login_options(credential_ids: list[bytes], rp_id: str = "localhost") -> PublicKeyCredentialRequestOptions:
    """Generate options to start WebAuthn authentication."""
    challenge = generate_challenge()
    # Omit allowCredentials so the browser can use a discoverable platform
    # credential such as the Windows Hello PIN on this laptop.
    allow_credentials = None

    return generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED
    )
