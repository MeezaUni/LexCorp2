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
from webauthn.helpers.structs import PublicKeyCredentialCreationOptions, AuthenticatorSelectionCriteria, UserVerificationRequirement

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
    """Verify a 6-digit TOTP token."""
    totp = pyotp.totp.TOTP(secret)
    return totp.verify(provided_token, valid_window=1)

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
        # Require user presence (biometrics/tap)
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED
        )
    )

def generate_webauthn_login_options(credential_ids: list[bytes], rp_id: str = "localhost") -> PublicKeyCredentialRequestOptions:
    """Generate options to start WebAuthn authentication."""
    challenge = generate_challenge()
    allow_credentials = [
        PublicKeyCredentialDescriptor(id=cid) for cid in credential_ids
    ] if credential_ids else None

    return generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED
    )
