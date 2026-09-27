"""Provisioning PINs and authenticator (TOTP) enrolment helpers.

Verification lives elsewhere: TOTP codes are checked by app.services.mfa.verify_totp_code
(purpose-bound, with replay protection), and passkeys are registered and verified in
app.api.auth and app.services.mfa.
"""

import secrets

import pyotp


def generate_one_time_pin(length: int = 12) -> str:
    """Generate a cryptographically random, high-entropy PIN for wallet provisioning.
    Uses alphanumeric characters (excluding confusing ones like 0/O, 1/l/I).
    """
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_totp_secret() -> str:
    """Generate a high-entropy secret for new TOTP enrolment."""
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str, issuer_name: str = "LexCorp") -> str:
    """OTP Auth URI for the enrolment QR code."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)
