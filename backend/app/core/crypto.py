"""Small cryptographic helpers: at-rest secret encryption and one-time PIN hashing."""

import base64
import hashlib
import hmac
import secrets
from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

_ENC_PREFIX = "enc:v1:"


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    if settings.DATA_ENCRYPTION_KEY:
        key = settings.DATA_ENCRYPTION_KEY.encode()
    else:
        derived = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=b"lexcorp-data-key", info=b"totp-secrets"
        ).derive(settings.JWT_SECRET.encode())
        key = base64.urlsafe_b64encode(derived)
    return Fernet(key)


def encrypt_secret(plaintext: Optional[str]) -> Optional[str]:
    if plaintext is None:
        return None
    return _ENC_PREFIX + _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(stored: Optional[str]) -> Optional[str]:
    """Return the plaintext secret. Legacy unencrypted values are returned unchanged."""
    if not stored:
        return None
    if not stored.startswith(_ENC_PREFIX):
        return stored
    try:
        return _fernet().decrypt(stored[len(_ENC_PREFIX):].encode()).decode()
    except InvalidToken:
        return None


# --- One-time provisioning PIN hashing (scrypt; the PIN itself is never stored) ---

_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}


def hash_pin(pin: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(pin.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_pin(pin: str, stored: Optional[str]) -> bool:
    if not stored or not pin:
        return False
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    candidate = hashlib.scrypt(pin.encode(), salt=bytes.fromhex(salt_hex), **_SCRYPT)
    return hmac.compare_digest(candidate.hex(), digest_hex)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
