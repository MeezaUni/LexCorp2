"""Small cryptographic helpers: at-rest secret encryption and one-time PIN hashing."""

import base64
import hashlib
import hmac
import logging
import secrets
from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

logger = logging.getLogger(__name__)

_ENC_PREFIX = "enc:v1:"


def legacy_jwt_derived_key(jwt_secret: str) -> str:
    """The key earlier versions derived from JWT_SECRET. Used ONLY by the key-migration
    script to read records written before DATA_ENCRYPTION_KEYS existed."""
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"lexcorp-data-key", info=b"totp-secrets").derive(jwt_secret.encode())
    return base64.urlsafe_b64encode(derived).decode()


def build_keyring(keys: list[str]) -> MultiFernet:
    """First key encrypts; every key can decrypt (supports rotation)."""
    return MultiFernet([Fernet(k.encode()) for k in keys])


@lru_cache(maxsize=1)
def _keyring() -> MultiFernet:
    return build_keyring(settings.data_encryption_keys)


def encrypt_secret(plaintext: Optional[str], keyring: Optional[MultiFernet] = None) -> Optional[str]:
    if plaintext is None:
        return None
    return _ENC_PREFIX + (keyring or _keyring()).encrypt(plaintext.encode()).decode()


def decrypt_secret(stored: Optional[str], keyring: Optional[MultiFernet] = None) -> Optional[str]:
    """Return the plaintext secret, or None. Unencrypted (legacy) values are REFUSED;
    they must be migrated with scripts/rotate_encryption_keys.py."""
    if not stored:
        return None
    if not stored.startswith(_ENC_PREFIX):
        logger.error("Refusing an unencrypted secret value; run scripts/rotate_encryption_keys.py")
        return None
    try:
        return (keyring or _keyring()).decrypt(stored[len(_ENC_PREFIX):].encode()).decode()
    except InvalidToken:
        return None


def is_encrypted(stored: Optional[str]) -> bool:
    return bool(stored) and stored.startswith(_ENC_PREFIX)


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
