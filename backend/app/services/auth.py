"""Wallet signature verification and JWT session management.

Sessions:
- scope "full"  : normal application access (issued after Login TOTP 1 or Passkey 1,
                  and only once both are configured).
- scope "setup" : mandatory first-login setup only (issued after wallet import with a
                  valid one-time provisioning PIN, or a login by a user whose login
                  setup is incomplete). Cannot reach any application endpoint.

Wallet signatures (EIP-191) are accepted only for provisioning. Nonces are stored
server-side, bound to the wallet address, single-use and expire after
NONCE_EXPIRY_SECONDS.
"""

import secrets
from datetime import datetime, timedelta, UTC
from typing import Optional

from eth_account import Account
from eth_account.messages import encode_defunct
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.domain import User

SCOPE_FULL = "full"
SCOPE_SETUP = "setup"


class AuthError(Exception):
    """Authentication failure."""


def generate_nonce() -> str:
    return secrets.token_hex(16)


def build_siwe_message(address: str, nonce: str) -> str:
    return (
        f"lexcorp-sih.example.com wants you to sign in with your Ethereum account.\n"
        f"Wallet: {address}\n"
        f"Nonce: {nonce}\n"
        f"URI: https://lexcorp-sih.example.com\n"
        f"Version: 1\n"
        f"Chain ID: {settings.CHAIN_ID}"
    )


def recover_signer(message: str, signature: str) -> str:
    try:
        return Account.recover_message(encode_defunct(text=message), signature=signature).lower()
    except Exception as e:
        raise AuthError(f"Invalid wallet signature: {e}")


def create_jwt(
    wallet_address: str,
    did: str,
    role: str,
    session_version: int = 0,
    client_ip: Optional[str] = None,
    scope: str = SCOPE_FULL,
) -> str:
    """Create a short-lived JWT bound to the session version and client IP."""
    now = datetime.now(UTC)
    payload = {
        "sub": wallet_address.lower(),
        "did": did,
        "role": role,
        "session_version": session_version,
        "client_ip": client_ip,
        "scope": scope,
        "jti": secrets.token_hex(12),
        "iat": now,
        "exp": now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_jwt(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None


def expected_did(wallet_address: str) -> str:
    return f"did:ethr:{settings.CHAIN_ID}:{wallet_address.lower()}"


async def report_legacy_dids(db: AsyncSession) -> int:
    """Count users whose DID does not match did:ethr:<CHAIN_ID>:<wallet>.
    Report-only: historical identifiers are never rewritten silently."""
    users = (await db.execute(select(User))).scalars().all()
    return sum(1 for u in users if u.did != expected_did(u.wallet_address))
