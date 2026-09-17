"""Wallet authentication using Ethereum signed messages and SIWE-standard format.

Implements NIST SP 800-63-4 session management practices:
- Nonce expiry (5 minutes default)
- Short-lived JWT sessions (30 minutes default)
- Direct secp256k1 signature verification via eth_account (robust & dependency-free)
"""

import secrets
from datetime import datetime, timedelta, UTC
from typing import Optional

from eth_account.messages import encode_defunct
from eth_account import Account
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.domain import User


class NonceData(BaseModel):
    """Stored nonce with expiry."""
    nonce: str
    expires_at: datetime


# In-memory nonce store — in production, use Redis with TTL
_nonce_store: dict[str, NonceData] = {}

# Store WebAuthn challenges for registration and login
_challenge_store: dict[str, str] = {}


class AuthError(Exception):
    """Authentication failure."""
    pass


def generate_nonce() -> str:
    """Generate a cryptographically random nonce."""
    return secrets.token_hex(16)


def store_nonce(address: str, nonce: str, expires_in_seconds: int = 300) -> None:
    """Store a nonce for a wallet address with expiry."""
    expires_at = datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
    _nonce_store[address.lower()] = NonceData(nonce=nonce, expires_at=expires_at)


def get_nonce(address: str) -> Optional[str]:
    """Get and validate a stored nonce. Returns None if expired or missing."""
    data = _nonce_store.get(address.lower())
    if not data:
        return None
    if datetime.now(UTC) > data.expires_at:
        del _nonce_store[address.lower()]
        return None
    return data.nonce


def clear_nonce(address: str) -> None:
    """Remove a used nonce."""
    _nonce_store.pop(address.lower(), None)

def store_challenge(user_id: str, challenge: str) -> None:
    """Store WebAuthn challenge for a user."""
    _challenge_store[user_id] = challenge

def get_challenge(user_id: str) -> Optional[str]:
    """Get and clear stored WebAuthn challenge."""
    return _challenge_store.pop(user_id, None)

def create_jwt(wallet_address: str, did: str, role: str, session_version: int = 0) -> str:
    """Create a short-lived JWT session token."""
    now = datetime.now(UTC)
    payload = {
        "sub": wallet_address.lower(),
        "did": did,
        "role": role,
        "session_version": session_version,
        "iat": now,
        "exp": now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_jwt(token: str) -> Optional[dict]:
    """Verify and decode a JWT. Returns payload or None if invalid."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


async def verify_siwe_message(
    message: str,
    signature: str,
    nonce: str,
    db: AsyncSession,
) -> User:
    """Verify a SIWE/EIP-4361 message and signature, returning or creating the user."""
    try:
        # Recover address from signature directly
        encoded_message = encode_defunct(text=message)
        recovered_address = Account.recover_message(encoded_message, signature=signature)

        # Verify nonce matches what we stored for the recovered address
        stored_nonce = get_nonce(recovered_address)
        if not stored_nonce:
            raise AuthError("Nonce expired or not found")
        if stored_nonce != nonce:
            raise AuthError("Invalid nonce")

        # Nonce is single-use — clear it
        clear_nonce(recovered_address)

        # Find or create user (using AsyncSession)
        from app.models.domain import User
        from sqlalchemy import func

        result = await db.execute(
            select(User).where(func.lower(User.wallet_address) == recovered_address.lower())
        )
        user = result.scalar_one_or_none()

        if not user:
            # First connect — issue DID
            did = f"did:ethr:{settings.CHAIN_ID}:{recovered_address.lower()}"
            user = User(wallet_address=recovered_address.lower(), did=did, role="USER")
            db.add(user)
            await db.commit()
            await db.refresh(user)
        elif not user.is_active:
            # Blocked wallet
            raise AuthError("Wallet access has been revoked for this user")
        elif not user.did:
            # Auto-repair legacy accounts that were seeded without a DID
            user.did = f"did:ethr:{settings.CHAIN_ID}:{user.wallet_address.lower()}"
            await db.commit()
            await db.refresh(user)

        return user

    except Exception as e:
        if isinstance(e, AuthError):
            raise
        raise AuthError(f"Authentication verification error: {e}")
