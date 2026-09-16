"""Temporary in-memory user store for Phase 4 demo (bypasses Postgres requirement)."""

from typing import Optional
from pydantic import BaseModel


class User(BaseModel):
    wallet_address: str
    did: str
    role: str = "USER"
    is_active: bool = True


_users: dict[str, User] = {}


def get_user(wallet_address: str) -> Optional[User]:
    """Get user by wallet address."""
    return _users.get(wallet_address.lower())


def create_user(wallet_address: str, did: str, role: str = "USER") -> User:
    """Create a new user."""
    user = User(
        wallet_address=wallet_address.lower(),
        did=did,
        role=role,
        is_active=True,
    )
    _users[wallet_address.lower()] = user
    return user
