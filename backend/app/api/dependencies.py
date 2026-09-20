from typing import Optional
from fastapi import Cookie, Depends, HTTPException, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.services.auth import verify_jwt
from app.models.domain import User

__all__ = ["get_db", "get_current_user", "get_current_active_user", "get_admin_user", "get_manager_user"]

async def get_current_user(
    session: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Dependency to get the current authenticated user via JWT from cookie or Auth header."""
    token = session
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]

    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    payload = verify_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Session expired or invalid")

    wallet_address = payload.get("sub")
    if not wallet_address:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    result = await db.execute(
        select(User).where(func.lower(User.wallet_address) == wallet_address.lower())
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if payload.get("session_version", 0) != (user.session_version or 0):
        raise HTTPException(status_code=401, detail="Session replaced by a newer login")

    return user

async def get_current_active_user(user: User = Depends(get_current_user)) -> User:
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    return user

async def get_admin_user(user: User = Depends(get_current_active_user)) -> User:
    if user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Requires ADMIN role")
    return user

async def get_manager_user(user: User = Depends(get_current_active_user)) -> User:
    if user.role not in ("ADMIN", "MANAGER"):
        raise HTTPException(status_code=403, detail="Requires MANAGER role")
    return user
