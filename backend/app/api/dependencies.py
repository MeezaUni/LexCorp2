from typing import Optional
from fastapi import Cookie, Depends, HTTPException, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.services.auth import verify_jwt
from app.models.domain import User

__all__ = ["get_db", "get_current_user", "get_current_active_user", "get_admin_user", "get_manager_user", "get_onboarded_user", "get_request_client_ip"]

def get_request_client_ip(request: Request) -> str:
    """Extract client IP from request headers or host, normalized to IPv4."""
    forwarded = request.headers.get("x-forwarded-for")
    ip = ""
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    elif request.client:
        ip = request.client.host
    else:
        ip = "127.0.0.1"

    if ip in ("::1", "localhost", "testclient"):
        return "127.0.0.1"
    if ip.startswith("::ffff:"):
        return ip.replace("::ffff:", "")
    return ip

async def get_current_user(
    request: Request,
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

    # IP Session Binding Verification
    token_ip = payload.get("client_ip")
    if token_ip:
        current_ip = get_request_client_ip(request)
        # Check mismatch, allowing standard local loopback aliases
        is_local = token_ip in ("127.0.0.1", "localhost", "testclient", "::1") and current_ip in ("127.0.0.1", "localhost", "testclient", "::1")
        if not is_local and token_ip != current_ip:
            raise HTTPException(
                status_code=401,
                detail="Session revoked: IP address mismatch (IP session binding violation)"
            )

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

async def get_onboarded_user(user: User = Depends(get_current_active_user)) -> User:
    if user.onboarding_pending:
        raise HTTPException(
            status_code=403,
            detail="Onboarding incomplete: You must configure Login Authenticator and Login Passkey before accessing platform features."
        )
    return user

async def get_admin_user(user: User = Depends(get_onboarded_user)) -> User:
    if user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Requires ADMIN role")
    return user

async def get_manager_user(user: User = Depends(get_onboarded_user)) -> User:
    if user.role not in ("ADMIN", "MANAGER"):
        raise HTTPException(status_code=403, detail="Requires MANAGER role")
    return user
