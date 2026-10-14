import hashlib
import ipaddress
import logging
import time
from datetime import datetime, timedelta, UTC
from typing import Optional

from fastapi import Cookie, Depends, HTTPException, Header, Request
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models.domain import AuditEvent, User
from app.services.auth import SCOPE_FULL, SCOPE_SETUP, verify_jwt

logger = logging.getLogger(__name__)

__all__ = [
    "get_db", "get_current_user", "get_current_active_user", "get_setup_user",
    "get_admin_user", "get_manager_user", "get_onboarded_user", "get_request_client_ip",
    "get_step_up_token", "record_audit", "get_optional_user",
]

# Throttle last-activity writes; the inactivity timeout is minutes, not seconds.
_ACTIVITY_WRITE_INTERVAL = timedelta(seconds=30)


from app.core.client_ip import _is_trusted, _normalize_ip, _trusted_networks, get_request_client_ip  # noqa: E402,F401


def get_step_up_token(x_step_up_token: Optional[str] = Header(None)) -> Optional[str]:
    return x_step_up_token


async def record_audit(
    db: AsyncSession,
    event_type: str,
    *,
    actor_did: Optional[str] = None,
    target_did: Optional[str] = None,
    asset_serial: Optional[str] = None,
    client_ip: Optional[str] = None,
    risk_label: Optional[str] = None,
    risk_score: Optional[float] = None,
    details: Optional[dict] = None,
    alert: bool = True,
) -> AuditEvent:
    """Add an off-chain audit event (block_number 0). Caller commits. A HIGH/CRITICAL event
    raises a security alert unless `alert` is False (the event is still recorded)."""
    tx_hash = "0x" + hashlib.sha256(
        f"{event_type}:{actor_did}:{target_did}:{asset_serial}:{time.time_ns()}".encode()
    ).hexdigest()
    event = AuditEvent(
        event_type=event_type,
        tx_hash=tx_hash,
        block_number=0,
        actor_did=actor_did,
        target_did=target_did,
        asset_serial=asset_serial,
        client_ip=client_ip,
        risk_label=risk_label,
        risk_score=risk_score,
        risk_factors=details,
    )
    db.add(event)
    if alert and (risk_label or "").upper() in ("HIGH", "CRITICAL"):
        from app.services.alerts import raise_alert
        await raise_alert(db, event, source="AI" if (details or {}).get("ai") else "RULE")
    return event


async def _record_replaced_session(db: AsyncSession, user: User, payload: dict, request: Request) -> None:
    """The first request of a session that a newer sign-in replaced: record that this device was
    signed out (once per session). Sessions ended by sign-out, revocation or expiry aren't this."""
    from app.models.domain import AuditEvent
    jti, issued = payload.get("jti"), payload.get("iat")
    if not jti or not issued:
        return
    newer = (await db.execute(select(AuditEvent.created_at).where(
        AuditEvent.actor_did == user.did, AuditEvent.event_type == "AuthenticationSucceeded",
    ).order_by(AuditEvent.created_at.desc()).limit(1))).scalar_one_or_none()
    if newer is None or newer.timestamp() <= float(issued):
        return
    seen = (await db.execute(select(AuditEvent.id).where(
        AuditEvent.actor_did == user.did, AuditEvent.event_type == "SESSION_ENDED_REPLACED",
        AuditEvent.risk_factors["jti"].as_string() == jti,
    ).limit(1))).scalar_one_or_none()
    if seen is not None:
        return
    await record_audit(db, "SESSION_ENDED_REPLACED", actor_did=user.did, target_did=user.did,
                       client_ip=get_request_client_ip(request),
                       details={"jti": jti, "session_ip": payload.get("client_ip"),
                                "reason": "the account signed in on another device (one session at a time)"})
    await db.commit()


def _in_vpn_subnet(ip: Optional[str]) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(settings.VPN_CLIENT_SUBNET, strict=False)
    except ValueError:
        return False


async def _authenticate(
    request: Request,
    session: Optional[str],
    authorization: Optional[str],
    db: AsyncSession,
    touch: bool = True,
) -> tuple[User, dict]:
    """Validate the session. touch=False checks it without counting as activity (the page's
    background session check must not keep an idle session alive)."""
    token = session
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    payload = verify_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    wallet_address = payload.get("sub")
    if not wallet_address:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = (await db.execute(
        select(User).where(func.lower(User.wallet_address) == wallet_address.lower())
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.is_active or user.revoked_at is not None:
        raise HTTPException(status_code=403, detail="Account is disabled or identity has been revoked")
    if payload.get("session_version", 0) != (user.session_version or 0):
        await _record_replaced_session(db, user, payload, request)
        raise HTTPException(status_code=401, detail="This account signed in on another device (only one session at a time), or the session was revoked. Sign in again to continue here.")

    # IP session binding: a changed effective client IP terminates the session.
    token_ip = payload.get("client_ip")
    current_ip = get_request_client_ip(request)
    if token_ip and _normalize_ip(token_ip) != current_ip:
        user.session_version = (user.session_version or 0) + 1
        if _in_vpn_subnet(_normalize_ip(token_ip)) and _in_vpn_subnet(current_ip):
            # The device reconnected to the VPN (each connection gets a new address): an expected
            # event, recorded but not raised as an alert. The session still ends.
            await record_audit(db, "SESSION_ENDED_VPN_RECONNECT", actor_did=user.did, target_did=user.did,
                               client_ip=current_ip, risk_label="MEDIUM", risk_score=0.3,
                               details={"bound_ip": token_ip, "request_ip": current_ip})
            await db.commit()
            raise HTTPException(status_code=401, detail="Your VPN connection was renewed, so your session ended. Please sign in again.")
        await record_audit(
            db, "SESSION_TERMINATED_IP_CHANGE",
            actor_did=user.did, target_did=user.did, client_ip=current_ip,
            risk_label="HIGH", risk_score=0.8,
            details={"bound_ip": token_ip, "request_ip": current_ip},
        )
        await db.commit()
        raise HTTPException(
            status_code=401,
            detail="Session terminated: client IP address changed (IP session binding). Please sign in again.",
        )

    # Server-side inactivity timeout.
    now = datetime.now(UTC)
    last = user.last_activity_at
    if last is not None and now - last > timedelta(minutes=settings.INACTIVITY_TIMEOUT_MINUTES):
        user.session_version = (user.session_version or 0) + 1
        await record_audit(db, "SESSION_EXPIRED_INACTIVITY", actor_did=user.did, client_ip=current_ip)
        await db.commit()
        raise HTTPException(status_code=401, detail="Session expired due to inactivity. Please sign in again.")
    if touch and (last is None or now - last > _ACTIVITY_WRITE_INTERVAL):
        user.last_activity_at = now
        await db.commit()

    return user, payload


async def get_setup_user(
    request: Request,
    session: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Any valid session (setup or full). Only for identity-setup endpoints."""
    user, payload = await _authenticate(request, session, authorization, db)
    if payload.get("scope", SCOPE_FULL) not in (SCOPE_FULL, SCOPE_SETUP):
        raise HTTPException(status_code=401, detail="Invalid session scope")
    return user


async def get_current_user(
    request: Request,
    session: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """A full application session. Setup-only sessions are rejected here, so no
    application endpoint is reachable before Login TOTP 1 + Passkey 1 exist."""
    user, payload = await _authenticate(request, session, authorization, db)
    if payload.get("scope", SCOPE_FULL) != SCOPE_FULL:
        raise HTTPException(
            status_code=403,
            detail="Onboarding incomplete: configure Login Authenticator (TOTP 1) and Login Passkey (Passkey 1) first.",
        )
    return user


def _require_active(user: User) -> None:
    # Checked again here (not only in _authenticate) as defence in depth.
    if not user.is_active or user.revoked_at is not None:
        raise HTTPException(status_code=403, detail="Account is disabled or identity has been revoked")


async def get_optional_user(
    request: Request,
    session: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """For public pages (QR verification): the onboarded user if a valid full session
    is presented, otherwise None. Never raises for missing/invalid credentials."""
    if not session and not (authorization and authorization.startswith("Bearer ")):
        return None
    try:
        user, payload = await _authenticate(request, session, authorization, db)
    except HTTPException:
        return None
    if payload.get("scope", SCOPE_FULL) != SCOPE_FULL or user.onboarding_pending:
        return None
    return user


async def get_current_active_user(user: User = Depends(get_current_user)) -> User:
    _require_active(user)
    return user


async def get_onboarded_user(user: User = Depends(get_current_user)) -> User:
    _require_active(user)
    if user.onboarding_pending:
        raise HTTPException(
            status_code=403,
            detail="Onboarding incomplete: You must configure Login Authenticator and Login Passkey before accessing platform features.",
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
