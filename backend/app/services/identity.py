"""The single identity-revocation mechanism.

Used by the administrative user endpoint (DELETE /users/{id}) and by the security
alert chain (Admin -> REVOKE IDENTITY). Revocation deactivates the identity, records
when/why, bumps session_version so every active session is invalidated immediately,
and is audited. Historical records (assets, audit trail, chain references) are kept.
"""

from datetime import datetime, UTC
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain import Asset, User

ROLE_LEVEL = {"ADMIN": 3, "MANAGER": 2, "AUDITOR": 1, "USER": 0}


async def revoke_identity(
    db: AsyncSession,
    actor: User,
    target: User,
    reason: str,
    *,
    client_ip: Optional[str] = None,
    require_no_owned_assets: bool = False,
    context: Optional[dict] = None,
) -> User:
    from app.api.dependencies import record_audit  # avoid import cycle

    if target.id == actor.id:
        raise HTTPException(status_code=403, detail="You cannot revoke your own identity.")
    if ROLE_LEVEL.get(target.role, 0) >= ROLE_LEVEL.get(actor.role, 0) and actor.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Insufficient permissions to revoke this identity.")
    if not target.is_active and target.revoked_at is not None:
        raise HTTPException(status_code=409, detail="This identity is already revoked.")
    if require_no_owned_assets:
        owns = (await db.execute(select(Asset.id).where(Asset.owner_id == target.id))).first()
        if owns is not None:
            raise HTTPException(status_code=409, detail="User still owns assets. Revoke or transfer every asset before deactivating this user.")

    target.is_active = False
    target.revoked_at = datetime.now(UTC)
    target.revocation_reason = (reason or "")[:1000]
    target.session_version = (target.session_version or 0) + 1  # kill every active session now
    await record_audit(db, "IDENTITY_REVOKED", actor_did=actor.did, target_did=target.did, client_ip=client_ip,
                       details={"reason": target.revocation_reason, "target_role": target.role, **(context or {})})
    return target
