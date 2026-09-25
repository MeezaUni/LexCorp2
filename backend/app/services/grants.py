"""Delegated access grants: validity, permissions and atomic view consumption."""

from datetime import datetime, UTC
from typing import Optional

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain import Asset, AssetAccessGrant, User


def now_utc() -> datetime:
    return datetime.now(UTC)


def valid_grant_clause(now: Optional[datetime] = None):
    """SQL predicate for a grant that is currently usable (independent of permission)."""
    now = now or now_utc()
    return and_(
        AssetAccessGrant.is_active.is_(True),
        AssetAccessGrant.revoked_at.is_(None),
        or_(AssetAccessGrant.expires_at.is_(None), AssetAccessGrant.expires_at > now),
    )


def _for(user: User, asset: Asset):
    return and_(
        AssetAccessGrant.grantee_did == user.did,
        or_(AssetAccessGrant.asset_id == asset.id,
            and_(AssetAccessGrant.asset_id.is_(None), AssetAccessGrant.asset_serial == asset.serial_number)),
    )


async def latest_grant(db: AsyncSession, user: User, asset: Asset) -> Optional[AssetAccessGrant]:
    """Most recent grant for this user and asset, valid or not (used to explain denials)."""
    return (await db.execute(
        select(AssetAccessGrant).where(_for(user, asset)).order_by(AssetAccessGrant.created_at.desc()).limit(1)
    )).scalar_one_or_none()


async def usable_grant(db: AsyncSession, user: User, asset: Asset, permission: str) -> Optional[AssetAccessGrant]:
    """A currently valid grant carrying `permission` ('view' | 'download')."""
    perm = AssetAccessGrant.can_view if permission == "view" else AssetAccessGrant.can_download
    conditions = [_for(user, asset), valid_grant_clause(), perm.is_(True)]
    if permission == "view":
        conditions.append(or_(AssetAccessGrant.max_views.is_(None), AssetAccessGrant.views_count < AssetAccessGrant.max_views))
    return (await db.execute(
        select(AssetAccessGrant).where(*conditions).order_by(AssetAccessGrant.created_at.desc()).limit(1)
    )).scalar_one_or_none()


def denial_reason(grant: Optional[AssetAccessGrant], permission: str) -> tuple[str, str]:
    """(audit event, user-facing message) explaining why no grant is usable."""
    if grant is None:
        return "ACCESS_DENIED_NO_GRANT", "You have no approved access to this document. Request access for approval."
    if grant.revoked_at is not None or not grant.is_active:
        return "ACCESS_DENIED_REVOKED", "Your access to this document has been revoked."
    if grant.expires_at is not None and grant.expires_at <= now_utc():
        return "ACCESS_EXPIRED", "Your access to this document expired."
    if permission == "download" and not grant.can_download:
        return "DOWNLOAD_NOT_PERMITTED", "Your access to this document is view-only; download is not permitted."
    if permission == "view" and not grant.can_view:
        return "VIEW_NOT_PERMITTED", "Your access to this document does not include viewing."
    if grant.max_views is not None and grant.views_count >= grant.max_views:
        return "ACCESS_LIMIT_REACHED", f"View limit reached ({grant.max_views} successful views)."
    return "ACCESS_DENIED", "Access denied."


async def consume_view(db: AsyncSession, grant_id) -> Optional[int]:
    """Atomically count one successful view. Returns the new count, or None if the
    grant became unusable (limit reached / expired / revoked) in the meantime.

    Concurrent requests serialise on the row lock and the WHERE clause is
    re-evaluated, so the limit can never be exceeded. Call this only once every
    other check has passed; the caller's transaction commits the increment only
    if the protected copy is actually produced."""
    result = await db.execute(
        update(AssetAccessGrant)
        .where(
            AssetAccessGrant.id == grant_id,
            valid_grant_clause(),
            AssetAccessGrant.can_view.is_(True),
            or_(AssetAccessGrant.max_views.is_(None), AssetAccessGrant.views_count < AssetAccessGrant.max_views),
        )
        .values(views_count=AssetAccessGrant.views_count + 1)
        .returning(AssetAccessGrant.views_count)
    )
    return result.scalar_one_or_none()
