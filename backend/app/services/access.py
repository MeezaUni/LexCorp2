"""Server-side RBAC and department scoping. All visibility decisions live here so
every endpoint filters in the database query, never by hiding rows in the UI.

  ADMIN   - every department; full registry
  AUDITOR - read-only inspection of every department (no administration)
  MANAGER - users.department + users.managed_departments, plus assets they own/custody
  USER    - assets they own or hold custody of, plus assets granted to them
"""

from typing import Optional

from fastapi import HTTPException
from sqlalchemy import and_, false, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain import Asset, AssetAccessGrant, Department, User

UNRESTRICTED_ROLES = ("ADMIN", "AUDITOR")

# Identifiers that must never leave the server for callers without scope.
SENSITIVE_PHYSICAL_FIELDS = ("mac_address", "device_unique_address")


def manager_departments(user: User) -> set[str]:
    depts = {user.department} if user.department else set()
    depts.update(d for d in (user.managed_departments or []) if d)
    return depts


async def active_department_names(db: AsyncSession) -> list[str]:
    rows = await db.execute(select(Department.name).where(Department.is_active.is_(True)).order_by(Department.name))
    return list(rows.scalars().all())


async def assignable_departments(db: AsyncSession, user: User) -> list[str]:
    """Departments this actor may assign when creating users / registering assets."""
    active = await active_department_names(db)
    if user.role == "ADMIN":
        return active
    if user.role == "MANAGER":
        scope = manager_departments(user)
        return [d for d in active if d in scope]
    return []


async def require_assignable_department(db: AsyncSession, user: User, department: Optional[str]) -> str:
    """Validate a client-supplied department against the server's scope for this actor."""
    if not department:
        raise HTTPException(status_code=400, detail="A department is required.")
    allowed = await assignable_departments(db, user)
    if department not in allowed:
        if department not in await active_department_names(db):
            raise HTTPException(status_code=400, detail=f"Unknown or inactive department '{department}'.")
        raise HTTPException(status_code=403, detail=f"You are not authorized for department '{department}'.")
    return department


async def granted_serials(db: AsyncSession, user: User) -> list[str]:
    rows = await db.execute(
        select(AssetAccessGrant.asset_serial).where(
            AssetAccessGrant.grantee_did == user.did, AssetAccessGrant.is_active.is_(True)
        )
    )
    return list(rows.scalars().all())


async def asset_scope_clause(db: AsyncSession, user: User):
    """SQL predicate restricting Asset rows to what this user may see (None = everything)."""
    if user.role in UNRESTRICTED_ROLES:
        return None
    own = or_(Asset.owner_id == user.id, Asset.custodian_id == user.id)
    if user.role == "MANAGER":
        depts = manager_departments(user)
        dept_clause = Asset.department.in_(depts) if depts else false()
        return or_(own, dept_clause)
    serials = await granted_serials(db, user)
    return or_(own, Asset.serial_number.in_(serials)) if serials else own


async def can_see_asset(db: AsyncSession, user: User, asset: Asset) -> bool:
    if user.role in UNRESTRICTED_ROLES:
        return True
    if asset.owner_id == user.id or (asset.custodian_id and asset.custodian_id == user.id):
        return True
    if user.role == "MANAGER":
        return bool(asset.department) and asset.department in manager_departments(user)
    return asset.serial_number in await granted_serials(db, user)


def can_manage_asset(user: User, asset: Asset) -> bool:
    """Approve / administer: ADMIN everywhere, MANAGER within their departments."""
    if user.role == "ADMIN":
        return True
    if user.role == "MANAGER":
        return bool(asset.department) and asset.department in manager_departments(user)
    return False


def can_see_sensitive_physical(user: User, asset: Asset) -> bool:
    if user.role in UNRESTRICTED_ROLES:
        return True
    return can_manage_asset(user, asset)


def redact_asset_dict(data: dict, user: User, asset: Asset) -> dict:
    if not can_see_sensitive_physical(user, asset):
        for field in SENSITIVE_PHYSICAL_FIELDS:
            if field in data:
                data[field] = None
    return data


def can_see_user(actor: User, target: User) -> bool:
    if actor.role in UNRESTRICTED_ROLES or actor.id == target.id:
        return True
    if actor.role == "MANAGER":
        return bool(target.department) and target.department in manager_departments(actor)
    return False


def user_scope_clause(actor: User):
    if actor.role in UNRESTRICTED_ROLES:
        return None
    if actor.role == "MANAGER":
        depts = manager_departments(actor)
        return or_(User.id == actor.id, User.department.in_(depts)) if depts else (User.id == actor.id)
    return User.id == actor.id
