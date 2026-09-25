"""User and Role Management API endpoints (Admin)."""

from typing import List, Optional
import uuid
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from web3 import Web3

from app.core.config import settings
from app.core.database import get_db
from app.api.dependencies import get_onboarded_user, get_manager_user, get_admin_user, get_request_client_ip, get_step_up_token, record_audit
from app.services import mfa
from app.services.chain import sync_user_chain_roles
from app.services import access
from app.models.domain import Department
from fastapi import Request
from app.models.domain import User, Asset, VerifiableCredential
from app.services.security import generate_one_time_pin
from app.core.crypto import hash_pin
from datetime import UTC

router = APIRouter(prefix="/users", tags=["users"])


class UserResponse(BaseModel):
    id: str
    wallet_address: str
    name: Optional[str] = None
    contact_number: Optional[str] = None
    department: Optional[str] = None
    did: Optional[str] = None
    role: str
    is_active: bool
    onboarding_pending: Optional[bool] = None
    one_time_pin: Optional[str] = None
    pin_expires_at: Optional[datetime] = None
    reset_requested: Optional[bool] = None
    chain_roles: Optional[dict] = None

    class Config:
        from_attributes = True


class CreateUserRequest(BaseModel):
    wallet_address: str
    name: Optional[str] = None
    contact_number: Optional[str] = None
    department: Optional[str] = None
    role: str = "USER"  # ADMIN, MANAGER, AUDITOR, USER
    totp_code: Optional[str] = None  # Factor 3 (or X-Step-Up-Token header)


class UpdateRoleRequest(BaseModel):
    role: str
    totp_code: Optional[str] = None  # Factor 3 (or X-Step-Up-Token header)


@router.get("", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_onboarded_user)
):
    """Users visible to the caller: ADMIN/AUDITOR all, MANAGER their departments, USER self."""
    query = select(User).where(User.is_active == True)
    clause = access.user_scope_clause(current_user)
    if clause is not None:
        query = query.where(clause)

    result = await db.execute(query.order_by(User.created_at.desc()))
    users = result.scalars().all()
    return [
        UserResponse(
            id=str(u.id),
            wallet_address=u.wallet_address,
            name=u.name,
            contact_number=u.contact_number,
            department=u.department,
            did=u.did,
            role=u.role,
            is_active=u.is_active,
            onboarding_pending=u.onboarding_pending,
            reset_requested=u.reset_requested,
        )
        for u in users
    ]


# Role Hierarchy mapping
# ADMIN can create MANAGER and USER (cannot create ADMIN)
# MANAGER can create USER (cannot create MANAGER or ADMIN)
# USER and AUDITOR cannot create any users
ROLE_HIERARCHY = {
    "ADMIN": 3,
    "MANAGER": 2,
    "AUDITOR": 1,
    "USER": 0
}

@router.post("", response_model=UserResponse)
async def create_or_register_user(
    request: CreateUserRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_onboarded_user),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Create or pre-seed a user with a specific role, enforcing strict role hierarchy.

    Hierarchy Rules:
    - A role can only create roles STRICTLY BELOW itself
    - ADMIN (3) can create: MANAGER (2), USER (0) — CANNOT create ADMIN (3)
    - MANAGER (2) can create: USER (0) — CANNOT create MANAGER (2), ADMIN (3)
    - USER (0) and AUDITOR (1) CANNOT create any users
    """
    # 1. Reject creation requests from USER and AUDITOR
    if current_user.role in ("USER", "AUDITOR"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{current_user.role}' is not permitted to create users",
        )

    # 2. Validate address format
    try:
        checksummed = Web3.to_checksum_address(request.wallet_address)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Ethereum wallet address format",
        )

    role_clean = request.role.upper()
    if role_clean not in ROLE_HIERARCHY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role must be one of ADMIN, MANAGER, AUDITOR, USER",
        )

    # 3. Hierarchy Enforcement: target must be STRICTLY BELOW acting role
    acting_role_level = ROLE_HIERARCHY.get(current_user.role, 0)
    target_role_level = ROLE_HIERARCHY.get(role_clean, 0)

    # Strict check: target must be lower than acting (target_role_level >= acting_role_level is DENIED)
    # This ensures ADMIN cannot create ADMIN, and MANAGER cannot create MANAGER/ADMIN
    if target_role_level >= acting_role_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot provision role '{role_clean}' with your current permissions (can only create roles below {current_user.role})",
        )

    # Check if user already exists
    result = await db.execute(
        select(User).where(func.lower(User.wallet_address) == checksummed.lower())
    )
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists for this wallet address. Use the role update action instead of registering it again.",
        )

    # Department enforcement: the submitted department must be one this actor is
    # authorized for (server-side list), regardless of what the UI offered.
    target_department = request.department
    if current_user.role == "MANAGER" and not target_department:
        target_department = current_user.department
    target_department = await access.require_assignable_department(db, current_user, target_department)

    # Provisioning an identity (and its on-chain role) requires Factor 3.
    await mfa.require_factor(db, current_user, "identity.provision", totp_code=request.totp_code, step_up_token=step_up_token)

    # Issue DID and create new record
    did = f"did:ethr:{settings.CHAIN_ID}:{checksummed.lower()}"
    # The PIN is returned once in this response and stored only as a scrypt hash.
    pin = generate_one_time_pin(12)
    pin_expires_at = datetime.now(UTC) + timedelta(hours=settings.PROVISIONING_PIN_TTL_HOURS)

    new_user = User(
        wallet_address=checksummed.lower(),
        name=request.name,
        contact_number=request.contact_number,
        department=target_department,
        did=did,
        role=role_clean,
        is_active=True,
        onboarding_pending=True,
        pin_hash=hash_pin(pin),
        pin_expires_at=pin_expires_at,
        pin_used=False
    )
    db.add(new_user)
    await record_audit(db, "USER_PROVISIONED", actor_did=current_user.did, target_did=did,
                       client_ip=get_request_client_ip(http_request),
                       details={"role": role_clean, "department": target_department})
    await db.commit()
    await db.refresh(new_user)

    # Grant the on-chain roles that match this identity (no funding is needed on the
    # zero-fee network). A failure is audited and retried by the reconciler; the
    # one-time PIN, which exists only in this response, is still returned.
    chain_roles = await sync_user_chain_roles(db, new_user, actor_did=current_user.did,
                                              client_ip=get_request_client_ip(http_request))

    return UserResponse(
        id=str(new_user.id),
        wallet_address=new_user.wallet_address,
        name=new_user.name,
        contact_number=new_user.contact_number,
        department=new_user.department,
        did=new_user.did,
        role=new_user.role,
        is_active=new_user.is_active,
        onboarding_pending=new_user.onboarding_pending,
        one_time_pin=pin,
        pin_expires_at=new_user.pin_expires_at,
        reset_requested=new_user.reset_requested,
        chain_roles=chain_roles,
    )


@router.patch("/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: str,
    request: UpdateRoleRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_onboarded_user),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Update role for an existing user enforcing strict hierarchy."""
    if current_user.role in ("USER", "AUDITOR"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{current_user.role}' is not permitted to modify roles",
        )

    role_clean = request.role.upper()
    if role_clean not in ["ADMIN", "MANAGER", "AUDITOR", "USER"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role must be one of ADMIN, MANAGER, AUDITOR, USER",
        )

    acting_role_level = ROLE_HIERARCHY.get(current_user.role, 0)
    target_role_level = ROLE_HIERARCHY.get(role_clean, 0)

    # Cannot promote to equal or higher role
    if target_role_level >= acting_role_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot provision role '{role_clean}' with your current permissions (can only assign roles below {current_user.role})",
        )

    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID format"
        )

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Department restriction for modifications
    if not access.can_see_user(current_user, user) or current_user.role == "AUDITOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Managers can only modify users in their own department ({current_user.department}).",
        )

    existing_role_level = ROLE_HIERARCHY.get(user.role, 0)
    if existing_role_level >= acting_role_level and current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to modify this user",
        )

    if user.id == current_user.id:
        raise HTTPException(status_code=403, detail="You cannot change your own role.")
    await mfa.require_factor(db, current_user, "identity.role", totp_code=request.totp_code, step_up_token=step_up_token)
    previous = user.role
    user.role = role_clean
    user.session_version = (user.session_version or 0) + 1  # new privileges require a new session
    await record_audit(db, "ROLE_CHANGED", actor_did=current_user.did, target_did=user.did,
                       client_ip=get_request_client_ip(http_request), details={"from": previous, "to": role_clean})
    await db.commit()
    await db.refresh(user)
    chain_roles = await sync_user_chain_roles(db, user, actor_did=current_user.did,
                                              client_ip=get_request_client_ip(http_request))
    return UserResponse(
        id=str(user.id),
        wallet_address=user.wallet_address,
        name=user.name,
        contact_number=user.contact_number,
        did=user.did,
        role=user.role,
        is_active=user.is_active,
        chain_roles=chain_roles,
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_manager_user),
    step_up_token: Optional[str] = Depends(get_step_up_token),
):
    """Revoke a user's identity by setting is_active=False (soft delete).

    This preserves historical audit trails while preventing the user from accessing the system.
    All blockchain events and audit logs remain intact for compliance purposes.
    """
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID format"
        )

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Department restriction for revocation
    if not access.can_see_user(current_user, user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Managers can only revoke users in their own department ({current_user.department}).",
        )

    from app.services.identity import revoke_identity
    await mfa.require_factor(db, current_user, "identity.revoke", step_up_token=step_up_token)
    await revoke_identity(db, current_user, user, "Revoked by administrator", require_no_owned_assets=True,
                          client_ip=get_request_client_ip(http_request))
    await db.commit()
    # Remove any on-chain operational role the identity held.
    await sync_user_chain_roles(db, user, actor_did=current_user.did, client_ip=get_request_client_ip(http_request))
    return None

# ---------------------------------------------------------------- Departments

class DepartmentCreateRequest(BaseModel):
    name: str


class ManagedDepartmentsRequest(BaseModel):
    departments: List[str]


@router.get("/departments")
async def list_assignable_departments(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_onboarded_user),
):
    """Departments the caller may assign (drives the create-user dropdown; the
    backend re-validates every submission independently)."""
    return {"departments": await access.assignable_departments(db, current_user)}


@router.post("/departments")
async def create_department(
    req: DepartmentCreateRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    name = req.name.strip()
    if not name or len(name) > 255:
        raise HTTPException(status_code=400, detail="Department name is required (max 255 characters).")
    exists = (await db.execute(select(Department).where(func.lower(Department.name) == name.lower()))).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="Department already exists.")
    db.add(Department(name=name, is_active=True))
    await record_audit(db, "DEPARTMENT_CREATED", actor_did=admin.did, client_ip=get_request_client_ip(http_request),
                       details={"department": name})
    await db.commit()
    return {"name": name}


@router.put("/{user_id}/managed-departments")
async def set_managed_departments(
    user_id: str,
    req: ManagedDepartmentsRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_admin_user),
):
    """ADMIN grants a MANAGER authority over additional departments."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    target = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.role != "MANAGER":
        raise HTTPException(status_code=400, detail="Managed departments apply to MANAGER accounts only.")
    active = set(await access.active_department_names(db))
    unknown = [d for d in req.departments if d not in active]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown or inactive departments: {unknown}")
    target.managed_departments = sorted(set(req.departments))
    await record_audit(db, "MANAGER_DEPARTMENTS_UPDATED", actor_did=admin.did, target_did=target.did,
                       client_ip=get_request_client_ip(http_request),
                       details={"managed_departments": target.managed_departments})
    await db.commit()
    return {"user_id": str(target.id), "managed_departments": target.managed_departments}
