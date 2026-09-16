"""User and Role Management API endpoints (Admin)."""

from typing import List, Optional
import uuid
import subprocess
import os
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from web3 import Web3

from app.core.config import settings
from app.core.database import get_db
from app.api.dependencies import get_current_active_user, get_manager_user, get_admin_user
from app.models.domain import User, Asset, VerifiableCredential

router = APIRouter(prefix="/users", tags=["users"])


def auto_fund_wallet(wallet_address: str):
    """Automatically fund the newly provisioned wallet with 1000 ETH on the local Hardhat network."""
    try:
        contracts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../contracts"))

        # Use shell=True for npx to resolve correctly on Windows
        import platform
        use_shell = platform.system() == "Windows"

        env = os.environ.copy()
        env["FUND_RECIPIENT"] = wallet_address

        # The command to run
        cmd = ["npx", "hardhat", "run", "scripts/fund_user.js", "--network", "localhost"]

        result = subprocess.run(
            cmd,
            cwd=contracts_dir,
            env=env,
            check=True,
            capture_output=True,
            shell=use_shell
        )
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode()
        print(f"Warning: Failed to auto-fund {wallet_address}. {err_msg}")
        raise RuntimeError(f"Faucet failed: {err_msg}")
    except Exception as e:
        print(f"Warning: Failed to auto-fund {wallet_address}. {e}")
        raise RuntimeError(f"Faucet execution failed: {str(e)}")


class UserResponse(BaseModel):
    id: str
    wallet_address: str
    name: Optional[str] = None
    contact_number: Optional[str] = None
    did: Optional[str] = None
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class CreateUserRequest(BaseModel):
    wallet_address: str
    name: Optional[str] = None
    contact_number: Optional[str] = None
    role: str = "USER"  # ADMIN, MANAGER, AUDITOR, USER


class UpdateRoleRequest(BaseModel):
    role: str


@router.get("", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all registered users and their current roles."""
    result = await db.execute(select(User).where(User.is_active == True).order_by(User.created_at.desc()))
    users = result.scalars().all()
    return [
        UserResponse(
            id=str(u.id),
            wallet_address=u.wallet_address,
            name=u.name,
            contact_number=u.contact_number,
            did=u.did,
            role=u.role,
            is_active=u.is_active,
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
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
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
        # Hierarchy Enforcement for update
        existing_role_level = ROLE_HIERARCHY.get(existing_user.role, 0)
        if existing_role_level >= acting_role_level:
            if current_user.role != "ADMIN":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to modify this user",
                )

        # Update existing user's details
        existing_user.role = role_clean
        if request.name:
            existing_user.name = request.name
        if request.contact_number:
            existing_user.contact_number = request.contact_number
        await db.commit()
        await db.refresh(existing_user)
        return UserResponse(
            id=str(existing_user.id),
            wallet_address=existing_user.wallet_address,
            name=existing_user.name,
            contact_number=existing_user.contact_number,
            did=existing_user.did,
            role=existing_user.role,
            is_active=existing_user.is_active,
        )

    # Issue DID and create new record
    did = f"did:ethr:{settings.CHAIN_ID}:{checksummed.lower()}"
    new_user = User(
        wallet_address=checksummed.lower(),
        name=request.name,
        contact_number=request.contact_number,
        did=did,
        role=role_clean,
        is_active=True,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Fund the newly generated wallet with ETH on local network so they can transact
    auto_fund_wallet(new_user.wallet_address)

    return UserResponse(
        id=str(new_user.id),
        wallet_address=new_user.wallet_address,
        name=new_user.name,
        contact_number=new_user.contact_number,
        did=new_user.did,
        role=new_user.role,
        is_active=new_user.is_active,
    )


@router.patch("/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: str,
    request: UpdateRoleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
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

    existing_role_level = ROLE_HIERARCHY.get(user.role, 0)
    if existing_role_level >= acting_role_level and current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to modify this user",
        )

    user.role = role_clean
    await db.commit()
    await db.refresh(user)
    return UserResponse(
        id=str(user.id),
        wallet_address=user.wallet_address,
        name=user.name,
        contact_number=user.contact_number,
        did=user.did,
        role=user.role,
        is_active=user.is_active,
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_manager_user),
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

    acting_role_level = ROLE_HIERARCHY.get(current_user.role, 0)
    target_role_level = ROLE_HIERARCHY.get(user.role, 0)

    if target_role_level >= acting_role_level and current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to revoke this user",
        )

    # Soft delete: deactivate the user instead of deleting
    # This preserves audit trail and historical blockchain references
    user.is_active = False
    await db.commit()

    return None

@router.post("/{user_id}/fund")
async def fund_user_wallet(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_manager_user),
):
    """Fund an existing user's wallet address with 10 ETH."""
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

    try:
        auto_fund_wallet(user.wallet_address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"message": f"Successfully funded {user.wallet_address} with 1000 LEX"}

