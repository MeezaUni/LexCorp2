import uuid
from typing import Optional, List

from sqlalchemy import String, Enum, Float, ForeignKey, Text, JSON, Uuid, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    wallet_address: Mapped[str] = mapped_column(String(42), unique=True, index=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contact_number: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    organization: Mapped[str] = mapped_column(String(255), default="Bharat Electronics Limited (BEL)")
    department: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    did: Mapped[Optional[str]] = mapped_column(String, unique=True, index=True, nullable=True)
    role: Mapped[str] = mapped_column(String(20), default="USER")  # ADMIN, MANAGER, AUDITOR, USER
    is_active: Mapped[bool] = mapped_column(default=True)
    session_version: Mapped[int] = mapped_column(Integer, default=0)

    # 2FA / TOTP support
    totp_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # High-Assurance Hardware WebAuthn/Passkey Credentials
    webauthn_credentials: Mapped[List["WebAuthnCredential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    assets: Mapped[list["Asset"]] = relationship(back_populates="owner", foreign_keys="[Asset.owner_id]")
    custodied_assets: Mapped[list["Asset"]] = relationship(back_populates="custodian", foreign_keys="[Asset.custodian_id]")
    credentials: Mapped[list["VerifiableCredential"]] = relationship(back_populates="user")


class WebAuthnCredential(Base, TimestampMixin):
    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    credential_id: Mapped[str] = mapped_column(String(512), unique=True, index=True)  # base64url encoded
    public_key: Mapped[str] = mapped_column(Text)  # base64url encoded credential public key
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    device_name: Mapped[Optional[str]] = mapped_column(String(255), default="Biometric Authenticator")
    transports: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    user: Mapped[User] = relationship(back_populates="webauthn_credentials")


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    token_id: Mapped[int] = mapped_column(unique=True, index=True)
    serial_number: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(50), default="EQUIPMENT")  # EQUIPMENT, COMPONENT, DOCUMENT, SOFTWARE_LICENSE
    metadata_cid: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # Off-chain pointer / URI
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # SHA-256 integrity hash

    # Ownership (Organization / Entity) vs Custody (Assigned Division / Engineer)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    owner: Mapped[User] = relationship(back_populates="assets", foreign_keys=[owner_id])

    custodian_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    custodian: Mapped[Optional[User]] = relationship(back_populates="custodied_assets", foreign_keys=[custodian_id])

    custodian_did: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    custodian_department: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # Lifecycle State: CREATED -> VERIFIED -> ASSIGNED -> TRANSFERRED -> MAINTENANCE -> RETURNED -> RETIRED
    lifecycle_status: Mapped[str] = mapped_column(String(30), default="CREATED")


class MaintenanceRecord(Base, TimestampMixin):
    __tablename__ = "maintenance_records"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    asset_serial: Mapped[str] = mapped_column(String, index=True)
    performed_by_did: Mapped[str] = mapped_column(String, index=True)
    action_description: Mapped[str] = mapped_column(Text)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    log_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # SHA-256 of maintenance log
    tx_hash: Mapped[Optional[str]] = mapped_column(String(66), nullable=True)


class AccessRequest(Base, TimestampMixin):
    __tablename__ = "access_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    requester_did: Mapped[str] = mapped_column(String, index=True)
    asset_serial: Mapped[str] = mapped_column(String, index=True)
    status: Mapped[str] = mapped_column(String, default="PENDING")  # PENDING, APPROVED, REJECTED
    signature: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class AuditEvent(Base, TimestampMixin):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    event_type: Mapped[str] = mapped_column(String, index=True)  # Mint, Transfer, Revoke, RoleGrant, AccessAttempted
    tx_hash: Mapped[str] = mapped_column(String, unique=True, index=True)
    block_number: Mapped[int] = mapped_column(index=True)
    actor_did: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    target_did: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    asset_serial: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # AI Risk Engine outputs
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_label: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_factors: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class VerifiableCredential(Base, TimestampMixin):
    __tablename__ = "verifiable_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    vc_jwt: Mapped[str] = mapped_column(Text)
    issuer_did: Mapped[str] = mapped_column(String)
    subject_did: Mapped[str] = mapped_column(String)
    type: Mapped[str] = mapped_column(String)  # e.g., "BELSecurityClearanceCredential"

    user: Mapped[User] = relationship(back_populates="credentials")
