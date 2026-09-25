import uuid
from datetime import date, datetime
from typing import Optional, List

from sqlalchemy import Index, text, String, Enum, Float, ForeignKey, Text, JSON, Uuid, Boolean, Integer, BigInteger, UniqueConstraint, DateTime, Date
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
    # MANAGER only: departments managed in addition to `department`.
    managed_departments: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    did: Mapped[Optional[str]] = mapped_column(String, unique=True, index=True, nullable=True)
    role: Mapped[str] = mapped_column(String(20), default="USER")  # ADMIN, MANAGER, AUDITOR, USER
    is_active: Mapped[bool] = mapped_column(default=True)
    onboarding_pending: Mapped[bool] = mapped_column(Boolean, default=True)
    session_version: Mapped[int] = mapped_column(Integer, default=0)
    # Legacy plaintext PIN column. Migration 0003 moved values into pin_hash; never written.
    one_time_pin: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    pin_hash: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    pin_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    pin_used: Mapped[bool] = mapped_column(Boolean, default=False)
    reset_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    reset_requested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reset_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Unlocks the browser's encrypted wallet keystore; encrypted at rest, rotated on provisioning.
    wallet_wrap_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Server-side session activity (single active session per user) and identity revocation
    last_activity_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # TOTP secrets are stored encrypted (app.core.crypto). *_last_step blocks code replay.
    # Factor 1: Login TOTP
    totp_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_step: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    # Factor 2: View / Submission TOTP
    totp_factor2_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_totp_factor2_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_factor2_last_step: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    # Factor 3: Mint / Approve / Modify TOTP
    totp_factor3_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_totp_factor3_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_factor3_last_step: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

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
    factor_scope: Mapped[str] = mapped_column(String(20), default="login")

    user: Mapped[User] = relationship(back_populates="webauthn_credentials")


class ActionIdCounter(Base):
    """Atomic per-prefix, per-UTC-day counter backing CRT/VW/DL/MOD-YYYYMMDD-XXXX IDs."""
    __tablename__ = "action_id_counters"

    prefix: Mapped[str] = mapped_column(String(8), primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    last_value: Mapped[int] = mapped_column(Integer)


class Department(Base, TimestampMixin):
    __tablename__ = "departments"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class AuthChallenge(Base, TimestampMixin):
    """Single-use server-side challenge: SIWE nonces and WebAuthn challenges."""
    __tablename__ = "auth_challenges"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(20), index=True)  # SIWE, WEBAUTHN_REG, WEBAUTHN_AUTH
    wallet_address: Mapped[Optional[str]] = mapped_column(String(42), index=True, nullable=True)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    purpose: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # login, factor2, factor3
    action: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    challenge: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class StepUpGrant(Base, TimestampMixin):
    """Proof that a purpose-specific factor (Factor 2 / Factor 3) was just satisfied
    for one named action. Single-use and short-lived; only the token hash is stored."""
    __tablename__ = "step_up_grants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    purpose: Mapped[str] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(64))
    method: Mapped[str] = mapped_column(String(10))  # TOTP, PASSKEY
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    session_version: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        # Global normalised uniqueness (migration 0008): serial, MAC and unique address
        Index("ux_assets_serial_norm", text("lower(btrim(serial_number))"), unique=True),
        Index("ux_assets_mac_norm", text("lower(regexp_replace(mac_address, '[^0-9a-fA-F]', '', 'g'))"),
              unique=True, postgresql_where=text("mac_address IS NOT NULL")),
        Index("ux_assets_unique_address_norm", text("lower(btrim(device_unique_address))"),
              unique=True, postgresql_where=text("device_unique_address IS NOT NULL")),
    )

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

    # Lifecycle State
    lifecycle_status: Mapped[str] = mapped_column(String(30), default="CREATED")

    # Revision Tree (Phase 7)
    parent_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("assets.id"), nullable=True)
    parent_asset: Mapped[Optional["Asset"]] = relationship(remote_side=[id], back_populates="revisions", foreign_keys=[parent_asset_id])
    revisions: Mapped[List["Asset"]] = relationship(back_populates="parent_asset", foreign_keys=[parent_asset_id])
    # Version lineage: the original is version 1; every revision is a new row (originals never overwritten).
    version_number: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    root_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("assets.id"), index=True, nullable=True)

    # Action / Approval Tracking (Phase 4, 6)
    action_id: Mapped[Optional[str]] = mapped_column(String(64), unique=True, index=True, nullable=True)
    action_type: Mapped[Optional[str]] = mapped_column(String(20), index=True, nullable=True)
    approval_status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    watermark_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Physical Asset Constraint Fields (Phase 9)
    is_physical: Mapped[bool] = mapped_column(Boolean, default=False)
    mac_address: Mapped[Optional[str]] = mapped_column(String(64), unique=True, index=True, nullable=True)
    device_unique_address: Mapped[Optional[str]] = mapped_column(String(128), unique=True, index=True, nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


class DocumentAction(Base, TimestampMixin):
    __tablename__ = "document_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    action_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    action_type: Mapped[str] = mapped_column(String(20), index=True)  # VIEW, DOWNLOAD, CREATION, MODIFICATION
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("assets.id"), nullable=True)
    asset_serial: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)

    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    actor_did: Mapped[str] = mapped_column(String, index=True)
    approver_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    approver_did: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    asset_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    purpose: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    client_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    download_token: Mapped[Optional[str]] = mapped_column(String(128), unique=True, index=True, nullable=True)
    token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    watermark_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


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



class AssetAccessGrant(Base, TimestampMixin):
    """Approved delegated access. View and download are separate permissions;
    max_views (None = unlimited) and expires_at (None = no expiry) are enforced
    server-side, and only successful authorized views increment views_count."""
    __tablename__ = "asset_access_grants"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("assets.id"), index=True, nullable=True)
    asset_serial: Mapped[str] = mapped_column(String, index=True)
    grantee_did: Mapped[str] = mapped_column(String, index=True)
    granted_by_did: Mapped[str] = mapped_column(String)
    requested_by_did: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    request_action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    access_level: Mapped[int] = mapped_column(Integer, default=1)
    can_view: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    can_download: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    max_views: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    views_count: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_did: Mapped[Optional[str]] = mapped_column(String, nullable=True)

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
    client_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # AI Risk Engine outputs
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_label: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_factors: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Workflow integration for Security Incidents
    alert_status: Mapped[str] = mapped_column(String, default="OPEN") # OPEN, FORWARDED_TO_MANAGER, ESCALATED_TO_ADMIN, DISMISSED, RESOLVED


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


class SecurityAlert(Base, TimestampMixin):
    """A dedicated high-risk alert. State machine:
    AUDITOR_REVIEW -> (DISMISSED | MANAGER_REVIEW) -> (DISMISSED | ADMIN_REVIEW)
    -> (DISMISSED | IDENTITY_REVOKED). History lives in security_alert_actions."""
    __tablename__ = "security_alerts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(10))  # AI | RULE | LEGACY
    source_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("audit_events.id"), unique=True, index=True, nullable=True)
    subject_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    subject_did: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    subject_role: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    subject_wallet: Mapped[Optional[str]] = mapped_column(String(42), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    risk_level: Mapped[str] = mapped_column(String(10))
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    event_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    asset_serial: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    related_action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    client_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(20), index=True)


class SecurityAlertAction(Base, TimestampMixin):
    __tablename__ = "security_alert_actions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("security_alerts.id"), index=True)
    actor_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_did: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    action: Mapped[str] = mapped_column(String(30))  # RAISED IMPORTED FORWARDED_TO_MANAGER FORWARDED_TO_ADMIN DISMISSED IDENTITY_REVOKED
    from_state: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    to_state: Mapped[str] = mapped_column(String(20))
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class IndexerState(Base, TimestampMixin):
    """Single-row indexer cursor. The block hash detects a replaced chain/contract."""
    __tablename__ = "indexer_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    contract_address: Mapped[str] = mapped_column(String(42))
    last_block: Mapped[int] = mapped_column(Integer)
    last_block_hash: Mapped[str] = mapped_column(String(66))

