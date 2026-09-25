import uuid
from datetime import datetime
from typing import Optional, List, Any

from pydantic import BaseModel, Field, ConfigDict


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# User Schemas
class UserBase(BaseSchema):
    wallet_address: str
    name: Optional[str] = None
    contact_number: Optional[str] = None
    organization: Optional[str] = "LexCorp2"
    department: Optional[str] = None
    did: Optional[str] = None
    role: str = "USER"
    is_active: bool = True
    onboarding_pending: bool = True
    is_totp_enabled: bool = False
    is_totp_factor2_enabled: bool = False
    is_totp_factor3_enabled: bool = False

class UserCreate(UserBase):
    pass

class UserRead(UserBase):
    id: uuid.UUID
    has_webauthn: Optional[bool] = False
    created_at: datetime
    updated_at: datetime


# Asset Schemas
class AssetBase(BaseSchema):
    token_id: int
    serial_number: str
    name: Optional[str] = None
    asset_type: str = "EQUIPMENT"
    metadata_cid: Optional[str] = None
    file_hash: Optional[str] = None
    custodian_did: Optional[str] = None
    custodian_department: Optional[str] = None
    lifecycle_status: str = "CREATED"
    parent_asset_id: Optional[uuid.UUID] = None
    action_id: Optional[str] = None
    action_type: Optional[str] = None
    approval_status: str = "ACTIVE"
    watermark_metadata: Optional[dict] = None
    is_physical: bool = False
    mac_address: Optional[str] = None
    device_unique_address: Optional[str] = None
    location: Optional[str] = None
    department: Optional[str] = None

class AssetCreate(AssetBase):
    owner_id: uuid.UUID
    custodian_id: Optional[uuid.UUID] = None

class AssetRead(AssetBase):
    id: uuid.UUID
    owner_id: uuid.UUID
    custodian_id: Optional[uuid.UUID] = None
    owner_wallet: Optional[str] = None
    owner_address: Optional[str] = None
    owner_did: Optional[str] = None
    owner_name: Optional[str] = None
    custodian_name: Optional[str] = None
    is_digital: Optional[bool] = None
    offchain_uri: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# Document Action Schemas
class DocumentActionBase(BaseSchema):
    action_id: str
    action_type: str
    asset_id: Optional[uuid.UUID] = None
    asset_serial: Optional[str] = None
    actor_did: str
    approver_did: Optional[str] = None
    status: str = "PENDING"
    purpose: Optional[str] = None
    client_ip: Optional[str] = None
    download_token: Optional[str] = None
    token_expires_at: Optional[datetime] = None
    watermark_text: Optional[str] = None
    details: Optional[dict] = None

class DocumentActionCreate(BaseSchema):
    action_type: str
    asset_id: Optional[uuid.UUID] = None
    asset_serial: Optional[str] = None
    purpose: Optional[str] = None
    details: Optional[dict] = None

class DocumentProposalRequest(BaseSchema):
    name: str # Document Title
    serial_number: str
    file_hash: str
    offchain_uri: str
    recipient_did: Optional[str] = None
    recipient_address: str
    department: Optional[str] = None
    purpose: Optional[str] = None
    totp_code: Optional[str] = None

class PhysicalProposalRequest(BaseSchema):
    name: str
    serial_number: str
    asset_type: str = "EQUIPMENT"
    has_mac_address: Optional[bool] = None  # YES -> mac_address required; NO -> device_unique_address required
    mac_address: Optional[str] = None
    device_unique_address: Optional[str] = None
    location: Optional[str] = None
    department: Optional[str] = None
    purpose: Optional[str] = None
    totp_code: Optional[str] = None
    recipient_did: Optional[str] = None
    recipient_address: str

class DocumentRevisionRequest(BaseSchema):
    parent_asset_serial: str
    name: str # New Document Title
    new_serial_number: Optional[str] = None  # server generates <root serial>-V<n> when omitted
    new_file_hash: str
    new_offchain_uri: str
    # The approved + completed MODIFICATION download this revision comes from (required)
    modification_download_id: Optional[str] = None
    purpose: Optional[str] = None
    totp_code: Optional[str] = None

class ShareProposalRequest(BaseSchema):
    asset_serial: str
    target_did: str
    access_level: int = 1
    purpose: Optional[str] = None
    totp_code: Optional[str] = None
    max_views: Optional[int] = None  # a suggestion only; the approver decides
    request_download: bool = False

class DocumentApprovalRequest(BaseSchema):
    decision: str # "APPROVE" or "REJECT"
    totp_code: Optional[str] = None
    rejection_reason: Optional[str] = None
    # Delegated-access approvals only (defaults: unlimited views, no expiry, view-only)
    max_views: Optional[int] = Field(default=None, ge=1)
    accessible_until: Optional[datetime] = None
    allow_download: bool = False

class DownloadRequest(BaseSchema):
    asset_serial: str
    purpose: Optional[str] = None
    totp_code: Optional[str] = None
    mode: str = "STANDARD"  # STANDARD | MODIFICATION (controlled download for editing)

class OwnerDecisionRequest(BaseSchema):
    decision: str  # APPROVE | REJECT
    totp_code: Optional[str] = None
    rejection_reason: Optional[str] = None

class FetchDownloadRequest(BaseSchema):
    totp_code: Optional[str] = None

class DocumentActionRead(DocumentActionBase):
    id: uuid.UUID
    actor_id: uuid.UUID
    approver_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime


# Maintenance Schemas
class MaintenanceRecordBase(BaseSchema):
    asset_serial: str
    performed_by_did: str
    action_description: str
    notes: Optional[str] = None
    log_hash: Optional[str] = None
    tx_hash: Optional[str] = None

class MaintenanceRecordCreate(MaintenanceRecordBase):
    pass

class MaintenanceRecordRead(MaintenanceRecordBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


# Access Request Schemas
class AccessRequestBase(BaseSchema):
    requester_did: str
    asset_serial: str

class AccessRequestCreate(AccessRequestBase):
    pass

class AccessRequestRead(AccessRequestBase):
    id: uuid.UUID
    status: str
    signature: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# Audit Event Schemas
class AuditEventBase(BaseSchema):
    event_type: str
    tx_hash: str
    block_number: int
    actor_did: Optional[str] = None
    target_did: Optional[str] = None
    asset_serial: Optional[str] = None
    client_ip: Optional[str] = None
    risk_score: Optional[float] = None
    risk_label: Optional[str] = None
    risk_factors: Optional[dict] = None
    alert_status: Optional[str] = None  # current SecurityAlert state, if this event raised one

class AlertStatusUpdateRequest(BaseSchema):
    alert_status: str # FORWARDED_TO_MANAGER, ESCALATED_TO_ADMIN, DISMISSED, RESOLVED

class AuditEventCreate(AuditEventBase):
    pass

class AuditEventRead(AuditEventBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


# Verifiable Credential Schemas
class VcBase(BaseSchema):
    issuer_did: str
    subject_did: str
    type: str

class VcCreate(VcBase):
    user_id: uuid.UUID
    vc_jwt: str

class VcRead(VcBase):
    id: uuid.UUID
    user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class PhysicalStatusRequest(BaseSchema):
    status: str
    reason: Optional[str] = None
    totp_code: Optional[str] = None


class MintConfirmRequest(BaseSchema):
    tx_hash: str

