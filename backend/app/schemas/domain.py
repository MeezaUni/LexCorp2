import uuid
from datetime import datetime
from typing import Optional, List, Any

from pydantic import BaseModel, ConfigDict


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# User Schemas
class UserBase(BaseSchema):
    wallet_address: str
    name: Optional[str] = None
    contact_number: Optional[str] = None
    organization: Optional[str] = "Bharat Electronics Limited (BEL)"
    department: Optional[str] = None
    did: Optional[str] = None
    role: str = "USER"
    is_active: bool = True
    is_totp_enabled: bool = False

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

class AssetCreate(AssetBase):
    owner_id: uuid.UUID
    custodian_id: Optional[uuid.UUID] = None

class AssetRead(AssetBase):
    id: uuid.UUID
    owner_id: uuid.UUID
    custodian_id: Optional[uuid.UUID] = None
    owner_wallet: Optional[str] = None
    owner_name: Optional[str] = None
    custodian_name: Optional[str] = None
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
    risk_score: Optional[float] = None
    risk_label: Optional[str] = None
    risk_factors: Optional[dict] = None

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
