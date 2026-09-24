import re

with open('backend/app/models/domain.py', 'r', encoding='utf-8') as f:
    code = f.read()

audit_event_block = """    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_label: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_factors: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)"""
audit_event_new = """    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_label: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_factors: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Workflow integration for Security Incidents
    alert_status: Mapped[str] = mapped_column(String, default="OPEN") # OPEN, FORWARDED_TO_MANAGER, ESCALATED_TO_ADMIN, DISMISSED, RESOLVED"""

code = code.replace(audit_event_block, audit_event_new)

access_grant_code = """
class AssetAccessGrant(Base, TimestampMixin):
    __tablename__ = "asset_access_grants"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    asset_serial: Mapped[str] = mapped_column(String, index=True)
    grantee_did: Mapped[str] = mapped_column(String, index=True)
    granted_by_did: Mapped[str] = mapped_column(String)
    access_level: Mapped[int] = mapped_column(Integer, default=1)
    max_views: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    views_count: Mapped[int] = mapped_column(Integer, default=0)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

"""

if "class AssetAccessGrant" not in code:
    code = code.replace("class AuditEvent(Base, TimestampMixin):", access_grant_code + "class AuditEvent(Base, TimestampMixin):")

with open('backend/app/models/domain.py', 'w', encoding='utf-8') as f:
    f.write(code)

print("domain models patched")
