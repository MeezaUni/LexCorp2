"""Test suite for Phase 8: Digital QR Verification & Role-Based Redaction (VW-)."""

import pytest
import uuid
import random
from app.services.auth import create_jwt
from app.models.domain import Asset, User
from sqlalchemy import select

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower()
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower()
USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower()

def get_token(wallet: str, role: str, session_version: int = 1) -> str:
    did = f"did:ethr:13371:{wallet}"
    return create_jwt(wallet, did, role, session_version, client_ip="testclient")

@pytest.mark.asyncio
async def test_qr_verification_redaction(client, db_session):
    """Users see redacted data for cross-department assets, but Auditors/Admins see everything."""
    # 1. Setup asset
    res = await db_session.execute(select(User).where(User.wallet_address == ADMIN_WALLET))
    admin_user = res.scalar_one()

    asset_serial = f"BEL-DOC-{uuid.uuid4().hex[:6].upper()}"
    new_asset = Asset(
        token_id=random.randint(1000000, 9999999),
        serial_number=asset_serial,
        name="Top Secret Specs",
        asset_type="DOCUMENT",
        file_hash="deadbeef",
        metadata_cid="secure-vault://docs/secret.pdf",
        department="Cyber",
        lifecycle_status="ACTIVE",
        is_physical=False,
        owner_id=admin_user.id
    )
    db_session.add(new_asset)
    await db_session.commit()

    # 2. Test User from different department (Avionics)
    user_token = get_token(USER_WALLET, "USER", 1) # Avionics
    res_user = await client.get(f"/api/assets/verify/{asset_serial}", headers={"Authorization": f"Bearer {user_token}"})
    assert res_user.status_code == 200
    user_data = res_user.json()
    assert user_data["name"] == "Top Secret Specs"
    assert user_data["serial_number"] == asset_serial
    # Redacted fields
    assert "file_hash" not in user_data or user_data["file_hash"] is None
    assert "metadata_cid" not in user_data or user_data["metadata_cid"] is None

    # 3. Test Admin (Sees all)
    admin_token = get_token(ADMIN_WALLET, "ADMIN", 5)
    res_admin = await client.get(f"/api/assets/verify/{asset_serial}", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_admin.status_code == 200
    admin_data = res_admin.json()
    assert admin_data["name"] == "Top Secret Specs"
    assert admin_data["file_hash"] == "deadbeef"
    assert admin_data["metadata_cid"] == "secure-vault://docs/secret.pdf"

