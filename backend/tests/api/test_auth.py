import pytest

@pytest.mark.asyncio
async def test_nonce_generation(async_client):
    wallet = "0x1234567890123456789012345678901234567890"
    response = await async_client.post(f"/api/auth/nonce?address={wallet}")
    assert response.status_code == 200
    data = response.json()
    assert "nonce" in data
    assert "message" in data
    assert wallet in data["message"]
    assert data["nonce"] in data["message"]

@pytest.mark.asyncio
async def test_vc_issue(async_client):
    """VC issuance is an admin action; it was previously reachable unauthenticated."""
    from app.services.auth import create_jwt
    admin = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
    subject_did = "did:ethr:13371:0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"

    anon = await async_client.post(f"/api/auth/vc/issue?subject_did={subject_did}")
    assert anon.status_code == 401

    user_token = create_jwt("0xe1ced2305c7c75618eeb1450e18e2099c15b7d72", subject_did, "USER", 1, client_ip="testclient")
    as_user = await async_client.post(f"/api/auth/vc/issue?subject_did={subject_did}",
                                      headers={"Authorization": f"Bearer {user_token}"})
    assert as_user.status_code == 403

    admin_token = create_jwt(admin, f"did:ethr:13371:{admin}", "ADMIN", 5, client_ip="testclient")
    response = await async_client.post(f"/api/auth/vc/issue?subject_did={subject_did}",
                                       headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    data = response.json()
    assert "vc_jwt" in data
    # Basic JWT validation
    assert len(data["vc_jwt"].split(".")) == 3
