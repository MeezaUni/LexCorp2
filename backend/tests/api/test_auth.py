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
    subject_did = "did:ethr:31337:0x1234567890123456789012345678901234567890"
    response = await async_client.post(f"/api/auth/vc/issue?subject_did={subject_did}")
    assert response.status_code == 200
    data = response.json()
    assert "vc_jwt" in data
    # Basic JWT validation
    assert len(data["vc_jwt"].split(".")) == 3
