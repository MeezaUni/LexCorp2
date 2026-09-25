import io
import pytest
from tests.conftest import mfa_headers
import uuid
import os
import pyotp
from datetime import datetime, timedelta
from unittest.mock import patch
from app.services.auth import create_jwt
from app.models.domain import User, Asset, DocumentAction
from sqlalchemy import select

ADMIN_WALLET = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a".lower()
MANAGER_WALLET = "0x049dd1327d3bf40ab2dd8d70086304770e841fca".lower()
USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72".lower()

def get_token(wallet: str, role: str, session_version: int = 1) -> str:
    did = f"did:ethr:13371:{wallet}"
    return create_jwt(wallet, did, role, session_version, client_ip="testclient")

@pytest.mark.asyncio
async def test_download_workflow_success(client, db_session):
    """Request (Factor 2) -> Manager approval (Factor 3) -> requester fetch (Factor 3):
    single-use, watermarked with the Download ID; approvers cannot fetch it."""
    from tests import flows
    from pypdf import PdfReader
    serial = await flows.approved_document(client, db_session, b"sensitive content", "report.txt")
    dl = await flows.request_download(client, db_session, serial)
    assert dl.startswith("DL-")

    early = await flows.fetch(client, db_session, dl)
    assert early.status_code == 403  # not approved yet

    appr = await flows.approve(client, db_session, dl)
    assert appr.status_code == 200 and appr.json()["download_token"] is None  # no bearer token handed out

    # The approving manager cannot fetch someone else's download
    mgr_try = await flows.fetch(client, db_session, dl, requester=flows.MANAGER)
    assert mgr_try.status_code == 404
    # Fetch without Factor 3 is refused
    no_f3 = await client.post(f"/api/assets/document/download/{dl}/fetch",
                              headers={"Authorization": f"Bearer {flows.token_for(flows.USER)}"}, json={})
    assert no_f3.status_code == 401

    got = await flows.fetch(client, db_session, dl)
    assert got.status_code == 200, got.text
    assert got.headers["content-type"] == "application/pdf"
    text = "".join(page.extract_text() for page in PdfReader(io.BytesIO(got.content)).pages)
    assert "sensitive content" in text
    assert f"Download ID: {dl}" in text and "Downloaded by:" in text

    again = await flows.fetch(client, db_session, dl)
    assert again.status_code == 409  # single use


