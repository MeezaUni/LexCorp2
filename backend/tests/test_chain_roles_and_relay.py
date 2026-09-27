"""On-chain role lifecycle (via the chain-operator transport) and the browser RPC relay."""

import uuid
from unittest.mock import patch

import httpx
import pytest
from eth_account import Account
from sqlalchemy import select

from app.models.domain import AuditEvent, User
from app.services.auth import create_jwt
from app.services.chain import desired_roles
from tests.conftest import step_up_header

ADMIN = "0x95ea9708bcf136d710a4b8e76fe20f895eca003a"
USER = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"
CONTRACT = "0x" + "11" * 20  # tests/.test_deployment.json


def h(wallet, role, version):
    return {"Authorization": f"Bearer {create_jwt(wallet, f'did:ethr:13371:{wallet}', role, version, client_ip='127.0.0.1')}"}


ADMIN_H = lambda: h(ADMIN, "ADMIN", 5)  # noqa: E731


def test_role_mapping():
    assert desired_roles("ADMIN", True) == {"MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE"}
    assert desired_roles("MANAGER", True) == {"MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE"}
    assert desired_roles("AUDITOR", True) == {"AUDITOR_ROLE"}
    assert desired_roles("USER", True) == set()
    assert desired_roles("MANAGER", False) == set()


@pytest.mark.asyncio
async def test_identity_lifecycle_drives_onchain_roles(client, db_session, fake_chain_roles):
    acct = Account.create()
    w = acct.address.lower()
    r = await client.post("/api/users", headers={**ADMIN_H(), **(await step_up_header(ADMIN, "identity.provision"))},
                          json={"wallet_address": acct.address, "role": "MANAGER", "department": "Avionics", "name": "Chain Mgr"})
    assert r.status_code == 200, r.text
    assert r.json()["chain_roles"]["ok"] is True
    assert fake_chain_roles[w] == {"MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE"}
    user = (await db_session.execute(select(User).where(User.wallet_address == w))).scalar_one()

    # Demotion requires Factor 3, is audited, ends sessions, and removes mint rights on-chain.
    r = await client.patch(f"/api/users/{user.id}/role", headers=ADMIN_H(), json={"role": "USER"})
    assert r.status_code == 401
    assert fake_chain_roles[w] == {"MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE"}
    r = await client.patch(f"/api/users/{user.id}/role", headers={**ADMIN_H(), **(await step_up_header(ADMIN, "identity.role"))},
                           json={"role": "USER"})
    assert r.status_code == 200, r.text
    assert fake_chain_roles[w] == set()
    await db_session.refresh(user)
    assert user.session_version == 1
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "ROLE_CHANGED",
                                                            AuditEvent.target_did == user.did))).scalar_one()
    assert {k: ev.risk_factors[k] for k in ("from", "to")} == {"from": "MANAGER", "to": "USER"}
    assert ev.risk_label == "MEDIUM"      # a role change: baseline level from the event type


@pytest.mark.asyncio
async def test_revocation_removes_onchain_roles(client, db_session, fake_chain_roles):
    acct = Account.create()
    w = acct.address.lower()
    await client.post("/api/users", headers={**ADMIN_H(), **(await step_up_header(ADMIN, "identity.provision"))},
                      json={"wallet_address": acct.address, "role": "AUDITOR", "department": "Cyber", "name": "Chain Aud"})
    assert fake_chain_roles[w] == {"AUDITOR_ROLE"}
    user = (await db_session.execute(select(User).where(User.wallet_address == w))).scalar_one()
    r = await client.delete(f"/api/users/{user.id}", headers={**ADMIN_H(), **(await step_up_header(ADMIN, "identity.revoke"))})
    assert r.status_code == 204
    assert fake_chain_roles[w] == set()


@pytest.mark.asyncio
async def test_admin_cannot_change_own_role(client, db_session):
    admin = (await db_session.execute(select(User).where(User.wallet_address == ADMIN))).scalar_one()
    r = await client.patch(f"/api/users/{admin.id}/role", headers={**ADMIN_H(), **(await step_up_header(ADMIN, "identity.role"))},
                           json={"role": "USER"})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_role_sync_failure_is_audited_high_and_does_not_lose_pin(client, db_session):
    class Down:
        def __init__(self):
            from app.services.chain import ChainUnavailable
            raise ChainUnavailable("node down")
    acct = Account.create()
    with patch("app.services.chain.RoleSync", Down):
        r = await client.post("/api/users", headers={**ADMIN_H(), **(await step_up_header(ADMIN, "identity.provision"))},
                              json={"wallet_address": acct.address, "role": "MANAGER", "department": "Avionics"})
    assert r.status_code == 200 and r.json()["one_time_pin"] and r.json()["chain_roles"]["ok"] is False
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "CHAIN_ROLE_SYNC_FAILED")
                                   .order_by(AuditEvent.created_at.desc()))).scalars().first()
    assert ev.risk_label == "HIGH"
    from app.models.domain import SecurityAlert
    alert = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.source_event_id == ev.id))).scalar_one()
    alert.state = "DISMISSED"  # keep later alert tests independent
    await db_session.commit()


# ------------------------------------------------------------------ RPC relay

def signed_tx(acct, to, chain_id=13371):
    tx = {"to": to, "value": 0, "gas": 100000, "gasPrice": 0, "nonce": 0, "chainId": chain_id, "data": "0x"}
    return "0x" + acct.sign_transaction(tx).raw_transaction.hex().removeprefix("0x")


async def _onboard(db, wallet):
    u = (await db.execute(select(User).where(User.wallet_address == wallet))).scalar_one()
    return u


@pytest.mark.asyncio
async def test_relay_requires_session(client):
    r = await client.post("/api/chain/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_relay_blocks_admin_debug_methods_and_batches(client):
    for method in ("admin_peers", "debug_traceTransaction", "personal_unlockAccount", "txpool_content", "eth_accounts"):
        r = await client.post("/api/chain/rpc", headers=ADMIN_H(), json={"jsonrpc": "2.0", "id": 1, "method": method, "params": []})
        assert r.status_code == 403, method
    r = await client.post("/api/chain/rpc", headers=ADMIN_H(), json=[{"jsonrpc": "2.0", "id": 1, "method": "eth_chainId"}])
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_relay_forwards_allowed_reads(client):
    class Resp:
        def json(self):
            return {"jsonrpc": "2.0", "id": 1, "result": "0x343b"}

    class FakeClient:
        def __init__(self, *a, **k):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def post(self, url, json):
            assert json["method"] == "eth_chainId"
            return Resp()

    with patch("app.api.chain.httpx.AsyncClient", FakeClient):
        r = await client.post("/api/chain/rpc", headers=ADMIN_H(), json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []})
    assert r.status_code == 200 and r.json()["result"] == "0x343b"


@pytest.mark.asyncio
async def test_relay_rejects_transactions_not_signed_by_session_wallet(client, db_session):
    stranger = Account.create()
    r = await client.post("/api/chain/rpc", headers=ADMIN_H(),
                          json={"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": [signed_tx(stranger, CONTRACT)]})
    assert r.status_code == 403
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "CHAIN_RELAY_REJECTED")
                                   .order_by(AuditEvent.created_at.desc()))).scalars().first()
    assert ev is not None and ev.risk_label == "HIGH"
    from app.models.domain import SecurityAlert
    alert = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.source_event_id == ev.id))).scalar_one()
    alert.state = "DISMISSED"
    await db_session.commit()


@pytest.mark.asyncio
async def test_relay_rejects_transactions_to_other_contracts(client, db_session):
    acct = Account.create()
    u = User(wallet_address=acct.address.lower(), did=f"did:ethr:13371:{acct.address.lower()}", role="USER",
             is_active=True, onboarding_pending=False, is_totp_enabled=True, department="Avionics")
    db_session.add(u)
    await db_session.commit()
    hh = h(acct.address.lower(), "USER", 0)
    for to in ("0x" + "44" * 20, None):
        tx = {"value": 0, "gas": 100000, "gasPrice": 0, "nonce": 0, "chainId": 13371, "data": "0x6080"}
        if to:
            tx["to"] = to
        raw = "0x" + acct.sign_transaction(tx).raw_transaction.hex().removeprefix("0x")
        r = await client.post("/api/chain/rpc", headers=hh,
                              json={"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": [raw]})
        assert r.status_code == 403, to


@pytest.mark.asyncio
async def test_reconciler_revokes_roles_of_unregistered_wallets(db_session, fake_chain_roles):
    """A wallet holding an operational role on-chain but unknown to LexCorp2 (e.g. an
    identity removed by a database rebuild) loses that role; registered ones converge."""
    from app.services.chain import reconcile_all
    orphan = "0x" + uuid.uuid4().hex + uuid.uuid4().hex[:8]
    fake_chain_roles[orphan] = {"MINTER_ROLE", "MANAGER_ROLE"}
    fake_chain_roles[USER] = {"MINTER_ROLE"}  # registered USER wrongly holding a role
    result = await reconcile_all(db_session)
    assert result["unregistered_revoked"] == 1
    assert fake_chain_roles[orphan] == set()
    assert fake_chain_roles[USER] == set()
    assert fake_chain_roles[ADMIN] == {"MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE"}
    ev = (await db_session.execute(select(AuditEvent).where(AuditEvent.event_type == "CHAIN_ROLES_REVOKED_UNREGISTERED")
                                   .order_by(AuditEvent.created_at.desc()))).scalars().first()
    assert ev.target_did.endswith(orphan) and ev.risk_label == "HIGH"
    from app.models.domain import SecurityAlert
    for a in (await db_session.execute(select(SecurityAlert).where(SecurityAlert.state == "AUDITOR_REVIEW"))).scalars().all():
        a.state = "DISMISSED"
    await db_session.commit()
