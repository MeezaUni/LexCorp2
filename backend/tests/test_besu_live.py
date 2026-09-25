"""LIVE integration against the running Besu network (opt-in: LEXCORP_LIVE_BESU=1).

No mocks: real signed transactions, real receipts, real contract state.
* The DEPLOYED contract (contracts/deployments/besu.json) is checked read-only, and an
  unauthorized wallet's mint transaction is sent to it and must fail on-chain.
* Authorized-vs-revoked minting is exercised on a THROWAWAY instance of the same
  compiled contract deployed to the same Besu network with throwaway keys, so the
  application's registry and alert queue are not polluted by test tokens.
"""

import json
import os
import secrets
from pathlib import Path

import pytest
from eth_account import Account
from web3 import Web3

pytestmark = pytest.mark.skipif(os.environ.get("LEXCORP_LIVE_BESU") != "1", reason="set LEXCORP_LIVE_BESU=1 to run live Besu tests")

ROOT = Path(__file__).resolve().parents[2]
RPC = os.environ.get("LEXCORP_RPC_URL", "http://127.0.0.1:8545")
PUBLIC_HARDHAT_0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


@pytest.fixture(scope="module")
def w3():
    w = Web3(Web3.HTTPProvider(RPC))
    assert w.eth.chain_id == 13371
    return w


@pytest.fixture(scope="module")
def deployment():
    return json.loads((ROOT / "contracts" / "deployments" / "besu.json").read_text(encoding="utf-8"))


def send(w3, acct, tx):
    tx = {**tx, "from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address), "gasPrice": 0, "chainId": 13371}
    tx.setdefault("gas", 3_000_000)
    signed = acct.sign_transaction(tx)
    return w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed.raw_transaction), timeout=60)


def test_deployed_contract_integrity(w3, deployment):
    code = w3.eth.get_code(Web3.to_checksum_address(deployment["address"]))
    assert len(code) > 0
    assert Web3.keccak(code).hex().removeprefix("0x") == deployment["runtimeBytecodeKeccak"].removeprefix("0x")
    c = w3.eth.contract(address=deployment["address"], abi=deployment["abi"])
    assert c.functions.hasRole(b"\x00" * 32, deployment["admin"]).call()
    assert c.functions.hasRole(c.functions.REGISTRAR_ROLE().call(), deployment["registrar"]).call()
    for role in ("DEFAULT_ADMIN_ROLE", "REGISTRAR_ROLE", "MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE", "AUDITOR_ROLE"):
        rid = b"\x00" * 32 if role == "DEFAULT_ADMIN_ROLE" else getattr(c.functions, role)().call()
        assert not c.functions.hasRole(rid, PUBLIC_HARDHAT_0).call(), f"public Hardhat #0 holds {role}"
    genesis = json.loads((ROOT / "network" / "besu" / "networkFiles" / "genesis.json").read_text(encoding="utf-8"))
    assert genesis["alloc"] == {}  # no pre-funded (let alone publicly known) account


def test_unauthorized_mint_rejected_by_deployed_contract(w3, deployment):
    c = w3.eth.contract(address=deployment["address"], abi=deployment["abi"])
    stranger = Account.create()
    token_id = int.from_bytes(secrets.token_bytes(6), "big") + 10**12
    fn = c.functions.mintDigitalAsset(stranger.address, token_id, f"ROGUE-{token_id}", "did:x", "ab" * 32, "u")
    with pytest.raises(Exception, match="AccessControl|revert"):
        fn.call({"from": stranger.address})
    rcpt = send(w3, stranger, {"to": deployment["address"], "data": fn._encode_transaction_data()})
    assert rcpt.status == 0  # mined, and rejected BY THE CONTRACT
    assert c.functions.getTokenBySerial(f"ROGUE-{token_id}").call() == 0
    # the same for physical mint and revision anchoring
    for f in (c.functions.mint(stranger.address, token_id, f"ROGUE-P-{token_id}", "did:x"),
              c.functions.updateDigitalAsset(token_id, "cd" * 32, "u")):
        assert send(w3, stranger, {"to": deployment["address"], "data": f._encode_transaction_data()}).status == 0


def test_authorized_mint_succeeds_and_revoked_minter_is_rejected(w3):
    art = json.loads((ROOT / "contracts" / "artifacts" / "contracts" / "AssetNFT.sol" / "AssetNFT.json").read_text(encoding="utf-8"))
    admin, registrar, minter, holder = (Account.create() for _ in range(4))
    factory = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
    rcpt = send(w3, admin, {"data": factory.constructor(admin.address, registrar.address).data_in_transaction, "gas": 6_000_000})
    assert rcpt.status == 1
    c = w3.eth.contract(address=rcpt.contractAddress, abi=art["abi"])
    MINTER = c.functions.MINTER_ROLE().call()
    assert send(w3, registrar, {"to": c.address, "data": c.functions.grantRole(MINTER, minter.address)._encode_transaction_data()}).status == 1

    mint = c.functions.mintDigitalAsset(holder.address, 101, "LIVE-DOC-101", f"did:ethr:13371:{holder.address.lower()}", "ab" * 32, "vault://101")
    r = send(w3, minter, {"to": c.address, "data": mint._encode_transaction_data()})
    assert r.status == 1
    assert c.functions.ownerOf(101).call() == holder.address
    assert c.functions.getDigitalAsset(101).call()[2] == "ab" * 32
    assert len(c.events.DigitalAssetMinted().process_receipt(r)) == 1

    # the holder cannot move the token or anchor a new hash
    assert send(w3, holder, {"to": c.address, "data": c.functions.transferFrom(holder.address, minter.address, 101)._encode_transaction_data()}).status == 0
    assert send(w3, holder, {"to": c.address, "data": c.functions.updateDigitalAsset(101, "cd" * 32, "x")._encode_transaction_data()}).status == 0

    # revoke -> the same wallet is rejected on-chain
    assert send(w3, registrar, {"to": c.address, "data": c.functions.revokeRole(MINTER, minter.address)._encode_transaction_data()}).status == 1
    again = c.functions.mintDigitalAsset(holder.address, 102, "LIVE-DOC-102", "did:x", "ab" * 32, "u")
    assert send(w3, minter, {"to": c.address, "data": again._encode_transaction_data()}).status == 0
