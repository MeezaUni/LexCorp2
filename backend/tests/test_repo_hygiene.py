"""Repository hygiene: no private keys, no public dev accounts, no tracked secrets."""

import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PUBLIC_DEV_ADDRESSES = {
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
}
KEY_RE = re.compile(r"(?i)(private[_ ]?key|secret|mnemonic|password)[\"'\s:=]+(0x)?[0-9a-f]{64}\b")
HEX64_LITERAL = re.compile(r"[\"'`]0x[0-9a-fA-F]{64}[\"'`]")


def tracked_files():
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    except Exception:
        pytest.skip("git not available")
    return [ROOT / p for p in out.splitlines()]


def test_no_secret_files_are_tracked():
    names = [p.relative_to(ROOT).as_posix() for p in tracked_files()]
    forbidden = [n for n in names if n in (".env", "backend/.env") or n.startswith("secrets/")
                 or n.startswith("network/besu/networkFiles/keys/") or n.startswith("db_backups/")
                 or n.endswith((".pem", ".key")) or n.endswith("/key")]
    assert forbidden == []


def test_no_private_key_literals_in_config_or_scripts():
    offenders = []
    for p in tracked_files():
        rel = p.relative_to(ROOT).as_posix()
        if not rel.endswith((".js", ".cjs", ".mjs", ".py", ".ps1", ".sh", ".yml", ".yaml", ".json", ".md", ".example", ".toml", ".ini")):
            continue
        if rel.startswith(("backend/tests/", "contracts/test/")) or "package-lock" in rel or rel.endswith("besu.json"):
            continue  # tests use SHA-256 document hashes; deployment record holds only public data
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if KEY_RE.search(text) or HEX64_LITERAL.search(text):
            offenders.append(rel)
    assert offenders == [], f"possible private key material in: {offenders}"


def test_hardhat_config_takes_keys_only_from_environment():
    cfg = (ROOT / "contracts" / "hardhat.config.js").read_text(encoding="utf-8")
    assert "DEPLOYER_PRIVATE_KEY" in cfg
    assert not re.search(r"0x[0-9a-fA-F]{64}", cfg)


def test_deployment_admin_and_registrar_are_not_public_dev_accounts():
    d = json.loads((ROOT / "contracts" / "deployments" / "besu.json").read_text(encoding="utf-8"))
    assert d["admin"].lower() not in PUBLIC_DEV_ADDRESSES
    assert d["registrar"].lower() not in PUBLIC_DEV_ADDRESSES
    assert d["admin"].lower() != d["registrar"].lower()
    assert d["chainId"] == 13371 and d["contractVersion"] == 3
