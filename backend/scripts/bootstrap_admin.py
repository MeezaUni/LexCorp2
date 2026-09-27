"""Bootstrap the FIRST LexCorp administrator (and the initial department list).

Administrators cannot create administrators through the API, so the first one is
created here, out-of-band, by whoever operates the server:

    cd backend
    python scripts/bootstrap_admin.py --name "Security Administrator" --department "Cyber Security"
    python scripts/bootstrap_admin.py ... --wallet-address 0xYourOwnWallet     # preferred

Output files (git-ignored, readable only by the operator; nothing secret is printed):
    secrets/bootstrap_admin_pin.txt       single-use provisioning PIN (valid 3 hours)
    secrets/bootstrap_admin_wallet.json   ONLY if no --wallet-address was given: the
                                          generated wallet's private key + recovery phrase
The administrator then opens the web app -> "Provision wallet" and imports the wallet
with the PIN, then must set up Login TOTP 1 and Login Passkey 1 before anything else.
Refuses to run when an active ADMIN already exists (use the Admin UI instead).
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eth_account import Account  # noqa: E402
from sqlalchemy import select  # noqa: E402
from web3 import Web3  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.crypto import hash_pin  # noqa: E402
from app.core.database import async_session_factory  # noqa: E402
from app.models.domain import AuditEvent, Department, User  # noqa: E402
from app.services.security import generate_one_time_pin  # noqa: E402

SECRETS = Path(__file__).resolve().parents[2] / "secrets"
DEFAULT_DEPARTMENTS = ["Cyber Security", "Avionics", "Radar Systems", "Manufacturing", "Quality Assurance"]


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name")
    ap.add_argument("--department")
    ap.add_argument("--wallet-address")
    ap.add_argument("--departments", default=",".join(DEFAULT_DEPARTMENTS),
                    help="comma-separated initial departments (existing ones are kept)")
    ap.add_argument("--reissue-pin", action="store_true",
                    help="issue a new PIN for the bootstrap admin if it has NOT completed provisioning yet")
    ap.add_argument("--reset-login", action="store_true",
                    help="reset an administrator's login factors (for the only administrator, who has no one to approve it); "
                         "with several administrators, name one with --wallet-address")
    a = ap.parse_args()

    if a.reset_login:
        return await reset_admin_login(a.wallet_address)

    if a.reissue_pin:
        async with async_session_factory() as db:
            admins = (await db.execute(select(User).where(User.role == "ADMIN"))).scalars().all()
            # Still setting up: either the PIN was never used, or it was used but the login
            # authenticator and passkey were never completed (the setup session ended first).
            pending = [u for u in admins if u.onboarding_pending and u.is_active]
            if len(admins) != 1 or len(pending) != 1:
                print("Re-issue is only possible while the single bootstrap admin has not finished setting up. "
                      "For an administrator who has finished, use --reset-login.")
                return 2
            u = pending[0]
            pin = generate_one_time_pin(12)
            u.pin_hash = hash_pin(pin)
            u.pin_used = False
            u.pin_expires_at = datetime.now(UTC) + timedelta(hours=settings.PROVISIONING_PIN_TTL_HOURS)
            import hashlib, time
            db.add(AuditEvent(event_type="PROVISIONING_PIN_REISSUED", block_number=0,
                              tx_hash="0x" + hashlib.sha256(f"reissue:{time.time_ns()}".encode()).hexdigest(),
                              actor_did="system:bootstrap", target_did=u.did, risk_factors={"bootstrap": True}))
            await db.commit()
        SECRETS.mkdir(exist_ok=True)
        (SECRETS / "bootstrap_admin_pin.txt").write_text(
            f"LexCorp bootstrap administrator\nwallet: {u.wallet_address}\nprovisioning PIN (single use, expires "
            f"{u.pin_expires_at.isoformat()}): {pin}\n", encoding="utf-8")
        print(f"New PIN written to {SECRETS / 'bootstrap_admin_pin.txt'} (not shown); the previous PIN no longer works.")
        return 0

    if not a.name or not a.department:
        ap.error("--name and --department are required")
    SECRETS.mkdir(exist_ok=True)
    generated = None
    if a.wallet_address:
        address = Web3.to_checksum_address(a.wallet_address)
    else:
        Account.enable_unaudited_hdwallet_features()
        acct, mnemonic = Account.create_with_mnemonic()
        address, generated = acct.address, {"address": acct.address, "private_key": acct.key.hex(), "recovery_phrase": mnemonic}

    async with async_session_factory() as db:
        existing = (await db.execute(select(User).where(User.role == "ADMIN", User.is_active.is_(True)))).scalars().first()
        if existing:
            print("An active ADMIN already exists; create further identities from the Admin UI.")
            return 2
        if (await db.execute(select(User).where(User.wallet_address == address.lower()))).scalar_one_or_none():
            print("That wallet is already registered.")
            return 2

        names = [d.strip() for d in a.departments.split(",") if d.strip()]
        if a.department not in names:
            names.append(a.department)
        have = {d.name for d in (await db.execute(select(Department))).scalars().all()}
        for n in names:
            if n not in have:
                db.add(Department(name=n, is_active=True))

        pin = generate_one_time_pin(12)
        did = f"did:ethr:{settings.CHAIN_ID}:{address.lower()}"
        admin = User(wallet_address=address.lower(), did=did, name=a.name, department=a.department, role="ADMIN",
                     is_active=True, onboarding_pending=True, pin_hash=hash_pin(pin),
                     pin_expires_at=datetime.now(UTC) + timedelta(hours=settings.PROVISIONING_PIN_TTL_HOURS), pin_used=False)
        db.add(admin)
        import hashlib, time
        db.add(AuditEvent(event_type="USER_PROVISIONED", block_number=0,
                          tx_hash="0x" + hashlib.sha256(f"bootstrap:{time.time_ns()}".encode()).hexdigest(),
                          actor_did="system:bootstrap", target_did=did,
                          risk_factors={"role": "ADMIN", "department": a.department, "bootstrap": True}))
        await db.commit()
        await db.refresh(admin)

        (SECRETS / "bootstrap_admin_pin.txt").write_text(
            f"LexCorp bootstrap administrator\nwallet: {address}\nprovisioning PIN (single use, expires "
            f"{admin.pin_expires_at.isoformat()}): {pin}\n", encoding="utf-8")
        if generated:
            (SECRETS / "bootstrap_admin_wallet.json").write_text(json.dumps(generated, indent=2), encoding="utf-8")

        from app.services.chain import sync_user_chain_roles
        chain = await sync_user_chain_roles(db, admin, actor_did="system:bootstrap")

    print(f"Administrator provisioned: {address} ({did})")
    print(f"Departments: {', '.join(names)}")
    print(f"One-time PIN written to {SECRETS / 'bootstrap_admin_pin.txt'} (not shown)")
    if generated:
        print(f"Generated wallet written to {SECRETS / 'bootstrap_admin_wallet.json'} (not shown) - move it to the admin securely")
    print(f"On-chain roles: {'granted ' + ', '.join(chain.get('roles', [])) if chain.get('ok') else 'FAILED - see audit log; reconciler will retry'}")
    return 0


async def reset_admin_login(wallet_address) -> int:
    """Out-of-band reset for an administrator, run by whoever operates the server. Same effect
    as an approved reset in the app: login factors and sessions end, and a new single-use PIN is
    written to secrets/bootstrap_admin_pin.txt. The administrator keeps their wallet and
    provisions again with their recovery phrase and the new PIN."""
    from app.services import mfa
    async with async_session_factory() as db:
        admins = (await db.execute(select(User).where(User.role == "ADMIN", User.is_active.is_(True)))).scalars().all()
        if wallet_address:
            target = next((u for u in admins if u.wallet_address == Web3.to_checksum_address(wallet_address).lower()), None)
            if target is None:
                print("No active administrator has that wallet address.")
                return 2
        elif len(admins) == 1:
            target = admins[0]
        else:
            print("There are several administrators: another administrator can approve the reset in the app, "
                  "or name the one to reset with --wallet-address.")
            return 2
        pin, expires_at = await mfa.reset_login_factors(db, target)
        import hashlib, time
        db.add(AuditEvent(event_type="ADMIN_LOGIN_RESET_BY_OPERATOR", block_number=0,
                          tx_hash="0x" + hashlib.sha256(f"operator-reset:{time.time_ns()}".encode()).hexdigest(),
                          actor_did="system:operator", target_did=target.did,
                          risk_factors={"invalidated": ["login_totp", "login_passkeys", "sessions", "wallet_keystore"]}))
        await db.commit()
    SECRETS.mkdir(exist_ok=True)
    (SECRETS / "bootstrap_admin_pin.txt").write_text(
        "LexCorp administrator login reset\n"
        f"wallet: {target.wallet_address}\n"
        f"provisioning PIN (single use, expires {expires_at.isoformat()}): {pin}\n",
        encoding="utf-8")
    print(f"Login factors reset for {target.wallet_address}. New PIN written to {SECRETS / 'bootstrap_admin_pin.txt'} (not shown).")
    print("The administrator signs in with First-time provisioning (recovery phrase + this PIN) and sets up new login factors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
