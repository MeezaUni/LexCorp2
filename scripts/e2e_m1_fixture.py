"""DEVELOPMENT-ONLY fixture for the M1 browser test (e2e/playwright/13_m1_ai_alert.mjs).

    python scripts/e2e_m1_fixture.py seed --emit-secrets   (used by the runner; prints secrets as JSON)
    python scripts/e2e_m1_fixture.py cleanup               (retires the people and removes the documents)

Checklist test M1 needs established people: the risk model judges each action against the
person's own last 30 days, so a brand-new identity looks unusual. Provisioning people through
the Admin UI would also need the Admin's own authenticator, so this fixture writes them straight
into the development database instead, all labelled "E2E-M1":

  * E2E-M1 Ordinary User and E2E-M1 Burst User (USER, E2E-M1 Engineering; names end in the run's
    date and time), each with three weeks of ordinary weekday history in the audit trail: a
    sign-in and a few views of familiar documents during working hours;
  * E2E-M1 Auditor (AUDITOR), E2E-M1 Document Owner (owns the Finance documents; never signs in);
  * 4 Engineering documents and 12 Finance documents (small PDFs in the vault), with view grants
    so the Burst User can open all 12 Finance documents it has never touched.

Each person who signs in gets a login authenticator secret and a login passkey (P-256), with
Factor 2 set to reuse the login factors. The secrets and the passkey private keys are printed
once as JSON for the runner, which keeps them in memory; nothing is written to disk. Refuses
to run unless backend/.env says ENVIRONMENT=development. Seeding first retires any earlier
E2E-M1 people, so it can be run again.

The audit trail is append-only (migration 0011): the seeded history (about 150 events per run,
tagged {"seed": "E2E-M1"}), the run's own actions and its alert stay after cleanup, attributed
to the retired, clearly named test identities. ml/export_feedback.py skips alerts about them, so
test decisions never become training labels. Section S2 of backend/Final_Manual_Test_Checklist.md
resets the database completely.
"""

import asyncio
import base64
import hashlib
import json
import os
import random
import secrets
import sys
from datetime import datetime, timedelta, UTC
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
os.chdir(BACKEND)
sys.path.insert(0, str(BACKEND))

TAG = "E2E-M1"
ENG, FIN, ASSURANCE = f"{TAG} Engineering", f"{TAG} Finance", f"{TAG} Assurance"
TOKEN_BASE = 2_000_000_000
IP = "127.0.0.1"                      # the browser run comes from this machine, like the history
HISTORY_DAYS = 21


def env_value(name):
    for line in (BACKEND / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip()
    return None


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def new_passkey():
    """A P-256 passkey: (credential id, COSE public key, PKCS#8 private key)."""
    import cbor2
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
    pkcs8 = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return secrets.token_bytes(32), cose, pkcs8


async def cleanup(db):
    """Retire every active E2E-M1 person. audit_events and security_alert_actions are append-only
    for every database role (migration 0011), so the audit trail, including the seeded history,
    and the alerts stay. Open alerts about the people are dismissed (one appended action each),
    the people are revoked with their secrets and passkeys removed, and the documents, their
    vault files, grants and document actions are deleted."""
    from sqlalchemy import delete, select
    from app.models.domain import (AssetAccessGrant, Asset, AuthChallenge, Department, DocumentAction,
                                   SecurityAlert, SecurityAlertAction, StepUpGrant, User, WebAuthnCredential)
    users = (await db.execute(select(User).where(User.name.like(f"{TAG} %"), User.revoked_at.is_(None)))).scalars().all()
    ids, dids = [u.id for u in users], [u.did for u in users]
    open_alerts = (await db.execute(select(SecurityAlert).where(
        SecurityAlert.subject_did.in_(dids), SecurityAlert.state.in_(["AUDITOR_REVIEW", "MANAGER_REVIEW", "ADMIN_REVIEW"])))).scalars().all()
    for a in open_alerts:
        db.add(SecurityAlertAction(alert_id=a.id, action="DISMISSED", from_state=a.state, to_state="DISMISSED",
                                   note=f"Closed by scripts/e2e_m1_fixture.py cleanup: automated test fixture ({TAG})."))
        a.state = "DISMISSED"
    assets = (await db.execute(select(Asset).where(Asset.serial_number.like(f"{TAG}-%")))).scalars().all()
    await db.execute(delete(AssetAccessGrant).where(AssetAccessGrant.asset_serial.like(f"{TAG}-%")))
    await db.execute(delete(DocumentAction).where(DocumentAction.asset_serial.like(f"{TAG}-%")))
    for model in (StepUpGrant, AuthChallenge, WebAuthnCredential):
        await db.execute(delete(model).where(model.user_id.in_(ids)))
    for a in assets:
        path = Path(_vault()) / a.metadata_cid.replace("secure-vault://", "")
        if path.is_file():
            path.unlink()
    await db.execute(delete(Asset).where(Asset.serial_number.like(f"{TAG}-%")))
    now = datetime.now(UTC)
    for u in users:
        u.is_active, u.revoked_at, u.revocation_reason = False, now, f"Automated test fixture ({TAG}) retired after the run."
        u.totp_secret, u.is_totp_enabled, u.session_version = None, False, (u.session_version or 0) + 1
    await db.execute(delete(Department).where(Department.name.like(f"{TAG} %")))
    await db.commit()
    return len(users), len(assets), len(open_alerts)


def _vault():
    from app.core.config import settings
    return settings.OFFCHAIN_STORAGE_DIR


def _local_to_utc(day, hour, minute):
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(os.environ.get("RISK_TIMEZONE", "Asia/Kolkata"))
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=tz).astimezone(UTC)


async def seed(db):
    from app.core.config import settings
    from app.core.crypto import encrypt_secret
    from app.models.domain import AssetAccessGrant, Asset, AuditEvent, Department, User, WebAuthnCredential
    from app.services.watermark import text_to_pdf
    import pyotp

    rng = random.Random()
    now = datetime.now(UTC)
    for name in (ENG, FIN, ASSURANCE):
        db.add(Department(name=name))

    out, people = {}, {}
    run = now.strftime("%m%d-%H%M")         # each run's people are distinct from earlier, retired ones
    for key, name, role, dept, signs_in in (
        ("ordinary", f"{TAG} Ordinary User {run}", "USER", ENG, True),
        ("burst", f"{TAG} Burst User {run}", "USER", ENG, True),
        ("auditor", f"{TAG} Auditor {run}", "AUDITOR", ASSURANCE, True),
        ("owner", f"{TAG} Document Owner {run}", "USER", FIN, False),
    ):
        wallet = "0x" + secrets.token_hex(20)
        user = User(wallet_address=wallet, name=name, organization="LexCorp", department=dept, role=role,
                    did=f"did:ethr:{settings.CHAIN_ID}:{wallet}", is_active=True, onboarding_pending=False, pin_used=True,
                    created_at=now - timedelta(days=HISTORY_DAYS + 9))
        if signs_in:
            secret = pyotp.random_base32()
            user.totp_secret, user.is_totp_enabled = encrypt_secret(secret), True
            user.factor2_uses_login = user.factor3_uses_login = True
            cred_id, cose, pkcs8 = new_passkey()
            user.webauthn_credentials.append(WebAuthnCredential(credential_id=cred_id.hex(), public_key=cose.hex(), sign_count=0,
                                                                device_name=f"{TAG} virtual passkey", factor_scope="login"))
            out[key] = {"name": name, "address": wallet, "totp": secret,
                        "passkey": {"credentialId": b64(cred_id), "privateKey": b64(pkcs8)}}
        db.add(user)
        people[key] = user
    await db.flush()

    vault = Path(settings.OFFCHAIN_STORAGE_DIR)
    vault.mkdir(parents=True, exist_ok=True)
    docs = {}

    def document(serial, title, owner, dept, n):
        pdf = text_to_pdf(f"{title}\n\nTest document created by scripts/e2e_m1_fixture.py for checklist test M1.".encode(), title)
        sha = hashlib.sha256(pdf).hexdigest()
        fname = f"{sha}_{serial}.pdf"
        (vault / fname).write_bytes(pdf)
        a = Asset(token_id=TOKEN_BASE + n, serial_number=serial, name=title, asset_type="DOCUMENT", metadata_cid=f"secure-vault://{fname}",
                  file_hash=sha, owner_id=owner.id, custodian_id=owner.id, custodian_did=owner.did, custodian_department=dept,
                  lifecycle_status="ACTIVE", approval_status="ACTIVE", department=dept, is_physical=False,
                  created_at=now - timedelta(days=HISTORY_DAYS + 7))
        db.add(a)
        docs[serial] = a
        return a

    n = 0
    for owner, titles in (("ordinary", ("Flight control interface spec", "Test bench wiring notes")),
                          ("burst", ("Sensor calibration procedure", "Firmware release checklist"))):
        for t in titles:
            n += 1
            document(f"{TAG}-ENG-{n:02d}", t, people[owner], ENG, n)
    fin_titles = ("Quarterly budget", "Supplier contracts", "Payroll summary", "Audit findings", "Cost forecast", "Pricing model",
                  "Bank reconciliation", "Tax filing notes", "Capital plan", "Invoice register", "Expense policy", "Board finance pack")
    for i, t in enumerate(fin_titles, 1):
        document(f"{TAG}-FIN-{i:02d}", t, people["owner"], FIN, 100 + i)
    await db.flush()

    def grant(serial, grantee, granted_by):
        db.add(AssetAccessGrant(asset_id=docs[serial].id, asset_serial=serial, grantee_did=grantee.did, granted_by_did=granted_by.did,
                                can_view=True, can_download=False, max_views=None, is_active=True,
                                created_at=now - timedelta(days=HISTORY_DAYS + 5)))

    # colleagues in Engineering read each other's documents; the Burst User may also view all of Finance
    grant(f"{TAG}-ENG-03", people["ordinary"], people["burst"])
    grant(f"{TAG}-ENG-01", people["burst"], people["ordinary"])
    for i in range(1, len(fin_titles) + 1):
        grant(f"{TAG}-FIN-{i:02d}", people["burst"], people["owner"])

    # three weeks of ordinary weekday work: sign in around 09:30-10:30, then 2-4 views of familiar
    # documents spread over working hours, always from this machine
    usual = {"ordinary": [f"{TAG}-ENG-01", f"{TAG}-ENG-02", f"{TAG}-ENG-03"],
             "burst": [f"{TAG}-ENG-01", f"{TAG}-ENG-03", f"{TAG}-ENG-04"],
             "auditor": []}
    today = now.date()
    events = 0
    for key, serials in usual.items():
        person = people[key]
        for d in range(HISTORY_DAYS, 0, -1):
            day = today - timedelta(days=d)
            if day.weekday() >= 5:
                continue
            t = _local_to_utc(day, 9, 30) + timedelta(minutes=rng.randint(0, 60))
            day_events = [("AuthenticationSucceeded", None, t)]
            for _ in range(rng.randint(2, 4) if serials else 0):
                day_events.append(("DOCUMENT_VIEWED", rng.choice(serials), _local_to_utc(day, 10, 0) + timedelta(minutes=rng.randint(0, 420))))
            for etype, serial, ts in day_events:
                db.add(AuditEvent(event_type=etype, tx_hash="0x" + hashlib.sha256(f"{TAG}:{person.did}:{ts.isoformat()}:{serial}".encode()).hexdigest(),
                                  block_number=0, actor_did=person.did, asset_serial=serial, client_ip=IP, risk_label="LOW", risk_score=0.0,
                                  risk_factors={"seed": TAG, "note": "ordinary history created by scripts/e2e_m1_fixture.py"},
                                  created_at=ts))
                events += 1
    await db.commit()
    out["documents"] = {"engineering": [s for s in docs if "-ENG-" in s], "finance": [s for s in docs if "-FIN-" in s]}
    out["history_events"] = events
    return out


async def main():
    if env_value("ENVIRONMENT") != "development":
        sys.exit("Refusing to run: backend/.env must say ENVIRONMENT=development.")
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd not in ("seed", "cleanup") or (cmd == "seed" and "--emit-secrets" not in sys.argv):
        sys.exit(__doc__)
    from app.core.database import async_session_factory
    async with async_session_factory() as db:
        users, assets, alerts = await cleanup(db)
        if cmd == "cleanup":
            print(f"Retired {users} {TAG} people (revoked, secrets and passkeys removed), deleted {assets} documents with their grants, "
                  f"closed {alerts} open alert(s). The audit trail is append-only and keeps their history.")
            return
        out = await seed(db)
    print(json.dumps(out))


if __name__ == "__main__":
    asyncio.run(main())
