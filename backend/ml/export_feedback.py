"""Turn Auditors' decisions on real alerts into training labels.

    cd backend
    python ml/export_feedback.py                 # writes ml/data/feedback.csv
    python ml/train.py --feedback ml/data/feedback.csv

For every closed security alert that came from a person's action:
  * DISMISSED (a reviewer judged it a false alarm)      -> label 0 (ordinary behaviour)
  * IDENTITY_REVOKED (the identity was revoked for it)  -> label 1 (misuse)
The features of the action are rebuilt exactly as the live app computes them (the person's
history up to that moment, from the audit trail). Open alerts are skipped, and so are alerts
about automated test identities (names starting "E2E-", e.g. scripts/e2e_m1_fixture.py). Needs the
database running (npm start or docker compose up -d postgres). Reads only; changes nothing.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402

from app.core.database import async_session_factory  # noqa: E402
from app.models.domain import AuditEvent, SecurityAlert, User  # noqa: E402
from app.services.risk.features import FEATURES, Event, features_for  # noqa: E402
from app.services.risk.live import AUDIT_KIND, FAILED, _asset_info, history_for, local  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LABEL = {"DISMISSED": 0, "IDENTITY_REVOKED": 1}
TEST_PREFIX = "E2E-"   # automated browser-test identities: their decisions are not real judgements


async def export(out_path: str) -> int:
    rows = []
    async with async_session_factory() as db:
        alerts = (await db.execute(select(SecurityAlert).where(SecurityAlert.state.in_(list(LABEL))))).scalars().all()
        for a in alerts:
            if not a.source_event_id or not a.subject_did:
                continue
            ev = (await db.execute(select(AuditEvent).where(AuditEvent.id == a.source_event_id))).scalar_one_or_none()
            person = (await db.execute(select(User).where(User.did == a.subject_did))).scalar_one_or_none()
            kind = AUDIT_KIND.get(ev.event_type) if ev else None
            if ev is None or person is None or kind is None or (person.name or "").startswith(TEST_PREFIX):
                continue
            if kind == "DOWNLOAD" and isinstance(ev.risk_factors, dict) and ev.risk_factors.get("mode") == "MODIFICATION":
                kind = "MOD_COPY"
            history = [h for h in await history_for(db, person, ev.created_at) if h.ts < local(ev.created_at)]
            info = await _asset_info(db, {ev.asset_serial} if ev.asset_serial else set())
            dept, owner, sens = info.get(ev.asset_serial, (None, None, 1))
            event = Event(ts=local(ev.created_at), actor=person.did, role=person.role, dept=person.department, kind=kind,
                          asset=ev.asset_serial, asset_dept=dept, asset_owner=owner, sensitivity=sens,
                          ip=ev.client_ip, ok=kind not in FAILED)
            feats = features_for(event, history)
            rows.append([event.ts.isoformat(), person.did, kind, LABEL[a.state], f"feedback:{a.alert_id}", a.alert_id, "train"]
                        + [f"{feats[k]:.6g}" for k in FEATURES])
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts", "actor", "kind", "label", "scenario", "attack_id", "split"] + FEATURES)
        w.writerows(rows)
    return len(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(HERE, "data", "feedback.csv"))
    a = ap.parse_args()
    n = asyncio.run(export(a.out))
    print(f"Exported {n} Auditor-labelled events to {a.out}")
    if n:
        print(f"Next: python ml/train.py --feedback {a.out}")
    else:
        print("No closed alerts yet: dismiss or resolve some alerts in the app first.")


if __name__ == "__main__":
    main()
