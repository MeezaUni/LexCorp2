"""The local risk model: shared features, simulate -> train -> evaluate, and live scoring from
the audit trail (with explanations and one open AI alert per person per day)."""
import uuid
from datetime import datetime, timedelta, UTC

import pytest
from sqlalchemy import select

from app.models.domain import AuditEvent, SecurityAlert, User
from app.services.risk import model as risk_model
from app.services.risk.features import FEATURES, Event, features_for

USER_WALLET = "0xe1ced2305c7c75618eeb1450e18e2099c15b7d72"


def _ev(minutes, kind="VIEW", asset="D1", ip="10.0.0.1", ok=True, dept="Avionics", asset_dept="Avionics"):
    base = datetime(2026, 3, 2, 10, 0)
    return Event(ts=base + timedelta(minutes=minutes), actor="p1", role="USER", dept=dept, kind=kind, asset=asset,
                 asset_dept=asset_dept, asset_owner="p2", ip=ip, ok=ok)


def test_features_use_only_the_past_and_describe_the_burst():
    history = [_ev(-60 * 24 * d) for d in range(1, 20)]             # one view a day for 19 days
    later = _ev(5)                                                  # an event AFTER the one scored is ignored
    burst = [_ev(i, "DOWNLOAD", f"X{i}", asset_dept="Radar") for i in range(-50, 0)]
    f = features_for(_ev(0, "DOWNLOAD", "X99", ip="172.16.0.9", asset_dept="Radar"), history + burst + [later])
    assert set(f) == set(FEATURES)
    assert f["events_1h"] == 51 and f["copies_24h"] == 51
    assert f["new_ip"] == 1.0 and f["out_of_dept_share_24h"] > 0.9
    assert f["new_assets_24h"] == 51                                # none of these were touched before
    assert f["volume_ratio_24h"] > 10                               # far above this person's usual day


def test_explanations_never_leave_a_flagged_event_without_a_reason():
    names = list(risk_model.FEATURE_TEXT)
    bundle = {"baseline": {"median": {k: 1.0 for k in names}, "spread": {k: 2.0 for k in names}}}
    quiet = {k: 1.0 for k in names}
    # exactly 1.5 spreads above normal counts as a reason
    assert risk_model.explain(bundle, {**quiet, "copies_24h": 4.0}) == ["4 downloads/copies in the last 24 h (usual about 1)"]
    # nothing reaches 1.5, but moderately raised features are still named (at most two)
    moderate = {**quiet, "copies_24h": 3.0, "new_assets_24h": 3.5, "events_1h": 3.2}
    assert len(risk_model.explain(bundle, moderate)) == 2
    assert risk_model.explain(bundle, quiet) == []


@pytest.fixture(scope="module")
def tiny_bundle(tmp_path_factory):
    """A small but real simulate -> train run."""
    import pandas as pd
    from app.services.risk.features import stream_features
    from ml.simulate import simulate
    from ml.train import train
    rows, split_at, _ = simulate(people=14, days=45, seed=3, attacks_per_scenario=6, orgs=1)
    recs = []
    for (e, f), r in zip(stream_features(r["event"] for r in rows), rows):
        recs.append({"ts": e.ts.isoformat(), "actor": e.actor, "kind": e.kind, "label": r["label"], "scenario": r["scenario"],
                     "attack_id": r["attack_id"], "split": "train" if e.ts < split_at else "test", **f})
    df = pd.DataFrame(recs)
    bundle = train(df, quiet=True)
    bundle["version"] = "test"
    return bundle, df


def test_train_and_evaluate_catch_bursts_with_few_false_alerts(tiny_bundle):
    from ml.evaluate import evaluate
    bundle, df = tiny_bundle
    assert bundle["thresholds"]["MEDIUM"] < bundle["thresholds"]["HIGH"] < bundle["thresholds"]["CRITICAL"]
    r = evaluate(df, bundle, "test")
    assert r["false_alert_rate"] < 0.02
    caught = {s["scenario"]: s["rate"] for s in r["scenarios"]}
    assert caught.get("factor_bruteforce", 0) >= 0.5 and caught.get("exfil_burst", 0) >= 0.5


@pytest.mark.asyncio
async def test_live_scoring_reads_the_audit_trail_and_explains(tiny_bundle, db_session, monkeypatch):
    from app.services.alerts import ai_assess
    bundle, _ = tiny_bundle
    monkeypatch.setattr(risk_model, "load_bundle", lambda path=None: bundle)
    user = (await db_session.execute(select(User).where(User.wallet_address == USER_WALLET))).scalar_one()
    now = datetime.now(UTC)
    for i in range(30):   # a burst of downloads of different documents in the last hour
        db_session.add(AuditEvent(event_type="DOCUMENT_DOWNLOADED", tx_hash=f"0x{uuid.uuid4().hex}", block_number=0,
                                  actor_did=user.did, asset_serial=f"RISK-{uuid.uuid4().hex[:6]}", client_ip="172.16.5.5",
                                  risk_factors={"mode": "STANDARD"}, created_at=now - timedelta(minutes=55 - i)))
    await db_session.commit()
    r = await ai_assess(db_session, "DOWNLOAD", user, asset_serial="RISK-NEW", client_ip="172.16.5.5")
    assert r["risk_label"] in ("HIGH", "CRITICAL"), r
    assert r["ai"]["model"].startswith("LexCorp2 risk model") and r["ai"]["reasons"]
    assert any("downloads" in x or "actions" in x or "documents" in x for x in r["ai"]["reasons"])


@pytest.mark.asyncio
async def test_one_open_ai_alert_per_person_per_day(db_session):
    from app.api.dependencies import record_audit
    user = (await db_session.execute(select(User).where(User.wallet_address == USER_WALLET))).scalar_one()
    before = len((await db_session.execute(select(SecurityAlert).where(SecurityAlert.subject_did == user.did,
                                                                       SecurityAlert.source == "AI"))).scalars().all())
    for _ in range(3):
        await record_audit(db_session, "DOCUMENT_DOWNLOADED", actor_did=user.did, risk_label="HIGH", risk_score=99.9,
                           details={"ai": {"reasons": ["30 downloads/copies in the last 24 h"]}})
    await db_session.commit()
    after = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.subject_did == user.did,
                                                                  SecurityAlert.source == "AI"))).scalars().all()
    assert len(after) - before <= 1
    assert any("30 downloads" in a.reason for a in after)
    # the events themselves are all in the audit trail
    events = (await db_session.execute(select(AuditEvent).where(AuditEvent.actor_did == user.did,
                                                               AuditEvent.risk_label == "HIGH"))).scalars().all()
    assert len(events) >= 3


@pytest.mark.asyncio
async def test_open_ai_alert_takes_the_strongest_evidence(db_session):
    from app.api.dependencies import record_audit
    from app.models.domain import SecurityAlertAction
    did = f"did:ethr:1337:0x{uuid.uuid4().hex[:40]}"
    db_session.add(User(wallet_address=did[-42:], did=did, name="Evidence Person", role="USER", department="Avionics",
                        onboarding_pending=False))
    await db_session.commit()

    async def act(level, reason):
        await record_audit(db_session, "DOCUMENT_VIEWED", actor_did=did, risk_label=level, risk_score=100.0,
                           details={"ai": {"reasons": [reason]}})
        await db_session.commit()

    await act("HIGH", "1 documents never touched before, in 24 h")
    await act("CRITICAL", "12 documents never touched before, in 24 h")
    await act("HIGH", "at the weekend")                     # weaker than what the alert already shows
    alerts = (await db_session.execute(select(SecurityAlert).where(SecurityAlert.subject_did == did))).scalars().all()
    assert len(alerts) == 1
    a = alerts[0]
    assert a.risk_level == "CRITICAL" and "12 documents" in a.reason
    history = (await db_session.execute(select(SecurityAlertAction).where(SecurityAlertAction.alert_id == a.id)
                                        .order_by(SecurityAlertAction.created_at))).scalars().all()
    assert [h.action for h in history] == ["RAISED", "SEVERITY_RAISED"]
    assert "1 documents" in history[0].note and "HIGH to CRITICAL" in history[1].note
