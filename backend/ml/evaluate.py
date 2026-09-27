"""How good is the trained risk model? Measured on the held-out test period.

    cd backend
    python ml/evaluate.py                     # ml/data/features.csv + ml/models/risk_model.joblib
    python ml/evaluate.py --data other.csv    # e.g. a simulation with a different --seed

Reports:
  * false alerts: share of ordinary events reaching HIGH+, and alerts per 100 people per day;
  * per scenario: share of attacks caught (at least one HIGH+ event), and how many of the
    attack's events had happened before the first alert;
  * ranking quality (ROC AUC) of the anomaly detector, the classifier and the combination;
  * example explanations, as an Auditor would read them.
Writes ml/reports/evaluation.md. Remember: this is synthetic data. It shows the method
catches these patterns; real-world performance must be measured on real activity (see
ml/export_feedback.py).
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, UTC

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.risk.features import FEATURES  # noqa: E402
from app.services.risk.model import explain, load_bundle, score_matrix  # noqa: E402
from ml.simulate import SCENARIOS  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
RULE_KINDS = {"TAMPER": "watermark tamper rule", "DUPLICATE": "duplicate registration rule"}


def evaluate(df, bundle, split="test"):
    from sklearn.metrics import roc_auc_score
    te = df[df["split"] == split].copy() if split else df.copy()
    s = score_matrix(bundle, te[FEATURES].to_numpy(float))
    te["risk"], te["rarity"], te["prob"] = s["risk"], s["rarity"], s["probability"]
    t = bundle["thresholds"]
    te["level"] = np.select([te["risk"] >= t["CRITICAL"], te["risk"] >= t["HIGH"], te["risk"] >= t["MEDIUM"]],
                            ["CRITICAL", "HIGH", "MEDIUM"], "LOW")
    te["alert"] = te["level"].isin(["HIGH", "CRITICAL"])
    # LexCorp's deterministic rules raise HIGH alerts for these regardless of the AI
    te["rule"] = te["kind"].isin(list(RULE_KINDS))
    # ordinary events by a person in the 24 h after their own attack: the consequences of that
    # incident (reported separately, not counted as false alerts)
    ts = pd.to_datetime(te["ts"], format="ISO8601")
    after = pd.Series(False, index=te.index)
    for attack_id, g in te[te["label"] == 1].groupby("attack_id"):
        actor, end = g["actor"].iloc[0], ts[g.index].max()
        after |= (te["actor"] == actor) & (te["label"] == 0) & (ts > end) & (ts <= end + pd.Timedelta(hours=24))
    te["aftermath"] = after
    normal = te[(te["label"] == 0) & ~te["aftermath"]]
    # incidents: at most one alert per person per 24 h (as the app groups AI alerts)
    fa = normal[normal["alert"]].copy()
    fa["t"] = ts[fa.index]
    fa = fa.sort_values("t")
    incidents, last = 0, {}
    for _, r in fa.iterrows():
        if r["actor"] not in last or r["t"] - last[r["actor"]] > pd.Timedelta(hours=24):
            incidents += 1
            last[r["actor"]] = r["t"]
    days = max(1.0, (np.datetime64(te["ts"].max()) - np.datetime64(te["ts"].min())) / np.timedelta64(1, "D"))
    people = te["actor"].nunique()
    out = {
        "events": int(len(te)), "normal_events": int(len(normal)), "misuse_events": int(te["label"].sum()),
        "false_alert_rate": float(normal["alert"].mean()) if len(normal) else 0.0,
        "false_alerts_per_100_people_per_day": float(normal["alert"].sum() / days / max(people, 1) * 100),
        "days": float(days), "people": int(people),
        "false_incidents_per_100_people_per_day": float(incidents / days / max(people, 1) * 100),
        "aftermath_events": int(te["aftermath"].sum()),
        "aftermath_alert_rate": float(te[te["aftermath"]]["alert"].mean()) if te["aftermath"].any() else 0.0,
    }
    for name, col in (("anomaly detector", "rarity"), ("classifier", "prob"), ("combined", "risk")):
        try:
            out[f"auc_{name}"] = float(roc_auc_score(te["label"], te[col]))
        except ValueError:
            out[f"auc_{name}"] = None
    rows = []
    for name in SCENARIOS:
        att = te[te["scenario"] == name]
        if att.empty:
            continue
        caught, with_rules, before = 0, 0, []
        for _, g in att.sort_values("ts").groupby("attack_id"):
            hits = np.flatnonzero(g["alert"].to_numpy())
            if len(hits):
                caught += 1
                before.append(int(hits[0]))
            if len(hits) or g["rule"].any():
                with_rules += 1
        n = att["attack_id"].nunique()
        rows.append({"scenario": name, "difficulty": SCENARIOS[name][1], "attacks": int(n), "caught": caught,
                     "rate": caught / n, "rate_with_rules": with_rules / n,
                     "median_events_before_alert": float(np.median(before)) if before else None})
    out["scenarios"] = rows
    alerts = te[te["alert"]]
    out["alerts_total"] = int(len(alerts))
    out["alert_precision"] = float(alerts["label"].mean()) if len(alerts) else None
    ex = []
    for name in SCENARIOS:
        hit = te[(te["scenario"] == name) & te["alert"]]
        if len(hit):
            r = hit.iloc[0]
            ex.append((name, r["level"], float(r["risk"]), explain(bundle, {k: float(r[k]) for k in FEATURES})))
    out["examples"] = ex
    return out


def report(r, bundle) -> str:
    lines = [f"# LexCorp risk model evaluation ({datetime.now(UTC):%Y-%m-%d %H:%M} UTC)", "",
             f"Model `{bundle.get('version')}`, thresholds {bundle['thresholds']}.",
             f"Test period: {r['days']:.0f} days, {r['people']} people, {r['events']:,} events "
             f"({r['misuse_events']:,} misuse events). **Synthetic data.**", "",
             "## False alerts", "",
             f"- Ordinary events reaching HIGH or above: **{r['false_alert_rate'] * 100:.3f}%**",
             f"- That is about {r['false_alerts_per_100_people_per_day']:.2f} flagged ordinary events per 100 people per day, which the "
             f"app groups into about **{r['false_incidents_per_100_people_per_day']:.2f} false alerts per 100 people per day** "
             "(one open AI alert per person per 24 h)",
             f"- In the 24 h after an attack, {r['aftermath_alert_rate'] * 100:.1f}% of that person's other actions were also flagged "
             f"({r['aftermath_events']} events, not counted above)",
             f"- Share of HIGH+ alerts that were real misuse (precision): "
             f"**{(r['alert_precision'] or 0) * 100:.1f}%** of {r['alerts_total']} alerts", "",
             "## Misuse caught (at least one HIGH+ alert per attack)", "",
             "| Scenario | Difficulty | Attacks | Caught by AI | AI rate | AI + rules | Events before first AI alert (median) |",
             "|---|---|---|---|---|---|---|"]
    for s in r["scenarios"]:
        m = s["median_events_before_alert"]
        before = "-" if m is None else f"{m:.0f}"
        lines.append(f"| {s['scenario']} | {s['difficulty']} | {s['attacks']} | {s['caught']} | {s['rate'] * 100:.0f}% | "
                     f"{s['rate_with_rules'] * 100:.0f}% | {before} |")
    lines += ["", "## Ranking quality (ROC AUC, 1.0 = perfect)", ""]
    for k in ("anomaly detector", "classifier", "combined"):
        v = r.get(f"auc_{k}")
        lines.append(f"- {k}: {'n/a' if v is None else f'{v:.3f}'}")
    lines += ["", "## Example explanations (as shown to the Auditor)", ""]
    for name, level, risk, reasons in r["examples"]:
        lines.append(f"- **{name}** ({level}, risk {risk:.1f}): " + ("; ".join(reasons) or "(no single standout feature)"))
    lines += ["", "Caveat: synthetic activity. The scenario the classifier was trained on is easier for it than "
              "genuinely new misuse; the anomaly detector's AUC is the better guide to that. Measure on real "
              "activity with Auditor feedback (ml/export_feedback.py) before relying on these numbers."]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=os.path.join(HERE, "data", "features.csv"))
    ap.add_argument("--model", default=os.path.join(HERE, "models", "risk_model.joblib"))
    ap.add_argument("--split", default="test", help="test (default), train, or '' for all rows")
    ap.add_argument("--report", default=os.path.join(HERE, "reports", "evaluation.md"))
    a = ap.parse_args()
    import pandas as pd
    bundle = load_bundle(a.model)
    if bundle is None:
        raise SystemExit(f"No usable model at {a.model}: run python ml/train.py")
    from ml.train import load
    r = evaluate(load(a.data), bundle, a.split)
    text = report(r, bundle)
    os.makedirs(os.path.dirname(a.report), exist_ok=True)
    open(a.report, "w", encoding="utf-8").write(text)
    print(text)
    print(f"Written to {a.report}")


if __name__ == "__main__":
    main()
