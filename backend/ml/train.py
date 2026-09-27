"""Train LexCorp's local risk model and write the bundle the app loads.

    cd backend
    python ml/train.py                                  # uses ml/data/features.csv
    python ml/train.py --feedback ml/data/feedback.csv  # also learn from Auditor decisions
    python ml/train.py --high-rate 0.0005               # fewer alerts (HIGH on 0.05 % of normal activity)

What it does (all local, scikit-learn):
  1. Isolation Forest on NORMAL activity only: learns what ordinary behaviour looks like, so
     it can flag the unusual, including misuse nobody simulated.
  2. Gradient-boosted classifier on labelled examples (simulated attack scenarios, plus
     Auditor feedback if given): learns what known misuse looks like.
  3. Thresholds: on a held-back slice of the training period, MEDIUM / HIGH / CRITICAL are set
     so only the chosen share of normal activity reaches each level (so the alert volume is
     known in advance, instead of alerting on everything like the old model).
  4. Baseline statistics used to explain alerts in plain words.
Output: ml/models/risk_model.joblib (loaded by the app on its next start; set RISK_MODEL_PATH
to use another file). Then run: python ml/evaluate.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, UTC

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.risk.features import FEATURES  # noqa: E402
from app.services.risk.model import score_matrix  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path: str):
    import pandas as pd
    df = pd.read_csv(path, dtype={"scenario": str, "attack_id": str, "actor": str, "kind": str, "split": str})
    df[["scenario", "attack_id"]] = df[["scenario", "attack_id"]].fillna("")
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        raise SystemExit(f"{path} lacks features {missing}: regenerate it with python ml/simulate.py")
    return df


def train(df, feedback=None, *, high_rate=0.001, medium_rate=0.01, critical_rate=0.0002, seed=0, quiet=False):
    from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest

    log = (lambda *a: None) if quiet else print
    tr = df[df["split"] == "train"].copy()
    tr["ts"] = tr["ts"].astype(str)
    cut = tr["ts"].quantile(0.8, interpolation="nearest") if len(tr) else None
    core, calib = tr[tr["ts"] < cut], tr[tr["ts"] >= cut]
    if len(calib) < 100 or (calib["label"] == 0).sum() < 100:
        core, calib = tr, tr

    X_normal = core[core["label"] == 0][FEATURES].to_numpy(float)
    t0 = time.time()
    iforest = IsolationForest(n_estimators=300, max_samples=min(4096, len(X_normal)), random_state=seed, n_jobs=-1)
    iforest.fit(X_normal)
    # The rarity scale is measured on HELD-BACK normal events: scores of the events the forest was
    # fitted on are optimistic, which made new ordinary activity look rarer than it is.
    X_ref = calib[calib["label"] == 0][FEATURES].to_numpy(float) if calib is not core else X_normal
    raw = np.sort(-iforest.score_samples(X_ref))
    step = max(1, len(raw) // 20000)
    normal_raw_sorted = raw[::step]
    log(f"Isolation Forest on {len(X_normal):,} normal events ({time.time() - t0:.1f}s)")

    # The first event of an attack usually looks exactly like ordinary work (the modification copy
    # before a tampered return, the first of many downloads). Teaching the classifier that it is
    # misuse only teaches it to distrust ordinary work, so it is left out of classifier training
    # (it still counts in evaluation).
    order = core.sort_values("ts")
    position = order.groupby(order["attack_id"]).cumcount().reindex(core.index)
    keep = ~((core["label"] == 1) & (position == 0))
    X = core[keep][FEATURES].to_numpy(float)
    y = core[keep]["label"].to_numpy(int)
    w = np.ones(len(y))
    if feedback is not None and len(feedback):
        X = np.vstack([X, feedback[FEATURES].to_numpy(float)])
        y = np.concatenate([y, feedback["label"].to_numpy(int)])
        w = np.concatenate([w, np.full(len(feedback), 5.0)])   # a person's verdict counts more than a simulation
        log(f"Including {len(feedback)} Auditor-labelled events ({int(feedback['label'].sum())} confirmed misuse)")
    classifier = None
    if y.sum() >= 10 and (y == 0).sum() >= 10:
        t0 = time.time()
        pos = y.sum()
        w = w * np.where(y == 1, (len(y) - pos) / max(pos, 1) / 10.0, 1.0)   # rebalance, capped
        classifier = HistGradientBoostingClassifier(max_iter=250, learning_rate=0.08, max_leaf_nodes=31, min_samples_leaf=5,
                                                    l2_regularization=1.0, random_state=seed)
        classifier.fit(X, y, sample_weight=w)
        log(f"Classifier on {len(y):,} labelled events, {int(pos):,} misuse ({time.time() - t0:.1f}s)")
    else:
        log("Not enough labelled misuse for the classifier: anomaly detection only")

    bundle = {"features": list(FEATURES), "iforest": iforest, "classifier": classifier,
              "normal_raw_sorted": normal_raw_sorted, "thresholds": {"MEDIUM": 101, "HIGH": 101, "CRITICAL": 101}}
    normal_cal = calib[calib["label"] == 0][FEATURES].to_numpy(float)
    if classifier is not None:
        probs = np.sort(classifier.predict_proba(normal_cal)[:, 1])
        bundle["normal_prob_sorted"] = probs[::max(1, len(probs) // 20000)]
    risk = np.sort(score_matrix(bundle, normal_cal)["risk"])
    q = lambda rate: float(np.quantile(risk, 1.0 - rate)) if len(risk) else 99.0  # noqa: E731
    thresholds = {"MEDIUM": q(medium_rate), "HIGH": q(high_rate), "CRITICAL": q(critical_rate)}
    # keep them ordered and meaningful
    thresholds["HIGH"] = max(thresholds["HIGH"], thresholds["MEDIUM"] + 0.01)
    thresholds["CRITICAL"] = max(thresholds["CRITICAL"], thresholds["HIGH"] + 0.01)
    bundle["thresholds"] = {k: round(v, 4) for k, v in thresholds.items()}

    normal_all = tr[tr["label"] == 0][FEATURES]
    med = normal_all.median()
    iqr = normal_all.quantile(0.75) - normal_all.quantile(0.25)
    spread = np.maximum(iqr, normal_all.std().fillna(0) * 0.5).clip(lower=0.25)
    bundle["baseline"] = {"median": {k: float(med[k]) for k in FEATURES}, "spread": {k: float(spread[k]) for k in FEATURES}}
    bundle["training"] = {"rows": int(len(tr)), "normal": int((tr["label"] == 0).sum()), "misuse": int(tr["label"].sum()),
                          "scenarios": sorted(s for s in tr["scenario"].unique() if s),
                          "feedback_rows": int(len(feedback)) if feedback is not None else 0,
                          "target_rates": {"MEDIUM": medium_rate, "HIGH": high_rate, "CRITICAL": critical_rate}}
    return bundle


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=os.path.join(HERE, "data", "features.csv"))
    ap.add_argument("--feedback", default=None, help="CSV from ml/export_feedback.py (Auditor-labelled live events)")
    ap.add_argument("--out", default=os.path.join(HERE, "models", "risk_model.joblib"))
    ap.add_argument("--high-rate", type=float, default=0.001, help="share of normal events allowed to reach HIGH (default 0.1%%)")
    ap.add_argument("--medium-rate", type=float, default=0.01)
    ap.add_argument("--critical-rate", type=float, default=0.0002)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    import joblib
    import pandas as pd

    if not os.path.exists(a.data):
        raise SystemExit(f"{a.data} not found: run python ml/simulate.py first")
    df = load(a.data)
    feedback = pd.read_csv(a.feedback) if a.feedback else None
    t0 = time.time()
    bundle = train(df, feedback, high_rate=a.high_rate, medium_rate=a.medium_rate, critical_rate=a.critical_rate, seed=a.seed)
    digest = hashlib.sha256(open(a.data, "rb").read()).hexdigest()[:10]
    bundle["version"] = f"{datetime.now(UTC):%Y%m%d-%H%M}-{digest}"
    bundle["trained_at"] = datetime.now(UTC).isoformat()
    bundle["training"]["data_sha256_10"] = digest
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    joblib.dump(bundle, a.out, compress=3)
    print(f"\nModel {bundle['version']} written to {a.out} ({time.time() - t0:.1f}s)")
    print("Thresholds (risk 0-100):", json.dumps(bundle["thresholds"]))
    print(f"Expected share of ordinary activity reaching HIGH or above: about {a.high_rate * 100:.2f}%")
    print("Next: python ml/evaluate.py   (then restart the app to use the new model)")


if __name__ == "__main__":
    main()
