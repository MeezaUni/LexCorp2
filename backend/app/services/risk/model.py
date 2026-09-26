"""The trained risk model bundle (written by backend/ml/train.py) and how events are scored.

Score = combination of two local scikit-learn models over the shared features:
  * an Isolation Forest trained on normal activity only (catches the unusual, including
    kinds of misuse nobody simulated), turned into a 0..1 rarity rank against normal data;
  * a gradient-boosted classifier trained on labelled examples (simulated attack scenarios
    plus any Auditor decisions exported from the live system).
Tampered returns and duplicate registrations are caught with certainty by LexCorp2's
deterministic rules; the AI is for behaviour no rule describes.
risk = max of the two ranks * 100 (each relative to held-back normal activity), and the thresholds for MEDIUM / HIGH /
CRITICAL come from the bundle: they were set during training so that only a small, known
share of normal activity reaches each level. Everything runs on this machine.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Dict, List, Optional

import numpy as np

from app.services.risk.features import FEATURE_TEXT, FEATURES, vector

logger = logging.getLogger(__name__)

DEFAULT_BUNDLE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
                              "ml", "models", "risk_model.joblib")


def bundle_path() -> str:
    return os.environ.get("RISK_MODEL_PATH") or DEFAULT_BUNDLE


@lru_cache(maxsize=1)
def load_bundle(path: Optional[str] = None) -> Optional[dict]:
    path = path or bundle_path()
    if not os.path.exists(path):
        return None
    import joblib
    bundle = joblib.load(path)
    if bundle.get("features") != FEATURES:
        logger.warning("Risk model at %s was trained on a different feature set; retrain it (python ml/train.py).", path)
        return None
    return bundle


def _rarity(bundle: dict, X: np.ndarray) -> np.ndarray:
    """0..1: share of normal training events that were LESS anomalous than this one."""
    raw = -bundle["iforest"].score_samples(X)                     # higher = more anomalous
    ref = bundle["normal_raw_sorted"]
    return np.searchsorted(ref, raw, side="right") / float(len(ref))


def score_matrix(bundle: dict, X: np.ndarray) -> Dict[str, np.ndarray]:
    """Both models are put on the same scale, "how unusual compared with ordinary activity":
    rarity = share of held-back normal events the forest found less anomalous; for the
    classifier, the share of held-back normal events it rated less likely to be misuse."""
    rarity = _rarity(bundle, X)
    if bundle.get("classifier") is not None:
        prob = bundle["classifier"].predict_proba(X)[:, 1]
        ref = bundle["normal_prob_sorted"]
        prob_rank = np.searchsorted(ref, prob, side="left") / float(len(ref))
    else:
        prob = prob_rank = np.zeros(len(X))
    risk = np.maximum(rarity, prob_rank) * 100.0
    return {"rarity": rarity, "probability": prob, "classifier_rank": prob_rank, "risk": risk}


def label_for(bundle: dict, risk: float) -> str:
    t = bundle["thresholds"]
    if risk >= t["CRITICAL"]:
        return "CRITICAL"
    if risk >= t["HIGH"]:
        return "HIGH"
    if risk >= t["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def explain(bundle: dict, feats: Dict[str, float], limit: int = 3) -> List[str]:
    """The most unusual features of this event compared with normal activity, in words."""
    med, spread = bundle["baseline"]["median"], bundle["baseline"]["spread"]
    scored = []
    for name, text in FEATURE_TEXT.items():
        v = feats.get(name)
        if v is None:
            continue
        z = (v - med[name]) / spread[name]
        if z <= 1.5:
            continue
        sentence = text(v, med[name])
        if sentence:
            scored.append((z, sentence))
    return [s for _, s in sorted(scored, reverse=True)[:limit]]


def assess(feats: Dict[str, float], bundle: Optional[dict] = None) -> Optional[dict]:
    bundle = bundle or load_bundle()
    if bundle is None:
        return None
    X = np.asarray([vector(feats)], dtype=float)
    s = score_matrix(bundle, X)
    risk = float(s["risk"][0])
    return {
        "risk_score": round(risk, 1),
        "risk_label": label_for(bundle, risk),
        "rarity": round(float(s["rarity"][0]), 4),
        "probability": round(float(s["probability"][0]), 4),
        "reasons": explain(bundle, feats),
        "model_version": bundle.get("version"),
    }
