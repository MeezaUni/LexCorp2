"""
Inference Module & Latency Benchmark for LexCorp Blockchain Risk Engine
Provides single-event real-time prediction and latency profiling.
"""

import os
import time
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any

# ---------------------------------------------------------
# CONSTANTS & PATHS
# ---------------------------------------------------------
PREPROCESSOR_PATH = "ml/models/preprocessor.joblib"
MODEL_PATH = "ml/models/isolation_forest.joblib"
CONFIG_PATH = "ml/models/model_config.json"

# Load artifacts ONCE at module level
if os.path.exists(PREPROCESSOR_PATH) and os.path.exists(MODEL_PATH) and os.path.exists(CONFIG_PATH):
    _PREPROCESSOR = joblib.load(PREPROCESSOR_PATH)
    _MODEL = joblib.load(MODEL_PATH)
    with open(CONFIG_PATH, "r") as f:
        _CONFIG = json.load(f)
    _FEATURE_COLS = _CONFIG["features"]["numerical"] + _CONFIG["features"]["categorical"]
else:
    _PREPROCESSOR = None
    _MODEL = None
    _CONFIG = None
    _FEATURE_COLS = []


def get_risk_label(risk_score: float) -> str:
    """Classifies risk score into operational tiers."""
    if risk_score < 25.0:
        return "LOW"
    elif risk_score < 50.0:
        return "MEDIUM"
    elif risk_score < 75.0:
        return "HIGH"
    else:
        return "CRITICAL"


def predict_event_risk(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes anomaly score, calibrated 0-100 risk score, and risk label for a single blockchain event.

    Parameters:
        event (dict): Dictionary containing event features according to feature schema.

    Returns:
        dict: {
            "anomaly_score": float,  # Raw IsolationForest decision_function value (<0 outlier, >0 inlier)
            "risk_score": float,     # Continuous calibrated risk index in [0.0, 100.0]
            "risk_label": str        # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        }
    """
    global _PREPROCESSOR, _MODEL, _FEATURE_COLS
    if _PREPROCESSOR is None or _MODEL is None:
        raise RuntimeError("Model or preprocessor artifacts not loaded. Please run train_model.py first.")

    # Efficient single-row DataFrame construction matching column order
    row_data = {col: [event[col]] for col in _FEATURE_COLS}
    df_row = pd.DataFrame(row_data)

    # Preprocessing
    X_transformed = _PREPROCESSOR.transform(df_row)

    # Model inference
    raw_score = float(_MODEL.decision_function(X_transformed)[0])

    # Calibrate risk score: 50.0 - 250.0 * raw_score
    risk_score = float(np.clip(50.0 - (raw_score * 250.0), 0.0, 100.0))
    risk_score = round(risk_score, 2)

    risk_label = get_risk_label(risk_score)

    return {
        "anomaly_score": round(raw_score, 4),
        "risk_score": risk_score,
        "risk_label": risk_label
    }


def benchmark_inference(num_iterations: int = 1000):
    """Benchmarks single-event inference latency over N consecutive runs."""
    print("="*60)
    print(f"BENCHMARKING INFERENCE LATENCY ({num_iterations} iterations)")
    print("="*60)

    sample_event = {
        "access_hour": 14,
        "is_weekend": 0,
        "time_elapsed_from_last_tx": 420.5,
        "role_escalation_index": 0.0,
        "rolling_event_frequency_1h": 4,
        "rolling_failure_rate_24h": 0.015,
        "asset_sensitivity_tier": 0,
        "is_write_operation": 0,
        "actor_to_asset_relationship_depth": 0,
        "user_role": "USER",
        "event_type": "AccessGranted"
    }

    # Warmup
    for _ in range(20):
        _ = predict_event_risk(sample_event)

    latencies_ms = []
    for _ in range(num_iterations):
        t0 = time.perf_counter()
        _ = predict_event_risk(sample_event)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    latencies_ms = np.array(latencies_ms)
    avg_latency = np.mean(latencies_ms)
    median_latency = np.median(latencies_ms)
    p95_latency = np.percentile(latencies_ms, 95)
    p99_latency = np.percentile(latencies_ms, 99)

    print(f"Sample Prediction Output:")
    res = predict_event_risk(sample_event)
    print(json.dumps(res, indent=4))

    print(f"\nLatency Benchmark Results:")
    print(f" - Average Inference Latency: {avg_latency:.3f} ms")
    print(f" - Median Inference Latency:  {median_latency:.3f} ms")
    print(f" - 95th Percentile Latency:   {p95_latency:.3f} ms")
    print(f" - 99th Percentile Latency:   {p99_latency:.3f} ms")
    print(f" - Target (< 50.0 ms):        {'[PASSED]' if p95_latency < 50.0 else '[FAILED]'}")


if __name__ == "__main__":
    benchmark_inference(1000)
