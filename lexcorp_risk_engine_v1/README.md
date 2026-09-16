# LexCorp Blockchain Risk Engine – ML Component

## Overview

This is the **unsupervised anomaly detection** module for the LexCorp Blockchain Risk Engine, a Smart India Hackathon project. The ML engine detects unusual or potentially suspicious blockchain access behaviour by learning what constitutes normal behavior and flagging significant deviations.

### Key Design Decisions

- **Unsupervised Learning (Isolation Forest)**: No labeled attack dataset exists yet. The model learns a baseline of normal user/admin behavior and identifies events that fall outside that distribution.
- **Synthetic Evaluation**: 5,000 synthetic anomalous events simulate realistic attack scenarios for testing. These **do not** represent real-world attack distributions and are used only to validate that the model can detect deviation patterns.
- **Continuous Risk Scoring**: Raw anomaly scores are mapped to a calibrated 0–100 risk index with operational tiers (LOW / MEDIUM / HIGH / CRITICAL).

---

## Dataset

### Composition
- **30,000 total events**
  - 25,000 normal (80% train / 20% held-out test)
  - 5,000 synthetic anomalous (evaluation only)

### Features (10 Total)

| Feature | Type | Range / Values | Description |
|---------|------|---|---|
| `access_hour` | int | 0–23 | Hour of day (0=midnight, 23=11pm) |
| `is_weekend` | binary | 0, 1 | Weekend (1) or weekday (0) |
| `time_elapsed_from_last_tx` | float | seconds | Time since actor's last blockchain tx (>0) |
| `role_escalation_index` | float | 0.0–2.0 | Deviation from assigned role (0: normal, 2: severe) |
| `rolling_event_frequency_1h` | int | count | Operations by actor in prior 60 min |
| `rolling_failure_rate_24h` | float | 0.0–1.0 | failed_attempts / total_attempts in 24h |
| `asset_sensitivity_tier` | int | 0, 1, 2 | PUBLIC (0), PRIVATE (1), CONFIDENTIAL (2) |
| `is_write_operation` | binary | 0, 1 | Mutating (1) or read-only (0) |
| `actor_to_asset_relationship_depth` | int | 0–3 | Direct owner (0) → Unauthorized (3) |
| `user_role` | categorical | USER, MANAGER, ADMIN, AUDITOR | Actor's assigned role |
| `event_type` | categorical | AccessAttempted, AccessGranted, ... | 8 blockchain audit event types |

### Feature Schema
Saved to `ml/data/feature_schema.json` with detailed descriptions and data types.

### Data Quality
- ✓ No missing values
- ✓ All time intervals strictly positive
- ✓ access_hour in [0, 23]
- ✓ Failure rates in [0.0, 1.0]
- ✓ All categorical domains match schema
- ✓ Realistic behavioral distributions by role

---

## Normal Behavior Profiles

The dataset reflects realistic operational patterns for each role:

### USER (60% of population)
- Mostly business-hour activity (8am–7pm)
- Primarily read/access operations
- Accesses owned/authorized assets
- Low-to-moderate frequency (median ~4 ops/hr)
- Low failure rate (<12% typically)
- Occasional legitimate off-hours access (~10%)
- Can legitimately access CONFIDENTIAL assets (7% of events)

### MANAGER (20%)
- More activity than users
- Mixed read/write operations
- Can access managed subordinate assets
- Moderate frequency (median ~12 ops/hr)
- Low failure rate
- Mostly business hours with occasional off-hours work

### ADMIN (10%)
- Highest legitimate activity volume
- Can perform privileged operations
- Broad access to CONFIDENTIAL assets (45% of events)
- High frequency is normal (median ~25 ops/hr, up to 85)
- Can operate outside business hours (22% off-hours)
- High activity alone does NOT indicate anomaly

### AUDITOR (10%)
- Primarily read/audit operations
- Broad asset inspection authority
- Low write operations
- Can operate outside business hours
- Moderate frequency (median ~15 ops/hr)

---

## Synthetic Anomaly Scenarios (5,000 events, 625 each)

Each scenario represents a realistic attack or suspicious operational pattern:

### 1. **BRUTE_FORCE_ACCESS** (625 events, 100% detection)
- Rapid authentication attempts (70–220 ops/hour, 0.1–4s intervals)
- Elevated failure rate (60–98%)
- Repeated AccessAttempted/AccessDenied events
- 25% generate low-and-slow variants to evade simple rate limits

### 2. **PRIVILEGE_ESCALATION** (625 events, 100% detection)
- Lower-privileged USER/AUDITOR attempting admin operations
- Escalation index 0.7–2.0 (violation → severe)
- Confidential asset access + write operations
- May occur during normal business hours
- 25% use subtle escalation indices (0.7–1.1) to test boundaries

### 3. **UNAUTHORIZED_ASSET_ACCESS** (625 events, 93.9% detection)
- Actor with no relationship to asset (depth=3)
- Confidential/private asset targeting
- 30% occur during business hours (insider threat simulation)
- 25% have low failure rates to blend as legitimate access
- Can overlap with legitimate access patterns

### 4. **ABNORMAL_HIGH_FREQUENCY** (625 events, 93.0% detection)
- Unusually high operation count (85–300 ops/hour)
- Very short transaction intervals (0.05–3.5s, vs ~6.5s baseline)
- 25% use moderate frequencies (45–80 ops/hr) for stealth
- May involve automated/scripted activity
- Failure rates vary to simulate diverse attack tools

### 5. **OFF_HOURS_SENSITIVE_ACCESS** (625 events, 95.5% detection)
- Access during unusual hours (late night 0–5am or 11pm)
- CONFIDENTIAL asset targeting
- Potential write operations
- 25% use business hours + confidential + write combo for subtle detection

### 6. **REPEATED_ACCESS_FAILURE** (625 events, 99.4% detection)
- Very high failure rate (50–100% of attempts)
- Multiple AccessDenied events
- Moderate-to-high frequency
- 25% use moderate failure rates (50–70%) to evade thresholds

### 7. **SUSPICIOUS_THIRD_PARTY_WRITE** (625 events, 78.7% detection)
- Actor with external relationship (depth 2–3) performing writes
- Private/confidential asset targeting
- 25% occur during business hours with reduced sensitivity tiers
- **Most challenging scenario**: overlaps with legitimate third-party integrations
- Average risk score 57.4 (marginal vs 50-threshold)

### 8. **COMBINED_ATTACK** (625 events, 100% detection)
- Multiple severe indicators simultaneously:
  - Off-hours (0–5am, 11pm)
  - Very high frequency (60–220 ops/hr)
  - High failure rate (50–95%)
  - Severe escalation (1.0–2.0)
  - CONFIDENTIAL asset
  - Write operation
  - No legitimate relationship (depth=3)
  - Always from USER role
- Represents highest-severity synthetic attack profile

### Key Behavioral Overlap Design
- 25% of all anomalies intentionally use "stealth" variants to blend into normal distributions
- Normal data includes ~3% legitimate events with higher failure rates (transient auth issues)
- Normal ADMIN events legitimately spike to 85 ops/hour
- Normal users can occasionally access confidential assets
- Anomalies can occur during business hours (not just nights)
- Some attacks have only 1–2 abnormal features, not all combinations

---

## Model Training

### Architecture
- **Algorithm**: `sklearn.ensemble.IsolationForest`
- **Configuration**:
  - n_estimators: 300 trees
  - contamination: "auto"
  - random_state: 42
  - n_jobs: -1 (all CPU cores)

### Training Data
- **Pure normal baseline**: 20,000 normal events (80% of 25,000)
- **Held-out evaluation set**: 5,000 normal + 5,000 anomalous

### Preprocessing Pipeline (Saved to `ml/models/preprocessor.joblib`)
- **Numerical features**: StandardScaler normalization
- **Categorical features**: OneHotEncoder (handle_unknown="ignore")
- Consistent preprocessing applied to training, validation, and inference

### Model Artifacts Saved
1. `ml/models/isolation_forest.joblib` – Trained IsolationForest
2. `ml/models/preprocessor.joblib` – Feature transformation pipeline
3. `ml/models/model_config.json` – Configuration + risk mapping + baseline stats

---

## Evaluation Results

### Global Performance
**Threshold**: Risk Score ≥ 50 (equivalent to decision_function ≤ 0.0)

| Metric | Value |
|--------|-------|
| **Precision** | 82.83% |
| **Recall** | 95.06% |
| **F1-Score** | 0.8853 |
| **ROC-AUC** | 0.9580 |
| **PR-AUC** | 0.9558 |
| **False Positive Rate** | 19.70% |
| **False Negative Rate** | 4.94% |

### Confusion Matrix
```
                  Predicted Normal    Predicted Anomaly
 Actual Normal         4015                 985         (Total: 5000)
 Actual Anomaly        247                 4753         (Total: 5000)
```

### Risk Score Distributions
| Group | Mean Risk | Median Risk | % LOW | % MED | % HIGH | % CRITICAL |
|-------|-----------|------------|-------|-------|--------|-----------|
| Normal Events | 36.96 | 36.40 | 23.6% | 56.7% | 19.3% | 0.4% |
| Anomaly Events | 71.76 | 71.13 | 0.0% | 4.9% | 57.0% | 38.0% |

### Per-Scenario Detection Performance

| Scenario | Total | Detected | Recall | Avg Risk |
|----------|-------|----------|--------|----------|
| BRUTE_FORCE_ACCESS | 625 | 625 | **100.0%** | 77.6 |
| PRIVILEGE_ESCALATION | 625 | 625 | **100.0%** | 76.3 |
| COMBINED_ATTACK | 625 | 625 | **100.0%** | 95.6 |
| REPEATED_ACCESS_FAILURE | 625 | 621 | 99.4% | 71.5 |
| OFF_HOURS_SENSITIVE_ACCESS | 625 | 597 | 95.5% | 61.9 |
| UNAUTHORIZED_ASSET_ACCESS | 625 | 587 | 93.9% | 70.1 |
| ABNORMAL_HIGH_FREQUENCY | 625 | 581 | 93.0% | 63.6 |
| SUSPICIOUS_THIRD_PARTY_WRITE | 625 | 492 | 78.7% | 57.4 |

### Detection Analysis

**High-Confidence Scenarios** (>99%):
- Multi-vector attacks (COMBINED_ATTACK, PRIVILEGE_ESCALATION, BRUTE_FORCE) are immediately flagged
- Extreme deviations (very high frequency, extreme failure rates) are easily distinguished

**Moderately Detected** (93–99%):
- Single strong signals (high frequency alone, failure rate alone, off-hours alone) are well detected
- Legitimate overlap is present but model separates them

**Challenging Scenario** (78.7%):
- **SUSPICIOUS_THIRD_PARTY_WRITE**: Shares distribution with legitimate third-party integrations
- Some events use business hours + reduced sensitivity + normal frequency, blending into the normal range
- This reflects realistic operational ambiguity in third-party access patterns

---

## Risk Score Calibration

### Mapping Formula
```
risk_score = clip(50.0 - (decision_score * 250.0), 0.0, 100.0)
```

Where:
- `decision_score`: Raw IsolationForest output (>0 inlier, <0 outlier)
- `risk_score`: Continuous index [0.0, 100.0]

### Risk Tiers
| Tier | Range | Interpretation |
|------|-------|---|
| **LOW** | 0.0–24.99 | Normal behavior, no immediate action |
| **MEDIUM** | 25.0–49.99 | Atypical but possibly legitimate, monitor |
| **HIGH** | 50.0–74.99 | Significant deviation, investigation recommended |
| **CRITICAL** | 75.0–100.0 | Severe anomaly, escalate immediately |

### Baseline Statistics (Trained on 20,000 normal events)
- Mean decision_score: 0.0531
- Median decision_score: 0.0557
- 1st percentile: -0.0841
- 5th percentile: -0.0687

---

## Inference Performance

### Latency Benchmark (1,000 iterations)
| Metric | Latency (ms) |
|--------|---|
| **Average** | 34.48 |
| **Median** | 33.75 |
| **95th Percentile** | 38.00 |
| **99th Percentile** | 43.83 |
| **Target** | <50.0 ✓ |

### Performance Characteristics
- Artifacts loaded once at module startup (no reload per prediction)
- Efficient single-row DataFrame construction
- Uses NumPy arrays for preprocessing
- Suitable for real-time event scoring in FastAPI backend
- No GPU required; standard CPU sufficient

---

## File Structure

```
ml/
├── data/
│   ├── dataset.csv                 # 30,000 events (train + test + synthetic anomalies)
│   └── feature_schema.json         # Feature definitions and metadata
├── models/
│   ├── isolation_forest.joblib     # Trained IsolationForest (300 estimators)
│   ├── preprocessor.joblib         # OneHotEncoder + StandardScaler
│   └── model_config.json           # Risk mapping, baseline stats, feature list
├── dataset_generator.py            # Generates dataset with realistic distributions
├── train_model.py                  # Trains IsolationForest on normal baseline
├── evaluate_model.py               # Evaluates on held-out normal + synthetic anomalies
├── predict.py                      # Inference + latency benchmarking module
└── README.md                       # This file
```

---

## How to Use

### 1. Generate Dataset
```bash
python ml/dataset_generator.py
```
Outputs:
- `ml/data/dataset.csv` – 30,000 event records
- `ml/data/feature_schema.json` – Feature schema

### 2. Train Model
```bash
python ml/train_model.py
```
Outputs:
- `ml/models/isolation_forest.joblib`
- `ml/models/preprocessor.joblib`
- `ml/models/model_config.json`

### 3. Evaluate Model
```bash
python ml/evaluate_model.py
```
Prints global + per-scenario metrics to console.

### 4. Benchmark Inference
```bash
python ml/predict.py
```
Runs 1,000 inference iterations and reports latency percentiles.

### 5. Production Inference
```python
from ml.predict import predict_event_risk

event = {
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

result = predict_event_risk(event)
print(result)
# Output: {
#     "anomaly_score": 0.147,
#     "risk_score": 13.25,
#     "risk_label": "LOW"
# }
```

### Reproduce Full Pipeline
```bash
python ml/dataset_generator.py && \
python ml/train_model.py && \
python ml/evaluate_model.py && \
python ml/predict.py
```

---

## Limitations & Future Work

### Current Limitations

1. **Synthetic-Only Evaluation**
   - Synthetic anomalies do NOT represent real-world attack distributions
   - Per-scenario detection rates (78–100%) are achieved on simulated patterns
   - Real attacks may follow different behavioral signatures

2. **No Concept Drift Handling**
   - Model trained on static 25,000 normal events
   - Legitimate business patterns may evolve over time
   - Retraining should occur periodically with updated baseline data

3. **Threshold Arbitrariness**
   - Risk tier boundaries (25, 50, 75) are initial application choices
   - Not empirically calibrated against real production incidents
   - Should be refined based on security team feedback

4. **Feature Engineering**
   - Rolling statistics (1h, 24h windows) are fixed in the dataset
   - Real feature extraction would depend on PostgreSQL query logic
   - Missing features: geographic anomalies, device fingerprinting, IP reputation

5. **False Positive Rate**
   - 19.7% FPR on synthetic evaluation
   - May be too high for high-volume platforms without tuning
   - Consider ensemble methods or domain-specific rule augmentation

### Future Enhancements

1. **Production Data Integration**
   - Retrain on real audit events once sufficient volume exists
   - Periodically update baseline to capture legitimate pattern evolution
   - Implement model versioning and A/B testing

2. **Threshold Calibration**
   - Collect security team feedback on flagged incidents
   - Use ROC curve or precision-recall analysis to tune tiers
   - Consider separate thresholds per role or asset tier

3. **Multi-Model Ensemble**
   - Combine IsolationForest with Local Outlier Factor (LOF) or DBSCAN
   - Reduce false positives via voting
   - Improve detection on edge-case attacks

4. **Explainability**
   - Add SHAP values to highlight which features drove anomaly flagging
   - Support security analyst investigation and tuning

5. **Real-Time Features**
   - Streaming feature computation from event indexer
   - Time-window aggregations over sliding windows
   - Integration with PostgreSQL for on-demand feature lookup

---

## Warnings & Important Notes

### ⚠ Evaluation Caveat
This model's performance metrics (95% recall, 83% precision) measure deviation detection on **simulated attack scenarios**. These synthetic scenarios are deliberately designed to represent diverse behavioral patterns but are not validated against real production incidents. **Do not assume these metrics predict real-world attack-detection accuracy.**

### ⚠ False Positive Management
A 19.7% false positive rate on synthetic evaluation may translate to operational overhead in high-volume platforms. The model will flag legitimate edge-case operations (e.g., admin bulk imports, legitimate third-party integrations) as suspicious. Plan for analyst review workflows or consider ensemble/rule-based refinement.

### ⚠ Model Drift
Once deployed, the model's baseline will gradually diverge from evolving legitimate behavior patterns. Establish:
- Retraining schedules (quarterly or semi-annually)
- Monitoring of flagged event distributions
- Security team feedback loops for threshold tuning

---

## Contact & Support

For integration with the FastAPI backend or questions about this ML component, refer to the main LexCorp Blockchain Risk Engine documentation.

---

**Generated**: 2026-09-05
**Model**: Unsupervised Isolation Forest
**Status**: Phase 1 Complete – Ready for FastAPI Integration
