"""
Local AI Risk Engine for Anomaly Detection (Enhanced)
Trains a more sophisticated IsolationForest on realistic blockchain behavior data
to score the risk of on-chain transactions (mint, transfer, revoke).
"""

import os
import joblib
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from datetime import datetime as dt

logger = logging.getLogger(__name__)

# Constants
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml_models")
MODEL_FILE = os.path.join(MODEL_PATH, "isolation_forest.pkl")

class AIRiskEngine:
    def __init__(self):
        self.model = None

    def _ensure_model_directory(self):
        if not os.path.exists(MODEL_PATH):
            os.makedirs(MODEL_PATH, exist_ok=True)

    def generate_synthetic_data(self) -> pd.DataFrame:
        """Generate realistic synthetic transaction behavior data for ML training."""
        np.random.seed(42)
        n_samples = 1000

        # Time-based features (simulate real-world patterns)
        now = datetime.now()
        hour_of_day = now.hour
        is_business_hour = 8 <= hour_of_day <= 18

        # Normal behavior (Low Risk)
        # - Typical transaction volumes during business hours
        # - Moderate transaction amounts
        # - Normal transfer frequency
        normal_tx_amounts = np.random.normal(loc=1.5, scale=0.5, size=int(n_samples * 0.95))
        normal_tx_frequency = np.random.normal(loc=3, scale=1, size=int(n_samples * 0.95))
        normal_is_business_hour = np.random.choice([True, False], size=int(n_samples * 0.95), p=[0.8, 0.2])

        # Anomalous behavior (High Risk)
        # - High volume transactions outside business hours
        # - Rapid, high-value transfers
        anomaly_tx_amounts = np.random.normal(loc=8, scale=2, size=int(n_samples * 0.05))
        anomaly_tx_frequency = np.random.normal(loc=18, scale=3, size=int(n_samples * 0.05))
        anomaly_is_business_hour = np.random.choice([False], size=int(n_samples * 0.05))  # Only anomaly outside business hours

        # Combine data
        amounts = np.concatenate([
            np.random.choice(normal_tx_amounts, int(n_samples * 0.95)),
            np.random.choice(anomaly_tx_amounts, int(n_samples * 0.05))
        ]
        frequencies = np.concatenate([
            np.random.choice(normal_tx_frequency, int(n_samples * 0.95)),
            np.random.choice(anomaly_tx_frequency, int(n_samples * 0.05))
        ]

        # Add time-of-day context
        hour_flags = np.random.choice([0, 1], size=len(amounts), p=[0.8, 0.2])  # 0=off-hours, 1=business hours
        is_business_hour = np.where(anomaly_tx_frequency > 10, False, np.random.choice([True, False], size=len(amounts), p=[0.8, 0.2]))

        df = pd.DataFrame({
            'tx_amount': amounts,
            'tx_frequency': frequencies,
            'is_business_hour': is_business_hour,
            'hour_of_day': hour_of_day,
            'is_anomalous_time': ~is_business_hour
        })

        # Clamp values to realistic ranges
        df['tx_amount'] = df['tx_amount'].clip(lower=0.1, upper=50.0)
        df['tx_frequency'] = df['tx_frequency'].clip(lower=0.1, upper=30.0)

        return df

    def train_and_save_model(self):
        """Train IsolationForest on synthetic data and persist the model."""
        self._ensure_model_directory()

        logger.info("Generating synthetic data for AI Risk Engine...")
        df = self.generate_synthetic_data()

        logger.info("Training IsolationForest model...")
        model = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            random_state=42,
            max_samples=0.8
        )
        model.fit(df)

        MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml_models")
        MODEL_FILE = os.path.join(MODEL_PATH, "isolation_forest.pkl")
        joblib.dump(model, MODEL_FILE)
        self.model = model
        logger.info(f"Model saved to {MODEL_FILE}")

    def load_model(self):
        """Load the trained ML model from disk."""
        if not os.path.exists(MODEL_FILE):
            logger.info("No existing ML model found, initiating training...")
            self.train_and_save_model()
        else:
            self.model = joblib.load(MODEL_FILE)
            logger.info("Loaded AI Risk Engine model from disk.")

    def analyze_transaction(self, tx_amount: float, tx_frequency: float, tx_timestamp: str = None) -> dict:
        """Analyze a real-time transaction event and return risk score and label."""
        if not self.model:
            self.load_model()

        # Use timestamp for time-based features if available
        if tx_timestamp:
            try:
                dt = dt.fromisoformat(tx_timestamp.replace('Z', '+00:00'))
                hour_of_day = dt.hour
                is_business_hour = 8 <= hour_of_day <= 18
            except:
                hour_of_day = None
                is_business_hour = False
        else:
            hour_of_day = None
            is_business_hour = False

        # Create feature vector with time context
        features = pd.DataFrame({
            'tx_amount': [tx_amount],
            'tx_frequency': [tx_frequency],
            'hour_of_day': [hour_of_day],
            'is_business_hour': [is_business_hour],
        )

        # -1 for outliers, 1 for inliers
        prediction = self.model.predict(features)[0]
        raw_score = self.model.decision_function(features)[0]

        # Normalize risk to 0-1 scale (0 = safe, 1 = high risk)
        normalized_risk = max(0.0, min(1.0, 0.5 - raw_score))

        if normalized_risk > 0.7 or prediction == -1:
            label = "HIGH"
        elif normalized_risk > 0.4:
            label = "MEDIUM"
        else:
            label = "LOW"

        return {
            "risk_score": float(round(normalized_risk, 3)),
            "risk_label": str(label),
            "raw_score": float(round(raw_score, 3)),
            "normalized_risk": normalized_risk
        }

# Singleton instance
ai_engine = AIRiskEngine()
