"""
AI Risk Engine — Backend wrapper around the V1 production model.

Architecture:
- Models live under `app/services/ai_engine/models/` (isolation_forest.joblib, preprocessor.joblib, model_config.json).
- The `predict_event_risk` function is loaded once at import time (Load Once, Predict Often).
- `AIRiskEngine` provides a FastAPI-friendly interface that:
  * Builds real-time features from blockchain events
  * Caches per-actor behavioral statistics (rolling failure rate, event frequency, time elapsed)
  * Calls the model and returns the risk assessment.

No cloud APIs are used—this ensures an air-gapped, zero-trust deployment.
"""

import logging
import os
import time
from collections import deque
from typing import Any, Dict, Optional

from app.services.ai_engine.predict import predict_event_risk, get_risk_label

logger = logging.getLogger(__name__)


# Mapping of blockchain event types to the model's expected categorical labels.
_EVENT_TYPE_MAP = {
    "AssetMinted": "AssetMinted",
    "DigitalAssetMinted": "AssetMinted",
    "DigitalAssetUpdated": "AssetUpdated",
    "AssetTransferred": "AssetTransferred",
    "AssetRevoked": "AssetRevoked",
    "AccessPermissionGranted": "RoleAssigned",
    "AccessPermissionRevoked": "RoleRevoked",
    "AccessAttempted": "AccessAttempted",
}

# Mapping of on-chain permission levels + system roles to the "actor_to_asset_relationship_depth" feature.
# 0 = direct owner, 1 = manager/admin, 2 = 3rd-party, 3 = unauthorized/unrelated
def _rel_depth(actor_did: Optional[str], owner_did: Optional[str], actor_role: str) -> int:
    if actor_did and owner_did and actor_did.lower() == owner_did.lower():
        return 0
    if actor_role in ("ADMIN", "MANAGER"):
        return 1
    if actor_role == "AUDITOR":
        return 2
    return 3


class _ActorCache:
    """In-memory rolling window of an actor's recent activity for behavioral features."""

    def __init__(self, max_actors: int = 1000):
        self._events: Dict[str, deque] = {}
        self._max_actors = max_actors

    def record(self, actor_did: str, event_type: str, granted: bool, ts: float) -> None:
        if not actor_did:
            return
        if actor_did not in self._events:
            if len(self._events) >= self._max_actors:
                # Evict the oldest actor (FIFO) to bound memory.
                evict_key = next(iter(self._events))
                self._events.pop(evict_key, None)
            self._events[actor_did] = deque()
        self._events[actor_did].append((ts, event_type, granted))

    def stats(self, actor_did: Optional[str], now_ts: float) -> Dict[str, float]:
        if not actor_did or actor_did not in self._events:
            return {
                "rolling_event_frequency_1h": 0,
                "rolling_failure_rate_24h": 0.0,
                "time_elapsed_from_last_tx": 86400.0,  # Default: 1 day (treat as "first time")
            }
        dq = self._events[actor_did]
        # 1h window
        h_ago = now_ts - 3600.0
        freq_1h = sum(1 for (t, _, _) in dq if t >= h_ago)
        # 24h window failure rate
        d_ago = now_ts - 86400.0
        last24 = [(et, g) for (t, et, g) in dq if t >= d_ago]
        if last24:
            failures = sum(1 for (_, g) in last24 if not g)
            fail_rate = failures / float(len(last24))
        else:
            fail_rate = 0.0
        # Time elapsed from last tx
        last_ts = dq[-1][0] if dq else now_ts
        return {
            "rolling_event_frequency_1h": int(freq_1h),
            "rolling_failure_rate_24h": float(fail_rate),
            "time_elapsed_from_last_tx": float(max(0.0, now_ts - last_ts)),
        }


class AIRiskEngine:
    """Wrapper that bridges the blockchain event indexer and the trained ML model."""

    def __init__(self):
        self._cache = _ActorCache()
        self._model_loaded = self._check_model_loaded()
        if not self._model_loaded:
            logger.warning(
                "AI Risk Engine model artifacts not found. "
                "Risk scoring will return N/A until the model is available."
            )

    @staticmethod
    def _check_model_loaded() -> bool:
        try:
            from app.services.ai_engine import predict as _p
            return _p._MODEL is not None and _p._PREPROCESSOR is not None  # type: ignore[attr-defined]
        except Exception:
            return False

    def record_event(
        self,
        actor_did: Optional[str],
        event_type: str,
        granted: bool = True,
    ) -> None:
        """Push the event into the rolling actor cache for future feature computation."""
        self._cache.record(actor_did or "", event_type, granted, time.time())

    def _build_features(
        self,
        event_type: str,
        actor_role: str,
        actor_did: Optional[str],
        target_did: Optional[str],
        is_write: bool,
        asset_sensitivity_tier: int,
    ) -> Dict[str, Any]:
        # Time features
        now = time.time()
        dt = time.localtime(now)
        access_hour = dt.tm_hour
        is_weekend = 1 if dt.tm_wday >= 5 else 0

        # Behavioral stats from cache
        stats = self._cache.stats(actor_did, now)

        # Role escalation index: 0.0 if user is doing allowed action; positive when a USER attempts a write.
        if actor_role == "USER" and is_write:
            role_escalation_index = 1.0
        elif actor_role == "AUDITOR" and is_write:
            role_escalation_index = 0.5
        else:
            role_escalation_index = 0.0

        return {
            "access_hour": int(access_hour),
            "is_weekend": int(is_weekend),
            "time_elapsed_from_last_tx": float(stats["time_elapsed_from_last_tx"]),
            "role_escalation_index": float(role_escalation_index),
            "rolling_event_frequency_1h": int(stats["rolling_event_frequency_1h"]),
            "rolling_failure_rate_24h": float(stats["rolling_failure_rate_24h"]),
            "asset_sensitivity_tier": int(asset_sensitivity_tier),
            "is_write_operation": int(1 if is_write else 0),
            "actor_to_asset_relationship_depth": int(_rel_depth(actor_did, target_did, actor_role)),
            "user_role": str(actor_role if actor_role in ("USER", "MANAGER", "ADMIN", "AUDITOR") else "USER"),
            "event_type": _EVENT_TYPE_MAP.get(event_type, "AccessAttempted"),
        }

    def analyze_event(
        self,
        event_type: str,
        actor_role: str = "USER",
        actor_did: Optional[str] = None,
        target_did: Optional[str] = None,
        is_write: bool = False,
        asset_sensitivity_tier: int = 0,
    ) -> Dict[str, Any]:
        """
        Score a single blockchain event.

        Returns:
            dict with keys: risk_score (0-100), risk_label ("LOW"/"MEDIUM"/"HIGH"/"CRITICAL"),
            anomaly_score (raw IsolationForest decision), and model_loaded (bool).
        """
        features = self._build_features(
            event_type=event_type,
            actor_role=actor_role,
            actor_did=actor_did,
            target_did=target_did,
            is_write=is_write,
            asset_sensitivity_tier=asset_sensitivity_tier,
        )
        if not self._model_loaded:
            return {
                "risk_score": None,
                "risk_label": "UNKNOWN",
                "anomaly_score": None,
                "model_loaded": False,
                "features": features,
            }
        try:
            result = predict_event_risk(features)
            # Record into the cache for future rolling stats (granted inferred by is_write=False read access).
            granted = (event_type not in ("AccessAttempted",)) or (not is_write)
            self.record_event(actor_did, event_type, granted=granted)
            return {
                "risk_score": result["risk_score"],
                "risk_label": result["risk_label"],
                "anomaly_score": result["anomaly_score"],
                "model_loaded": True,
                "features": features,
            }
        except Exception as e:
            logger.error(f"AI Risk Engine inference failed: {e}")
            return {
                "risk_score": None,
                "risk_label": "ERROR",
                "anomaly_score": None,
                "model_loaded": True,
                "features": features,
                "error": str(e),
            }


# Singleton
ai_engine = AIRiskEngine()


async def check_actor_risk_level(actor_did: str, db) -> dict:
    """
    Check actor's recent risk history to determine if they should be blocked from sensitive operations.

    Args:
        actor_did: W3C DID of the actor (e.g., did:ethr:13371:0x...)
        db: Async database session

    Returns:
        dict with keys:
        - is_high_risk: bool (True if actor should be blocked)
        - recent_high_count: int (number of HIGH risk events in last 24h)
        - last_high_event: dict or None (most recent HIGH risk event details)
        - reason: str (human-readable explanation)
    """
    from sqlalchemy import select, desc
    from app.models.domain import AuditEvent
    from datetime import datetime, timedelta

    if not actor_did:
        return {
            "is_high_risk": False,
            "recent_high_count": 0,
            "last_high_event": None,
            "reason": "No actor DID provided"
        }

    try:
        # Query recent events for this actor (last 24 hours)
        cutoff_time = datetime.utcnow() - timedelta(hours=24)

        result = await db.execute(
            select(AuditEvent)
            .filter(AuditEvent.actor_did == actor_did)
            .filter(AuditEvent.created_at >= cutoff_time)
            .order_by(desc(AuditEvent.created_at))
            .limit(20)
        )
        recent_events = result.scalars().all()

        if not recent_events:
            return {
                "is_high_risk": False,
                "recent_high_count": 0,
                "last_high_event": None,
                "reason": "No recent activity"
            }

        # Count HIGH and CRITICAL risk events
        high_risk_events = [e for e in recent_events if e.risk_label in ("HIGH", "CRITICAL")]
        high_count = len(high_risk_events)

        # Determine if actor should be blocked
        # Policy: Block if >= 2 HIGH/CRITICAL events in last 24h OR if last event was HIGH/CRITICAL
        last_event = recent_events[0] if recent_events else None
        is_high_risk = False
        reason = "Normal activity pattern"

        if high_count >= 2:
            is_high_risk = True
            reason = f"Multiple high-risk events detected ({high_count} in last 24h)"
        elif last_event and last_event.risk_label in ("HIGH", "CRITICAL"):
            is_high_risk = True
            reason = f"Most recent activity flagged as {last_event.risk_label} risk"

        last_high_event = None
        if high_risk_events:
            evt = high_risk_events[0]
            last_high_event = {
                "event_type": evt.event_type,
                "risk_label": evt.risk_label,
                "risk_score": evt.risk_score,
                "timestamp": evt.created_at.isoformat() if evt.created_at else None,
                "asset_serial": evt.asset_serial
            }

        return {
            "is_high_risk": is_high_risk,
            "recent_high_count": high_count,
            "last_high_event": last_high_event,
            "reason": reason
        }

    except Exception as e:
        logger.error(f"Error checking actor risk level: {e}")
        # Fail open for now to avoid blocking legitimate operations due to errors
        return {
            "is_high_risk": False,
            "recent_high_count": 0,
            "last_high_event": None,
            "reason": f"Error checking risk: {str(e)}"
        }
