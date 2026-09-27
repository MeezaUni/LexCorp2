"""Behavioural features for LexCorp's local risk model: ONE implementation, used by the
simulator, training, evaluation and the live app, so the model never sees features computed
one way in training and another way in production (the flaw of the previous model).

An Event is one thing a person did (or tried to do). Features for an event are computed
from that event plus the same person's EARLIER events only (a per-person history), so every
feature is available at the moment the event happens.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, List, Optional

# What a person did. Live audit events are mapped onto these (see app.services.risk.live).
KINDS = (
    "LOGIN", "LOGIN_FAILED", "STEP_UP_FAILED", "ACCESS_DENIED",
    "VIEW", "DOWNLOAD_REQUEST", "DOWNLOAD", "MOD_COPY", "REVISION",
    "REGISTER", "APPROVE", "DELEGATE", "TAMPER", "DUPLICATE",
)
FAILURE_KINDS = {"LOGIN_FAILED", "STEP_UP_FAILED", "ACCESS_DENIED"}
READ_KINDS = {"VIEW"}
COPY_KINDS = {"DOWNLOAD", "MOD_COPY"}
WRITE_KINDS = {"REVISION", "REGISTER", "APPROVE", "DELEGATE", "MOD_COPY"}
PRIVILEGED_KINDS = {"APPROVE", "REGISTER", "DELEGATE"}
ROLES = ("USER", "MANAGER", "AUDITOR", "ADMIN")
TYPICAL_HOUR = {"USER": 12.5, "MANAGER": 12.5, "AUDITOR": 12.5, "ADMIN": 12.5}

HISTORY_DAYS = 30


@dataclass
class Event:
    ts: datetime                    # timezone-aware UTC (or consistently naive)
    actor: str                      # stable person id (DID in the live app)
    role: str                       # USER / MANAGER / AUDITOR / ADMIN
    dept: Optional[str]
    kind: str                       # one of KINDS
    asset: Optional[str] = None     # document / asset serial
    asset_dept: Optional[str] = None
    asset_owner: Optional[str] = None
    sensitivity: int = 1            # 0 public, 1 internal, 2 confidential
    ip: Optional[str] = None
    ok: bool = True                 # False for refused / failed attempts
    local_hour: Optional[float] = None  # hour in the organisation's time zone (defaults to ts.hour)


def _hour(e: Event) -> float:
    return e.local_hour if e.local_hour is not None else e.ts.hour + e.ts.minute / 60.0


def _circ_dist(a: float, b: float) -> float:
    d = abs(a - b) % 24.0
    return min(d, 24.0 - d)


# Order matters: it is the model's input order. Keep in sync with FEATURE_TEXT below.
FEATURES: List[str] = [
    "hour_sin", "hour_cos", "is_weekend", "is_off_hours", "hour_deviation",
    "events_1h", "events_24h", "volume_ratio_24h",
    "views_24h", "copies_24h", "copy_share_24h",
    "distinct_assets_24h", "new_assets_24h",
    "out_of_dept_share_24h", "not_owned_share_24h",
    "failures_1h", "failures_24h", "failure_share_24h",
    "new_ip", "distinct_ips_24h", "log_secs_since_last",
    "is_write", "is_copy", "is_privileged", "is_failure", "sensitivity",
    "tampers_30d", "duplicates_30d",
    "role_user", "role_manager", "role_auditor", "role_admin",
]

# How each feature is explained to an Auditor (value, usual) -> text.
FEATURE_TEXT = {
    "is_off_hours": lambda v, u: "outside working hours" if v >= 0.5 else None,
    "is_weekend": lambda v, u: "at the weekend" if v >= 0.5 else None,
    "hour_deviation": lambda v, u: f"about {v:.0f} h away from this person's usual working time",
    "events_1h": lambda v, u: f"{v:.0f} actions in the last hour (usual about {u:.0f})",
    "events_24h": lambda v, u: f"{v:.0f} actions in the last 24 h (usual about {u:.0f})",
    "volume_ratio_24h": lambda v, u: f"{v:.1f}x this person's normal daily volume",
    "copies_24h": lambda v, u: f"{v:.0f} downloads/copies in the last 24 h (usual about {u:.0f})",
    "copy_share_24h": lambda v, u: f"{v * 100:.0f}% of recent actions were downloads/copies",
    "distinct_assets_24h": lambda v, u: f"{v:.0f} different documents touched in 24 h (usual about {u:.0f})",
    "new_assets_24h": lambda v, u: f"{v:.0f} documents never touched before, in 24 h",
    "out_of_dept_share_24h": lambda v, u: f"{v * 100:.0f}% of recent actions on other departments' documents",
    "not_owned_share_24h": lambda v, u: f"{v * 100:.0f}% of recent actions on documents owned by others",
    "failures_1h": lambda v, u: f"{v:.0f} refused or failed attempts in the last hour",
    "failures_24h": lambda v, u: f"{v:.0f} refused or failed attempts in 24 h",
    "failure_share_24h": lambda v, u: f"{v * 100:.0f}% of recent attempts refused or failed",
    "new_ip": lambda v, u: "from a network address not seen for this person in 30 days" if v >= 0.5 else None,
    "distinct_ips_24h": lambda v, u: f"{v:.0f} different network addresses in 24 h",
    "log_secs_since_last": lambda v, u: None,
    "is_privileged": lambda v, u: "a privileged action (approve / register / delegate)" if v >= 0.5 else None,
    "is_failure": lambda v, u: "the attempt was refused or failed" if v >= 0.5 else None,
    "tampers_30d": lambda v, u: f"{v:.0f} watermark tamper flag(s) in 7 days",
    "duplicates_30d": lambda v, u: f"{v:.0f} duplicate registration attempt(s) in 7 days",
}


@dataclass
class PersonHistory:
    """One person's events in the last HISTORY_DAYS, oldest first."""
    events: Deque[Event] = field(default_factory=deque)

    def add(self, e: Event) -> None:
        self.events.append(e)
        cutoff = e.ts - timedelta(days=HISTORY_DAYS)
        while self.events and self.events[0].ts < cutoff:
            self.events.popleft()


def features_for(e: Event, history: Iterable[Event]) -> Dict[str, float]:
    """Features of event `e` given the SAME person's earlier events (any order; later ones ignored)."""
    past = [p for p in history if p.ts < e.ts and p.ts >= e.ts - timedelta(days=HISTORY_DAYS)]
    h1 = [p for p in past if p.ts >= e.ts - timedelta(hours=1)]
    h24 = [p for p in past if p.ts >= e.ts - timedelta(hours=24)]
    older = [p for p in past if p.ts < e.ts - timedelta(hours=24)]
    win = h24 + [e]                               # the last 24 h including this event

    hour = _hour(e)
    work_hours = [_hour(p) for p in past if p.kind not in FAILURE_KINDS]
    if len(work_hours) >= 5:
        # typical time = circular mean of this person's own activity
        s = sum(math.sin(2 * math.pi * x / 24) for x in work_hours)
        c = sum(math.cos(2 * math.pi * x / 24) for x in work_hours)
        typical = (math.atan2(s, c) * 24 / (2 * math.pi)) % 24
    else:
        typical = TYPICAL_HOUR.get(e.role, 12.5)

    first = min((p.ts for p in past), default=None)
    days_seen = max(1.0, min(float(HISTORY_DAYS), (e.ts - first).total_seconds() / 86400.0)) if first else 1.0
    usual_daily = len(older) / max(1.0, days_seen - 1.0) if older else 0.0

    copies = [p for p in win if p.kind in COPY_KINDS]
    assets_24h = {p.asset for p in win if p.asset}
    seen_before = {p.asset for p in older if p.asset}
    with_asset = [p for p in win if p.asset]
    failures_24h = [p for p in win if p.kind in FAILURE_KINDS or not p.ok]
    ips_before = {p.ip for p in past if p.ip and p.ts < e.ts - timedelta(hours=1)}
    last = max((p.ts for p in past), default=None)

    return {
        "hour_sin": math.sin(2 * math.pi * hour / 24),
        "hour_cos": math.cos(2 * math.pi * hour / 24),
        "is_weekend": 1.0 if e.ts.weekday() >= 5 else 0.0,
        "is_off_hours": 1.0 if (hour < 7 or hour >= 20) else 0.0,
        "hour_deviation": _circ_dist(hour, typical),
        "events_1h": float(len(h1) + 1),
        "events_24h": float(len(win)),
        "volume_ratio_24h": len(win) / (usual_daily + 1.0),
        "views_24h": float(sum(1 for p in win if p.kind in READ_KINDS)),
        "copies_24h": float(len(copies)),
        "copy_share_24h": len(copies) / len(win),
        "distinct_assets_24h": float(len(assets_24h)),
        "new_assets_24h": float(len(assets_24h - seen_before)),
        "out_of_dept_share_24h": (sum(1 for p in with_asset if p.asset_dept and p.dept and p.asset_dept != p.dept)
                                  / len(with_asset)) if with_asset else 0.0,
        "not_owned_share_24h": (sum(1 for p in with_asset if p.asset_owner and p.asset_owner != p.actor)
                                / len(with_asset)) if with_asset else 0.0,
        "failures_1h": float(sum(1 for p in h1 + [e] if p.kind in FAILURE_KINDS or not p.ok)),
        "failures_24h": float(len(failures_24h)),
        "failure_share_24h": len(failures_24h) / len(win),
        "new_ip": 1.0 if (e.ip and ips_before and e.ip not in ips_before) else 0.0,
        "distinct_ips_24h": float(len({p.ip for p in win if p.ip})),
        "log_secs_since_last": math.log1p((e.ts - last).total_seconds()) if last else math.log1p(30 * 86400),
        "is_write": 1.0 if e.kind in WRITE_KINDS else 0.0,
        "is_copy": 1.0 if e.kind in COPY_KINDS else 0.0,
        "is_privileged": 1.0 if e.kind in PRIVILEGED_KINDS else 0.0,
        "is_failure": 1.0 if (e.kind in FAILURE_KINDS or not e.ok) else 0.0,
        "sensitivity": float(e.sensitivity),
        # incident counts look back a week: long enough to connect a pattern, short enough that one
        # handled incident doesn't flag the person's ordinary work for a month
        "tampers_30d": float(sum(1 for p in past + [e] if p.kind == "TAMPER" and p.ts >= e.ts - timedelta(days=7))),
        "duplicates_30d": float(sum(1 for p in past + [e] if p.kind == "DUPLICATE" and p.ts >= e.ts - timedelta(days=7))),
        "role_user": 1.0 if e.role == "USER" else 0.0,
        "role_manager": 1.0 if e.role == "MANAGER" else 0.0,
        "role_auditor": 1.0 if e.role == "AUDITOR" else 0.0,
        "role_admin": 1.0 if e.role == "ADMIN" else 0.0,
    }


def vector(feats: Dict[str, float]) -> List[float]:
    return [float(feats[name]) for name in FEATURES]


def stream_features(events: Iterable[Event]):
    """Yield (event, features) for a time-ordered stream of many people's events."""
    people: Dict[str, PersonHistory] = {}
    for e in events:
        h = people.setdefault(e.actor, PersonHistory())
        yield e, features_for(e, h.events)
        h.add(e)


def kind_counts(events: Iterable[Event]) -> Counter:
    return Counter(e.kind for e in events)
