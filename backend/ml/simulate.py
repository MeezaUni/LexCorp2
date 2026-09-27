"""Simulate months of LexCorp activity, with labelled misuse, for training and evaluation.

    cd backend
    python ml/simulate.py                       # defaults: 3 organisations (~80 people each), 120 days -> ml/data/
    python ml/simulate.py --people 150 --days 180 --seed 11

The organisation: departments, people with their own working hours, workload, documents
and network addresses, and ordinary messiness (busy days, late evenings, typos in codes,
travel, weekend work, occasional cross-department work). Into that, ATTACK SCENARIOS are
injected and labelled (see SCENARIOS). Features are computed with the same code the live
app uses (app.services.risk.features), so the trained model sees exactly what production
will show it.

Output: ml/data/events.csv (raw events) and ml/data/features.csv (features + label +
scenario + attack id + split). The first 70 % of days are "train", the rest "test".
This is synthetic data: it tests whether the method catches these patterns, not how it
performs on a real organisation. Retrain on real activity and Auditor feedback over time.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import random
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.risk.features import FEATURES, Event, stream_features  # noqa: E402

DEPARTMENTS = ["Avionics", "Radar Systems", "Cyber Security", "Manufacturing", "Quality Assurance"]
KIND_MIX = {
    "USER": {"VIEW": 0.70, "DOWNLOAD": 0.07, "MOD_COPY": 0.02, "REGISTER": 0.04, "DELEGATE": 0.02, "DOWNLOAD_REQUEST": 0.04,
             "ACCESS_DENIED": 0.02, "_REVISE": 0.02, "LOGIN": 0.07},
    "MANAGER": {"VIEW": 0.46, "APPROVE": 0.20, "REGISTER": 0.08, "DOWNLOAD": 0.07, "DELEGATE": 0.05, "MOD_COPY": 0.03,
                "_REVISE": 0.03, "ACCESS_DENIED": 0.01, "LOGIN": 0.07},
    "AUDITOR": {"VIEW": 0.86, "ACCESS_DENIED": 0.02, "LOGIN": 0.12},
    "ADMIN": {"APPROVE": 0.25, "REGISTER": 0.10, "DELEGATE": 0.10, "VIEW": 0.40, "DOWNLOAD": 0.05, "ACCESS_DENIED": 0.01,
              "LOGIN": 0.09},
}
DAILY_RATE = {"USER": 12, "MANAGER": 20, "AUDITOR": 15, "ADMIN": 10}

# name: (description, difficulty)
SCENARIOS = {
    "exfil_burst": ("many distinct documents downloaded within 1-3 hours", "easy"),
    "off_hours_exfil": ("downloads and views between 23:00 and 04:00", "easy"),
    "dept_sweep": ("browsing many other departments' documents, some refused", "medium"),
    "factor_bruteforce": ("a burst of failed sign-ins / factor codes from a new address", "easy"),
    "account_takeover": ("sign-in from a new address at an odd hour, then downloads", "medium"),
    "limit_probing": ("repeated refused views of the same few documents", "medium"),
    "tamper_return": ("a modification copy returned with its watermark altered", "easy"),
    "privilege_probe": ("a user repeatedly attempting approvals they are not allowed", "medium"),
    "slow_exfil": ("2-4x the person's usual downloads, spread over a week of working hours", "hard"),
    "duplicate_spree": ("several duplicate physical asset registrations", "medium"),
}


@dataclass
class Person:
    pid: str
    role: str
    dept: str
    start: float
    length: float
    rate: float
    weekend_worker: bool
    night_shift: bool
    ip: str
    working_set: List[str] = field(default_factory=list)
    own_docs: List[str] = field(default_factory=list)


@dataclass
class Doc:
    serial: str
    dept: str
    owner: str
    sensitivity: int


class World:
    def __init__(self, people: int, rng: random.Random, prefix: str = "did:sim"):
        self.rng = rng
        self.people: List[Person] = []
        roles = ["ADMIN"] * max(2, round(people * 0.03)) + ["AUDITOR"] * max(3, round(people * 0.05))
        roles += ["MANAGER"] * max(len(DEPARTMENTS), round(people * 0.12))
        roles += ["USER"] * max(0, people - len(roles))
        for i, role in enumerate(roles):
            dept = DEPARTMENTS[i % len(DEPARTMENTS)] if role in ("MANAGER", "USER") else "Cyber Security"
            night = rng.random() < 0.03 and role == "USER"
            start = 21.0 if night else min(11.0, max(7.0, rng.gauss(9.0, 0.7)))
            self.people.append(Person(
                pid=f"{prefix}:{i:04d}", role=role, dept=dept, start=start, length=max(6.0, rng.gauss(8.5, 0.8)),
                rate=DAILY_RATE[role] * math.exp(rng.gauss(0, 0.35)), weekend_worker=rng.random() < 0.08,
                night_shift=night, ip=f"10.20.{DEPARTMENTS.index(dept)}.{10 + i % 240}"))
        self.docs: List[Doc] = []
        owners = [p for p in self.people if p.role in ("USER", "MANAGER")]
        for n in range(max(200, people * 8)):
            o = rng.choice(owners)
            d = Doc(f"DOC-{prefix[-2:]}-{o.dept[:3].upper()}-{n:05d}", o.dept, o.pid, 2 if rng.random() < 0.8 else 1)
            self.docs.append(d)
            o.own_docs.append(d.serial)
        self.by_serial = {d.serial: d for d in self.docs}
        by_dept = {dep: [d.serial for d in self.docs if d.dept == dep] for dep in DEPARTMENTS}
        for p in self.people:
            pool = by_dept.get(p.dept) or [d.serial for d in self.docs]
            p.working_set = list(set(p.own_docs + rng.sample(pool, min(len(pool), rng.randint(10, 30)))))
            if rng.random() < 0.3:  # some delegated cross-department documents
                p.working_set += rng.sample([d.serial for d in self.docs], 3)

    def event(self, p: Person, ts: datetime, kind: str, asset: Optional[str] = None, ip: Optional[str] = None,
              ok: bool = True, scenario: str = "", attack_id: str = "") -> dict:
        d = self.by_serial.get(asset) if asset else None
        return {"event": Event(ts=ts, actor=p.pid, role=p.role, dept=p.dept, kind=kind, asset=asset,
                               asset_dept=d.dept if d else None, asset_owner=d.owner if d else None,
                               sensitivity=d.sensitivity if d else 1, ip=ip or p.ip, ok=ok),
                "label": 1 if scenario else 0, "scenario": scenario, "attack_id": attack_id}

    # ------------------------------------------------------------------ ordinary days
    def normal_day(self, p: Person, day: datetime) -> List[dict]:
        rng = self.rng
        weekend = day.weekday() >= 5
        if weekend and not (p.weekend_worker and rng.random() < 0.5) and rng.random() > 0.03:
            return []
        if not weekend and rng.random() < 0.08:          # leave, training, sick day
            return []
        busy = 2.0 if rng.random() < 0.1 else 1.0
        late = rng.uniform(1.5, 3.0) if rng.random() < 0.05 else 0.0
        n = max(1, int(rng.gauss(p.rate * busy * (0.5 if weekend else 1.0), p.rate * 0.25)))
        ip = p.ip if rng.random() > 0.05 else f"10.99.{rng.randint(0, 20)}.{rng.randint(2, 250)}"  # VPN / travel
        out = []

        def at(hour: float) -> datetime:
            return day + timedelta(hours=hour)

        login = p.start + rng.uniform(-0.3, 0.4)
        if rng.random() < 0.03:
            out.append(self.event(p, at(login - 0.02), "LOGIN_FAILED", ip=ip, ok=False))
        out.append(self.event(p, at(login), "LOGIN", ip=ip))
        mix = KIND_MIX[p.role]
        kinds, weights = list(mix), list(mix.values())
        hours = sorted(rng.uniform(login + 0.05, p.start + p.length + late) for _ in range(n))
        for h in hours:
            kind = rng.choices(kinds, weights)[0]
            asset = rng.choice(p.working_set) if rng.random() > (0.08 if p.role == "MANAGER" else 0.03) \
                else rng.choice(self.docs).serial
            if kind in ("LOGIN",):
                out.append(self.event(p, at(h), "LOGIN", ip=ip))
                continue
            if kind == "_REVISE":                     # a modification copy, then its revision later that day
                out.append(self.event(p, at(h), "MOD_COPY", asset, ip))
                out.append(self.event(p, at(min(h + rng.uniform(0.5, 3), 23.9)), "REVISION", asset, ip))
                continue
            if kind in ("DOWNLOAD", "MOD_COPY", "APPROVE", "REGISTER", "DELEGATE") and rng.random() < 0.02:
                out.append(self.event(p, at(h - 0.01), "STEP_UP_FAILED", asset, ip, ok=False))   # mistyped code
            out.append(self.event(p, at(h), kind, asset if kind not in ("REGISTER",) else f"NEW-{p.pid}-{h:.3f}", ip,
                                  ok=kind != "ACCESS_DENIED"))
        return out

    # ------------------------------------------------------------------ misuse
    def attack(self, name: str, day: datetime, attack_id: str) -> List[dict]:
        rng = self.rng
        users = [p for p in self.people if p.role == "USER"]
        managers = [p for p in self.people if p.role == "MANAGER"]
        p = rng.choice(managers if name == "duplicate_spree" else users)
        ev = lambda ts, kind, asset=None, ip=None, ok=True: self.event(p, ts, kind, asset, ip, ok, name, attack_id)  # noqa: E731
        work = day + timedelta(hours=p.start + rng.uniform(1, max(1.5, p.length - 3)))
        other = [d.serial for d in self.docs if d.dept != p.dept]
        out = []
        if name == "exfil_burst":
            for t, s in zip(sorted(rng.uniform(0, rng.uniform(1, 3)) for _ in range(rng.randint(15, 40))),
                            rng.sample([d.serial for d in self.docs], 40)):
                out.append(ev(work + timedelta(hours=t), rng.choice(["DOWNLOAD", "DOWNLOAD", "VIEW"]), s))
        elif name == "off_hours_exfil":
            night = day + timedelta(hours=rng.uniform(23, 27.5))
            for k, s in enumerate(rng.sample(p.working_set + other[:50], min(20, rng.randint(8, 20)))):
                out.append(ev(night + timedelta(minutes=4 * k + rng.uniform(0, 3)), rng.choice(["DOWNLOAD", "VIEW"]), s))
        elif name == "dept_sweep":
            for k, s in enumerate(rng.sample(other, rng.randint(20, 50))):
                out.append(ev(work + timedelta(minutes=6 * k), "VIEW" if rng.random() > 0.3 else "ACCESS_DENIED", s,
                              ok=rng.random() > 0.3))
        elif name == "factor_bruteforce":
            ip = f"172.16.{rng.randint(0, 255)}.{rng.randint(2, 250)}"
            for k in range(rng.randint(10, 30)):
                out.append(ev(work + timedelta(minutes=k * rng.uniform(0.5, 2)), rng.choice(["LOGIN_FAILED", "STEP_UP_FAILED"]),
                              ip=ip, ok=False))
        elif name == "account_takeover":
            ip = f"172.16.{rng.randint(0, 255)}.{rng.randint(2, 250)}"
            odd = day + timedelta(hours=rng.choice([2.5, 3.5, 5.0, 22.5]))
            out.append(ev(odd, "LOGIN", ip=ip))
            for k, s in enumerate(rng.sample([d.serial for d in self.docs], rng.randint(5, 15))):
                out.append(ev(odd + timedelta(minutes=3 + 5 * k), "DOWNLOAD", s, ip=ip))
        elif name == "limit_probing":
            targets = rng.sample(other, 3)
            for k in range(rng.randint(8, 20)):
                out.append(ev(work + timedelta(minutes=7 * k), "ACCESS_DENIED", rng.choice(targets), ok=False))
        elif name == "tamper_return":
            s = rng.choice(p.working_set)
            out.append(ev(work, "MOD_COPY", s))
            out.append(ev(work + timedelta(hours=rng.uniform(1, 5)), "TAMPER", s))
        elif name == "privilege_probe":
            for k in range(rng.randint(5, 10)):
                out.append(ev(work + timedelta(minutes=9 * k), "ACCESS_DENIED", rng.choice(other), ok=False))
        elif name == "slow_exfil":
            for d_off in range(rng.randint(5, 8)):
                dday = day + timedelta(days=d_off)
                if dday.weekday() >= 5:
                    continue
                for _ in range(max(2, int(p.rate * rng.uniform(0.15, 0.3)))):
                    t = dday + timedelta(hours=p.start + rng.uniform(0.5, p.length - 0.5))
                    out.append(ev(t, "DOWNLOAD", rng.choice(other)))
        elif name == "duplicate_spree":
            for k in range(rng.randint(3, 6)):
                out.append(ev(work + timedelta(minutes=5 * k), "DUPLICATE", f"PHY-DUP-{attack_id}-{k}", ok=False))
        return out


def simulate(people: int = 80, days: int = 120, seed: int = 7, attacks_per_scenario: int = 10, start: Optional[datetime] = None,
             orgs: int = 1):
    """`orgs` > 1 simulates several organisations of different sizes and habits (different
    seeds), so the model learns patterns rather than one organisation's quirks."""
    start = start or datetime(2026, 1, 5)
    rows, worlds, n = [], [], 0
    per_org = max(2, -(-attacks_per_scenario // orgs))
    for org in range(orgs):
        rng = random.Random(seed + 1000 * org)
        size = people if org == 0 else max(15, int(people * rng.uniform(0.5, 1.5)))
        world = World(size, rng, prefix=f"did:sim:o{org}")
        worlds.append(world)
        for d in range(days):
            day = start + timedelta(days=d)
            for p in world.people:
                rows.extend(world.normal_day(p, day))
        # spread every scenario over both periods so train and test each contain it
        for name in SCENARIOS:
            for k in range(per_org):
                lo, hi = (0, int(days * 0.7) - 8) if k % 2 == 0 else (int(days * 0.7), days - 8)
                day = start + timedelta(days=rng.randint(max(lo, 14), max(lo + 14, hi)))
                n += 1
                rows.extend(world.attack(name, day, f"ATK-{n:04d}"))
    rows.sort(key=lambda r: r["event"].ts)
    split_at = start + timedelta(days=int(days * 0.7))
    return rows, split_at, worlds


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--people", type=int, default=80)
    ap.add_argument("--days", type=int, default=120)
    ap.add_argument("--attacks-per-scenario", type=int, default=12)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--orgs", type=int, default=3, help="simulate several organisations (default 3)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    rows, split_at, worlds = simulate(a.people, a.days, a.seed, a.attacks_per_scenario, orgs=a.orgs)
    print(f"Simulated {len(worlds)} organisation(s), {sum(len(w.people) for w in worlds)} people, "
          f"{sum(len(w.docs) for w in worlds)} documents, {a.days} days: {len(rows):,} events "
          f"({sum(r['label'] for r in rows):,} in {len({r['attack_id'] for r in rows if r['attack_id']})} attacks) "
          f"in {time.time() - t0:.1f}s")

    ev_path = os.path.join(a.out, "events.csv")
    with open(ev_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts", "actor", "role", "dept", "kind", "asset", "asset_dept", "asset_owner", "sensitivity", "ip", "ok",
                    "label", "scenario", "attack_id"])
        for r in rows:
            e = r["event"]
            w.writerow([e.ts.isoformat(), e.actor, e.role, e.dept, e.kind, e.asset or "", e.asset_dept or "", e.asset_owner or "",
                        e.sensitivity, e.ip or "", int(e.ok), r["label"], r["scenario"], r["attack_id"]])

    t1 = time.time()
    feat_path = os.path.join(a.out, "features.csv")
    with open(feat_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts", "actor", "kind", "label", "scenario", "attack_id", "split"] + FEATURES)
        meta = iter(rows)
        for i, (e, feats) in enumerate(stream_features(r["event"] for r in rows)):
            r = next(meta)
            w.writerow([e.ts.isoformat(), e.actor, e.kind, r["label"], r["scenario"], r["attack_id"],
                        "train" if e.ts < split_at else "test"] + [f"{feats[k]:.6g}" for k in FEATURES])
            if i and i % 20000 == 0:
                print(f"  features: {i:,}/{len(rows):,}")
    print(f"Features computed in {time.time() - t1:.1f}s")
    print(f"Wrote {ev_path}\nWrote {feat_path}")
    print(f"Split: train before {split_at.date()}, test after. Next: python ml/train.py")


if __name__ == "__main__":
    main()
