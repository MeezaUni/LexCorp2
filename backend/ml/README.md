# LexCorp risk model (local, free, no external services)

The AI part of LexCorp's security alerts. It scores each sensitive action (views,
downloads, modification copies, revisions, registrations, failed sign-ins and factor
codes) against **that person's own recent behaviour** and against what is ordinary for the
organisation, and explains its score in plain words to the Auditor. It only advises:
alerts go to people (Auditor, then Manager, then Administrator), and it never blocks or
revokes anything by itself.

Everything runs on this machine with scikit-learn. No paid APIs and no internet.

## Run it

```
cd backend
python ml/simulate.py          # months of simulated activity with labelled misuse (a few minutes)
python ml/train.py             # trains and writes ml/models/risk_model.joblib (under a minute)
python ml/evaluate.py          # measures it on the held-out period, writes ml/reports/evaluation.md
```

Then restart the app (`npm start`): it loads `ml/models/risk_model.joblib` automatically.
A trained model and its report (`ml/reports/evaluation.md`) are committed, so a fresh clone uses
the new model straight away; retrain only to change the model. The simulated data in `ml/data/`
is not committed.

Useful options:

| Command | What it does |
|---|---|
| `python ml/simulate.py --people 150 --days 180 --orgs 4` | Bigger, more varied simulation |
| `python ml/simulate.py --seed 99 --orgs 1 --out ml/data/other` then `python ml/evaluate.py --data ml/data/other/features.csv --split ""` | Test on an organisation the model has never seen |
| `python ml/train.py --high-rate 0.0005` | Fewer alerts: only 0.05 % of ordinary activity may reach HIGH |
| `python ml/export_feedback.py` then `python ml/train.py --feedback ml/data/feedback.csv` | Learn from your Auditors' real decisions |
| `set RISK_MODEL_PATH=...` (PowerShell: `$env:RISK_MODEL_PATH="..."`) | Use a model file somewhere else |

## How it works

**One feature builder** (`app/services/risk/features.py`) is used by the simulator,
training, evaluation and the live app, so the model sees exactly the same inputs in
training and in production. The previous model was trained on inputs computed differently
from what the app sent it, which is why it rated almost everything HIGH.

**Signals** (per action, from the person's last 30 days in the audit trail):

- time: hour, weekend, outside working hours, distance from this person's usual time;
- volume: actions in the last hour and 24 h, and compared with this person's usual day;
- copying: downloads and modification copies, and their share of recent actions;
- reach: different documents in 24 h, documents never touched before, other
  departments' documents, documents owned by others;
- failures: refused or failed attempts in the last hour and 24 h;
- network: a new address for this person, several addresses in 24 h;
- incidents in the last 7 days: tamper flags and duplicate registrations;
- the action itself (write, copy, privileged, failed) and the person's role.

**Three parts:**

1. an Isolation Forest trained on ordinary activity only, which flags the unusual,
   including misuse nobody simulated;
2. a gradient-boosted classifier trained on labelled examples (the simulated scenarios,
   plus Auditor decisions if exported), which recognises known misuse;
3. thresholds set during training so that only a chosen share of ordinary activity reaches
   HIGH (default 0.1 %), so the alert volume is known in advance.

Both models are put on the same scale ("how unusual compared with ordinary activity"),
and the higher one is the risk.

**In the app:**

- The Auditor sees the top reasons, for example "14 downloads/copies in the last 24 h
  (usual about 1); 16 documents never touched before".
- While a person has an open AI alert from the last 24 hours, further unusual actions are
  recorded in the audit trail but don't open new alerts: one incident, one alert.
- Tampered returns and duplicate registrations are caught with certainty by the app's
  deterministic rules; the AI covers behaviour no rule describes.

## Simulated scenarios

| Scenario | What happens | Difficulty |
|---|---|---|
| exfil_burst | many distinct documents downloaded within 1–3 hours | easy |
| off_hours_exfil | downloads and views between 23:00 and 04:00 | easy |
| dept_sweep | browsing many other departments' documents, some refused | medium |
| factor_bruteforce | a burst of failed sign-ins and factor codes from a new address | easy |
| account_takeover | sign-in from a new address at an odd hour, then downloads | medium |
| limit_probing | repeated refused views of the same few documents | medium |
| tamper_return | a modification copy returned with its watermark altered (also a rule) | easy |
| privilege_probe | a user repeatedly attempting approvals they are not allowed | medium |
| slow_exfil | 2–4x the usual downloads, spread over a week of working hours | hard |
| duplicate_spree | several duplicate physical asset registrations (also a rule) | medium |

The simulated organisations also contain ordinary messiness, so "unusual" isn't
automatically "bad": busy days, late evenings, typos in codes, travel and VPN addresses,
weekend workers, night shifts, sick days and some cross-department work.

## Honest limits

- The data is simulated. The evaluation shows the method catches these patterns while
  keeping false alerts low. It does **not** show how it performs on a real organisation.
- Retrain on real activity as it accumulates, and feed back Auditor decisions
  (`export_feedback.py`).
- New people have no history, so their first days look more unusual than they are.
- A patient insider who stays within their normal volume, hours and documents is
  hard for any behavioural model.

## Public datasets (optional, for research)

These are free but don't match LexCorp's activity directly. They're useful for choosing
signals and sanity-checking the method.

- **CERT Insider Threat Test Dataset** (Carnegie Mellon; search "CERT Insider Threat Test
  Dataset KiltHub"): simulated organisation logs with labelled insider scenarios such as
  data theft before leaving.
- **LANL Comprehensive Multi-Source Cyber-Security Events**: real authentication logs
  with red-team activity marked.
