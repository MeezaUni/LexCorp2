# LexCorp risk model evaluation (2026-09-27 08:40 UTC)

Model `20260927-0834-97ed7cdd47`, thresholds {'MEDIUM': 99.4922, 'HIGH': 99.9488, 'CRITICAL': 99.9907}.
Test period: 36 days, 244 people, 93,195 events (906 misuse events). **Synthetic data.**

## False alerts

- Ordinary events reaching HIGH or above: **0.120%**
- That is about 1.24 flagged ordinary events per 100 people per day, which the app groups into about **0.74 false alerts per 100 people per day** (one open AI alert per person per 24 h)
- In the 24 h after an attack, 17.7% of that person's other actions were also flagged (548 events, not counted above)
- Share of HIGH+ alerts that were real misuse (precision): **79.4%** of 1006 alerts

## Misuse caught (at least one HIGH+ alert per attack)

| Scenario | Difficulty | Attacks | Caught by AI | AI rate | AI + rules | Events before first AI alert (median) |
|---|---|---|---|---|---|---|
| exfil_burst | easy | 6 | 6 | 100% | 100% | 2 |
| off_hours_exfil | easy | 6 | 6 | 100% | 100% | 1 |
| dept_sweep | medium | 6 | 6 | 100% | 100% | 2 |
| factor_bruteforce | easy | 6 | 6 | 100% | 100% | 1 |
| account_takeover | medium | 6 | 6 | 100% | 100% | 1 |
| limit_probing | medium | 6 | 6 | 100% | 100% | 1 |
| tamper_return | easy | 6 | 1 | 17% | 100% | 1 |
| privilege_probe | medium | 6 | 6 | 100% | 100% | 2 |
| slow_exfil | hard | 6 | 6 | 100% | 100% | 2 |
| duplicate_spree | medium | 6 | 6 | 100% | 100% | 1 |

## Ranking quality (ROC AUC, 1.0 = perfect)

- anomaly detector: 0.960
- classifier: 0.992
- combined: 0.992

## Example explanations (as shown to the Auditor)

- **exfil_burst** (HIGH, risk 100.0): 4 downloads/copies in the last 24 h (usual about 1); 4 documents never touched before, in 24 h
- **off_hours_exfil** (HIGH, risk 100.0): outside working hours; about 9 h away from this person's usual working time
- **dept_sweep** (CRITICAL, risk 100.0): 2 refused or failed attempts in the last hour; the attempt was refused or failed; 2 different network addresses in 24 h
- **factor_bruteforce** (HIGH, risk 100.0): the attempt was refused or failed; from a network address not seen for this person in 30 days; 100% of recent attempts refused or failed
- **account_takeover** (CRITICAL, risk 100.0): outside working hours; from a network address not seen for this person in 30 days; 100% of recent actions on other departments' documents
- **limit_probing** (CRITICAL, risk 100.0): 2 refused or failed attempts in the last hour; the attempt was refused or failed; at the weekend
- **tamper_return** (HIGH, risk 100.0): at the weekend; 1 watermark tamper flag(s) in 7 days; 50% of recent actions were downloads/copies
- **privilege_probe** (CRITICAL, risk 100.0): 2 refused or failed attempts in the last hour; the attempt was refused or failed; 2 refused or failed attempts in 24 h
- **slow_exfil** (HIGH, risk 100.0): 67% of recent actions on other departments' documents; 60% of recent actions were downloads/copies
- **duplicate_spree** (CRITICAL, risk 100.0): 2 refused or failed attempts in the last hour; 2 duplicate registration attempt(s) in 7 days; the attempt was refused or failed

Caveat: synthetic activity. The scenario the classifier was trained on is easier for it than genuinely new misuse; the anomaly detector's AUC is the better guide to that. Measure on real activity with Auditor feedback (ml/export_feedback.py) before relying on these numbers.
