# LexCorp: test and evaluation report

The evidence behind the **Proof it works** figures in the SIH 2026 idea presentation (problem
statement SIH26125). Each row names the test suite, where it lives in this repository, the command
that reproduces it, and the recorded result.

| Figure on the slide | What it means | Result | Details |
|---|---|---|---|
| **312 + 23** automated tests | 312 backend tests + 23 smart-contract tests | 312 passed, 23 passing | [1](#1-backend-tests-312), [2](#2-smart-contract-tests-23) |
| **3 / 3** live-chain tests | Real transactions on the running Hyperledger Besu network | 3 passed | [3](#3-live-blockchain-tests-3--3) |
| **13 / 13** browser flows | Automated Playwright runs against the full running system | 13 passed | [4](#4-end-to-end-browser-flows-13--13) |
| **0.992** AI detection (AUC) | Ranking quality of the local risk model on held-back simulated activity | 0.992 | [5](#5-ai-risk-model-evaluation-auc-0992) |

---

## 1. Backend tests (312)

- **Covers:** the FastAPI API, sign-in and sessions, purpose-bound factors (TOTP and passkeys),
  role-based access by role and department, document and device workflows, watermarking and the
  tamper check, the audit trail and its risk levels, the ledger indexer, and the AI risk model.
- **Where:** [`backend/tests/`](../backend/tests/)
- **Isolation:** runs against a separate `*_test` database and a separate file store, never the live
  data ([`backend/tests/conftest.py`](../backend/tests/conftest.py)).
- **Reproduce:**
  ```bash
  cd backend && python -m pytest -q
  ```
- **Result:** 312 passed. The 3 live-blockchain tests (section 3) are skipped in this default run
  because they need the running Besu network, so the run reports `312 passed, 3 skipped`.

## 2. Smart-contract tests (23)

- **Covers:** the AssetNFT (ERC-721) contract's role checks: only a wallet holding the MINTER role
  can mint, the operator key can grant and revoke roles but never hold them itself, free transfers
  and approvals are disabled, and versions and access grants behave as designed.
- **Where:** [`contracts/test/AssetNFT.test.js`](../contracts/test/AssetNFT.test.js)
- **Reproduce:**
  ```bash
  cd contracts && npx hardhat test
  ```
- **Result:** 23 passing.

## 3. Live blockchain tests (3 / 3)

- **Covers:** real transactions on the 3-validator Hyperledger Besu (QBFT) network. A wallet
  without the MINTER role tries to mint and **the contract itself rejects it**. An authorised
  minter succeeds, and is rejected again once its role is revoked.
- **Where:** [`backend/tests/test_besu_live.py`](../backend/tests/test_besu_live.py)
- **Reproduce** (with the Besu network running):
  ```bash
  cd backend && LEXCORP_LIVE_BESU=1 python -m pytest -q tests/test_besu_live.py
  ```
- **Result:** 3 passed.

## 4. End-to-end browser flows (13 / 13)

Automated Chrome runs (Playwright) against the real running system: the web app, API, PostgreSQL,
the Besu network and the AssetNFT contract. Each role used its own browser, wallet and passkey
(a virtual WebAuthn authenticator).

| # | Flow | Script | Result |
|---|---|---|---|
| 1 | First administrator: wallet, one-time PIN, TOTP, passkey | [`01_admin_provision.js`](../e2e/playwright/01_admin_provision.js) | Pass |
| 2 | Extra factors; registering a Manager, Auditor and User; on-chain roles granted | [`02_admin_factors_and_identities.js`](../e2e/playwright/02_admin_factors_and_identities.js) | Pass |
| 3 | People create their own wallets and enrol; nothing is reachable before enrolment | [`03_provision_people.js`](../e2e/playwright/03_provision_people.js) | Pass |
| 4 | Upload, Manager approval, officer-signed mint, watermarked view | [`04_digital_create_approve_view.js`](../e2e/playwright/04_digital_create_approve_view.js) | Pass |
| 5 | Controlled download, modification (version 2), delegation with a view limit | [`05_download_modify_delegate.js`](../e2e/playwright/05_download_modify_delegate.js) | Pass |
| 6 | Physical asset registration, duplicate check, QR label | [`06_physical.js`](../e2e/playwright/06_physical.js) | Pass |
| 7 | Physical asset recheck and public QR verification | [`07_physical_recheck.js`](../e2e/playwright/07_physical_recheck.js) | Pass |
| 8 | Security alert chain: Auditor → Manager → Admin | [`08_alert_chain.js`](../e2e/playwright/08_alert_chain.js) | Pass |
| 9 | Admin revokes an identity: sessions end, on-chain roles removed | [`09_admin_revocation.js`](../e2e/playwright/09_admin_revocation.js) | Pass |
| 10 | Role-based access on desktop, tablet and phone | [`10_responsive_rbac.js`](../e2e/playwright/10_responsive_rbac.js) | Pass |
| 11 | Responsive recheck | [`11_responsive_recheck.js`](../e2e/playwright/11_responsive_recheck.js) | Pass |
| 12 | Passkeys on several devices, logout, audit filters | [`12_passkeys_logout_audit.js`](../e2e/playwright/12_passkeys_logout_audit.js) | Pass |
| 13 | AI alert in the running app: no alert for ordinary work, one explained alert for a burst | [`13_m1_ai_alert.mjs`](../e2e/playwright/13_m1_ai_alert.mjs) | Pass |

- **Full write-up of flows 1–12, including the defects they found and fixed:**
  [`docs/Playwright_Verification_Report.md`](Playwright_Verification_Report.md)
- **Screenshots:** [`docs/evidence/playwright/`](evidence/playwright/)
- **How to run:** [`e2e/playwright/README.md`](../e2e/playwright/README.md)

## 5. AI risk model evaluation (AUC 0.992)

- **Model:** a local model that runs on the organisation's own server (scikit-learn: an
  IsolationForest anomaly detector plus gradient boosting over 32 behaviour features, compared
  against each person's own 30-day history). It gives plain-word reasons, and people make every
  decision.
- **Test set:** 36 held-back days of simulated activity, 244 people, 93,195 events, 60 simulated
  attacks across 10 misuse types.
- **Results:**
  - ranking quality (ROC AUC): **0.992**; the anomaly detector alone scores 0.960;
  - 9 of the 10 misuse types caught by the AI in every attack; with the integrity rules added,
    **all 60 attacks caught**;
  - misuse flagged within **1–2 actions** (median);
  - **79%** of HIGH alerts are real misuse; about **0.74 false alerts per 100 people per day**.
- **Full report:** [`backend/ml/reports/evaluation.md`](../backend/ml/reports/evaluation.md)
- **Reproduce:** [`backend/ml/evaluate.py`](../backend/ml/evaluate.py)
- **Caveat:** the activity is simulated. The model should be measured again on real activity,
  with Auditor feedback, before relying on these figures.

## Also checked

| Check | Result |
|---|---|
| Remote access: VPN with company (Google) sign-in, from another network and a phone | Connected and reached the app; unapproved accounts refused |
| Environment integrity script | 9 checks |
| Python dependency security audit (pip-audit) | No known vulnerabilities |

Project overview: [`docs/LexCorp_Project_Brief.md`](LexCorp_Project_Brief.md) (section 7 lists
the same evidence).
