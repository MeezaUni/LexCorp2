# Browser verification harness (Playwright)

These scripts drive the **real running LexCorp stack** (Vite frontend, FastAPI backend,
PostgreSQL, the Besu network and the AssetNFT v3 contract) through the browser. They were
executed through the Playwright MCP tool (`browser_run_code_unsafe`, each file is one
`async (page) => { ... }` function). Results and screenshots are recorded in
`docs/Playwright_Verification_Report.md` and `docs/evidence/playwright/`.

## What is real and what is automated

- Real: every HTTP request, database write, Factor 2/3 check, watermark and QR, and
  ledger transaction. The ledger transactions are signed by each role's own wallet
  inside its browser context and sent through the authenticated relay.
- Automated stand-ins:
  - Passkeys use a Chrome DevTools **virtual WebAuthn authenticator** (CTAP2, user
    verification simulated). This exercises the full WebAuthn protocol and server checks,
    but it is not Windows Hello or any physical authenticator. Those remain manual tests.
  - TOTP codes are computed by the dev-only credential broker
    (`scripts/e2e_fixture_server.py`) from secrets captured during enrolment, in place
    of a phone authenticator app.
- No secret passes through the operator's console. Wallet keys, PINs and TOTP secrets
  travel only between the page and the broker on 127.0.0.1. Screenshots mask every
  element marked `data-sensitive`.

## Order

| Script | Covers |
|---|---|
| 01 | Bootstrap admin provisioning, TOTP 1 and Passkey 1 enrolment |
| 02 | Admin Factor 2/3 set-up; identity registration with Factor 3 and ledger role sync |
| 03 | Self-generated wallet path; provisioning and enrolment of Manager, Auditor and Users |
| 04 | Document registration, approval with Factor 3, ledger mint, watermarked view |
| 05 | Controlled download, modification copy, revision, anchoring, delegation with a view limit |
| 06, 07 | Physical assets: duplicates, approval and mint, card and QR, redaction, public verification |
| 08, 09 | Alert chain from Auditor to Manager to Admin, revocation, session termination |
| 10, 11 | Role navigation, direct-URL and API guards, four viewports, mobile drawer |
| 12 | Logout, login passkey, Passkey 3 step-up, purpose separation, audit filters |
| 13 | Checklist M1: AI-assisted alert from the trained risk model (standalone, see below) |

## Running again

1. Start the stack (`npm start`), then run `python scripts/e2e_fixture_server.py`.
   The broker refuses to run unless `ENVIRONMENT=development`.
2. Issue a fresh bootstrap PIN: `python backend/scripts/bootstrap_admin.py --reissue-pin`.
3. Run the scripts in order with the Playwright MCP tool.
   - Contexts are created in order: 1 admin, 2 user1, 3 manager, 4 auditor, 5 user2.
   - Sessions have a 15-minute idle limit and a 30-minute absolute limit; later scripts
     sign in again through the UI when needed.
4. The run writes data to the development database and ledger. Reset afterwards as
   described in `backend/Final_Manual_Test_Checklist.md`, section S.

## Script 13 (M1, AI-assisted alert) runs on its own

It does not need the broker, the bootstrap PIN or scripts 01-12. With the stack running and
a trained model in `backend/ml/models/`:

```
cd e2e/playwright
npm install            # the Playwright library only; it uses your installed Chrome
node 13_m1_ai_alert.mjs            # add --headed to watch, --keep to leave the test data
```

`scripts/e2e_m1_fixture.py` seeds run-stamped E2E-M1 people with three weeks of ordinary
history (the model compares each action with the person's own habits, so brand-new people look
unusual), 16 documents and view grants. The run checks that ordinary work raises no alert and
that a burst of 12 never-touched documents raises exactly one AI alert with plain-word reasons,
then the test Auditor dismisses it and the people are retired. The audit trail is append-only,
so each run leaves about 150 labelled history events plus its own actions and alert in it;
`ml/export_feedback.py` ignores alerts about E2E- identities.
