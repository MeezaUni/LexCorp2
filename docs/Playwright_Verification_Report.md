# LexCorp — Playwright browser verification report (2026-09-26)

This is **automated browser verification** against the real running stack: Vite on
:5173, FastAPI on 127.0.0.1:8000, PostgreSQL, the 3-validator Besu network and AssetNFT v3.
**It is not human manual testing.** The harness is in `e2e/playwright/` and screenshots are in
`docs/evidence/playwright/`. Sensitive elements are masked in magenta.

## Environment and method

- **Contract.** During the run the contract was `0x113904450c2E72A1E1602F733D9140eAB9Db35aD`.
  After the run a fresh contract, `0x9017fB8bC1721aF8F1F4Af622dF86fD24E736213`, was deployed
  and the database recreated for manual testing. The E2E state is kept in
  `db_backups/e2e_run_20260926/`.
- **Browser contexts.** Each identity had its own context: its own wallet keystore, cookie
  and virtual authenticator.
- **Passkeys.** A Chrome DevTools virtual WebAuthn authenticator was used (CTAP2, user
  verification simulated). It exercises the full WebAuthn protocol and server verification.
  It is not Windows Hello.
- **TOTP.** Codes came from `scripts/e2e_fixture_server.py`, a development-only broker.
  Secrets were captured from the enrolment UI and never passed through the operator
  transcript.
- **Ledger.** Every on-chain transaction was signed in the browser by that role's own wallet
  and submitted through the authenticated relay to Besu.

## Results

| # | Flow (role) | Result |
|---|---|---|
| 01 | Bootstrap admin: first-time provisioning (wallet + PIN), TOTP 1, Passkey 1, dashboard | PASS |
| 02 | Admin: Factor 2 and Factor 3 authenticators; registers a Manager, an Auditor and a User with Factor 3; one-time PIN shown once. Ledger roles granted on-chain: Manager gets MINTER/ANCHOR/MANAGER, Auditor gets AUDITOR, User gets none | PASS |
| 03 | User creates their own wallet on the sign-in screen, and the admin registers only the address. Four identities provision and enrol. Before enrolment completes the application is unreachable in every case | PASS |
| 04 | User registers a PDF with Factor 2. The Manager approves with Factor 3; the Manager's wallet signs the mint (Besu block 17893) and the server verifies receipt and state. Watermarked view `VW-20260926-0001` shows viewer, wallet, IP, date, View ID, QR and the diagonal CONFIDENTIAL mark | PASS |
| 05 | Download request with Factor 2 is approved by the Manager with Factor 3, then fetched with Factor 3. A second fetch is refused (409). A modification copy leads to a revision upload (`MOD-20260926-0001`), which the Manager approves and anchors in block 17943; the version history shows v1 and v2. Delegation to a Radar user with a 1-view limit: view 1 succeeds, view 2 is refused ("View limit reached"). The Radar user's register shows only the delegated document | PASS |
| 05b | File-level check of the downloaded PDFs: Download ID, "Downloaded by Meera Iyer", short wallet, IP, CONFIDENTIAL, QR on every page, original content kept, control page appended | PASS |
| 06 / 07 | Physical: a MAC asset is registered. A duplicate MAC in a different notation is refused, a duplicate serial is refused, and an unregistered custodian is refused. A unique-address asset is registered. The Admin approves and signs the mint. The Manager cannot decide on their own submission. The card and QR render. MAC and location are hidden from the custodian user and visible to the Manager and Auditor. Status change (Factor 3) and maintenance entry are recorded. The public QR page on a phone viewport shows minimal fields and no MAC or location. An invalid token fails safely | PASS (after fixes, see below) |
| 07b | Public watermark QR page (`/verify/action/VW-...`) confirms authenticity and does not reveal the viewer's name or IP when signed out | PASS |
| 08 / 09 | Alerts: the Auditor forwards user1's alert, the Avionics Manager dismisses it with a note, and the Auditor gets read-only access once it has moved on. A Radar user's alert is taken over by the Admin (no Radar manager) and the identity is revoked with Factor 3. The history reads RAISED, FORWARDED_TO_MANAGER (Auditor), FORWARDED_TO_ADMIN (Admin), IDENTITY_REVOKED (Admin). The revoked user's live session ends, their sign-in is refused generically, and the register shows Revoked | PASS (after fixes) |
| 10 / 11 | Role navigation: the User sees 5 items, the Auditor 7, the Manager 8 ("People"), the Admin 8 ("Administration"). A User opening `/admin`, `/alerts` or `/audit` directly gets "Not available". API refusals (all 403): User on alerts, stats, chain status and reconcile; Manager on chain status; Auditor creating users. Ten pages at 1920×1080, 1366×768, 768×1024 and 390×844 show no horizontal overflow and no off-screen controls. The mobile and tablet drawer opens, navigates and closes | PASS (after fixes) |
| 12 | Logout: the next `/auth/me` returns 401. Sign-in with the login passkey works; one device's passkey cannot sign in to another identity. The Manager registers Passkey 3 (proven with the Factor 3 code) and uses it for a Factor 3 status change. A login passkey cannot satisfy Factor 2. Audit filters work: CHAIN 21 rows, HIGH 25 rows | PASS |
| — | Console errors on clean page loads (all roles, all pages) | 0 |
| — | Failed API requests other than intentionally refused ones | 0 |

## Defects found by this run and fixed (each re-run afterwards)

1. **Wrong recipient on minted assets.** An asset created for another identity was minted to that identity on-chain, but the registry owner and the owner DID stayed the proposer. The indexer's new integrity rule flagged both mints. Recipients must now be registered identities and are used consistently.
2. **Alerts parked at an empty stage.** Alerts for a department without an independent manager sat in manager review. They now go to Admin review, and the Admin can take over any already parked.
3. **Superseded versions shown as unrecorded.** Obsolete versions appeared as "not recorded on the ledger".
4. **Duplicate rows** in the approval queue.
5. **Two identical "Approve" buttons** in the decision dialog.
6. **Table actions cut off** at tablet width.
7. **Mint actor mis-recorded.** The indexer recorded the token holder as the actor of a mint, and the AI then scored "a USER minting".
8. **AI alert flooding.** The AI model rated 11 of 11 ordinary actions HIGH or CRITICAL. Calibrated alert mode was introduced; see the matrix.
9. **Double alerting.** Duplicate registrations raised two alerts each.
10. **Unexplained session end.** No explanation was shown when a presented session had ended.
11. **Raw WebAuthn errors** were shown to users.
12. **Rotated registrar flagged.** The indexer reported a legitimately rotated registrar as an unexpected governance grant.

Incidental observation: the server's 15-minute inactivity limit and 30-minute absolute session
lifetime both ended idle browser sessions during the run, as designed.

## Not covered by this automation (manual tests required)

- Windows Hello or any physical authenticator, and real phone authenticator apps.
- Scanning QR codes with a real phone camera.
- Opening downloaded DOCX, PPTX and XLSX files in desktop Office. Structure was verified
  programmatically; rendering was not.
- A real network-address change, and access from another machine on the LAN.
- Human judgement on approvals and alerts.
