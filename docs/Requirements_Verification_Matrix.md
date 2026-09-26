# LexCorp2 — Requirements Verification Matrix

Updated 2026-09-26 against the final code on branch `feature/security-workflow-upgrades`.

## Statuses and evidence

**Statuses used:**
- IMPLEMENTED + VERIFIED: automated tests and/or browser verification exercise the behaviour.
- IMPLEMENTED — MANUAL TEST REQUIRED: implemented, but a necessary part can only be checked
  by a person with real devices.
- PARTIAL, NOT IMPLEMENTED, UNVERIFIED, BLOCKED: as named.

"VERIFIED" here means automated or browser evidence. **No manual test has been executed yet.**
Manual test IDs refer to `backend/Final_Manual_Test_Checklist.md`.

**Evidence sources:**
- Backend pytest: 248 passed and 3 live tests skipped by default. The 3 live-Besu tests pass
  when `LEXCORP_LIVE_BESU=1` is set.
- Contract tests: 23 passing.
- Browser verification: `docs/Playwright_Verification_Report.md`.
- Integrity checker: `backend/scripts/verify_integrity.py`, 9/9 on the hand-off environment.
- Infrastructure record: `docs/Infrastructure_Rebuild_Record.md`.

## 1. Release blockers from the previous report

| Blocker | Status | Evidence | Manual |
|---|---|---|---|
| Contract admin was the publicly known Hardhat #0 key | IMPLEMENTED + VERIFIED | A new governance key is generated locally (`secrets/chain.env`); `deploy.js` refuses public dev accounts; `verify_deployment.js` confirms no public dev account holds any role; `test_besu_live::test_deployed_contract_integrity`; `test_repo_hygiene` | Q1 |
| Anyone with gas could mint | IMPLEMENTED + VERIFIED | AssetNFT v3 roles (MINTER/ANCHOR/MANAGER/AUDITOR under REGISTRAR); 23 Hardhat tests. On the live Besu contract an unauthorized mint, physical mint and anchor each land with receipt status 0; an authorized mint succeeds, then fails after revocation (`test_besu_live`) | Q2, Q3 |
| Development secrets and a JWT-derived encryption key | IMPLEMENTED + VERIFIED | No secret defaults. `ENVIRONMENT` defaults to production and fails closed. JWT, VC-signing, data-encryption and chain-operator keys are separate. A MultiFernet key ring with a migration script covers legacy JWT-derived, retired and plaintext secrets. Config errors never echo values (`test_secret_config`, 16 tests) | A2 |
| No manual testing | IMPLEMENTED — MANUAL TEST REQUIRED | The checklist is ready and has **not** been executed | All |

## 2. Identity and authentication

| Requirement | Status | Evidence / tests | Manual |
|---|---|---|---|
| Wallet identity, DID `did:ethr:13371:<wallet>`; unknown wallets never authenticate | IMPLEMENTED + VERIFIED | `test_auth_identity::test_unknown_wallet_cannot…`; the indexer no longer creates identities from chain events (`test_unregistered_mint_raises_integrity_alert_and_creates_no_identity`) | C3 |
| Wallet provisioning with a hashed, single-use PIN valid 3 hours | IMPLEMENTED + VERIFIED | scrypt hash with atomic consume, expiry and reissue (`bootstrap_admin.py --reissue-pin`); auth tests; Playwright 01 and 03 | B1, R5 |
| Self-generated wallet (the admin never sees the key) | IMPLEMENTED + VERIFIED | "Create a wallet" tab; the admin registers the address only (Playwright 03). A custodial "generate for them" path remains, with an explicit warning | D2 |
| Mandatory Login TOTP 1 + Passkey 1 before any access | IMPLEMENTED + VERIFIED | The setup-scope session is rejected by application endpoints; the UI shows only enrolment (Playwright 03: app unreachable for all 4 identities) | B2, B3, B4 |
| Passkey 1 with Windows Hello or a physical authenticator | IMPLEMENTED — MANUAL TEST REQUIRED | Server WebAuthn verification is tested with a software authenticator and a CDP virtual authenticator; real platform authenticator not tested | B3, C2 |
| Purpose-bound Factor 2 and Factor 3; no cross-satisfaction; single-use action-bound step-up | IMPLEMENTED + VERIFIED | Auth tests (passkey/TOTP purpose matrix); Playwright 12 (login passkey refused for Factor 2; Passkey 3 accepted for a Factor 3 action) | C5, R3 |
| Adding a factor to an already-protected purpose requires that purpose's own proof | IMPLEMENTED + VERIFIED | Fixed in this round for TOTP enrolment next to an existing passkey (`test_factor_totp_cannot_be_added_to_passkey_protected_purpose…`) | C4 |
| Identity administration requires Factor 3 (provision, role change, revoke) | IMPLEMENTED + VERIFIED | `test_chain_roles_and_relay`, `test_security_alerts`; Playwright 02 | D2, D9 |
| No self-service login reset; admin approves with Factor 3; new PIN; sessions revoked | IMPLEMENTED + VERIFIED | Auth tests; UI in My identity, Administration and Sign in → Locked out | C10, C11 |
| Session in an HttpOnly, SameSite=Strict cookie only (Secure in production); no token in JS or responses | IMPLEMENTED + VERIFIED | `test_session_is_httponly_cookie_only`; the frontend holds no token | — |
| One active session; logout revokes; disabled/revoked identity refused | IMPLEMENTED + VERIFIED | Auth tests; Playwright 09 and 12 | C6, O2, O3 |
| Inactivity timeout (15 min) and absolute lifetime (30 min) | IMPLEMENTED + VERIFIED | `test_inactivity_timeout`; observed during the Playwright run | C7, C8 |
| Session ends when the client IP changes (trusted proxies only) | IMPLEMENTED — MANUAL TEST REQUIRED | Logic tested (`test_ip_change_terminates_session`); a real network change is not reproducible in automation | C9 |
| TOTP replay protection; secrets encrypted; plaintext refused | IMPLEMENTED + VERIFIED | Tests; the integrity checker reports 0 plaintext values | P4 |

## 3. RBAC and departments

| Requirement | Status | Evidence / tests | Manual |
|---|---|---|---|
| USER, MANAGER, AUDITOR and ADMIN enforced server-side; SQL-level department scoping | IMPLEMENTED + VERIFIED | `test_rbac_scoping` (12); Playwright 10 API refusals | D7 |
| UI navigation per role (hiding only; never treated as security) | IMPLEMENTED + VERIFIED | Playwright 10 (5, 7, 8 and 8 nav items; direct URLs show "Not available") | D6 |
| Manager extra departments; departments from a server table | IMPLEMENTED + VERIFIED | Tests; Administration → Departments | D1, D8 |
| Audit statistics scoped like audit events | IMPLEMENTED + VERIFIED | Fixed this round (`test_audit_stats_are_scoped_like_events`) | P1 |
| Revoked identities listed only for Admin/Auditor on request | IMPLEMENTED + VERIFIED | `test_revoked_identities_listed_only_for_admin_auditor…` | O5 |

## 4. Digital assets

| Requirement | Status | Evidence / tests | Manual |
|---|---|---|---|
| Registration: server SHA-256, byte-detected supported types only, 50 MB streaming cap, CRT ID | IMPLEMENTED + VERIFIED | `test_upload_accepts_only_watermarkable_types`; Playwright 04 | E1, E2, E3 |
| The recipient must be a registered active identity; registry owner = on-chain holder = owner DID | IMPLEMENTED + VERIFIED | Fixed this round, after Playwright exposed a mismatch the indexer flagged (`test_physical_asset_approval_calldata`, `test_asset_for_unregistered_recipient_is_refused`) | E1, L11 |
| Approval by Manager/Admin with Factor 3; separation of duties; approver's wallet signs; recorded only after receipt + state verification | IMPLEMENTED + VERIFIED | Tests; Playwright 04 (block 17893) | E4, E5, E6 |
| View: Factor 2 (header only, never a code in the URL); VW ID; watermark shows viewer, not owner | IMPLEMENTED + VERIFIED | Watermark and API tests; Playwright 04 (screenshot) | F1, F2 |
| View never hands out a native Office file | IMPLEMENTED + VERIFIED | Fixed this round: Office views render as a watermarked PDF of the text content (`test_view_copy_of_office_documents…`) | F3 |
| Delegated access with view limit (atomic), expiry, view ≠ download | IMPLEMENTED + VERIFIED | `test_delegated_access` (10); Playwright 05 (view 2 refused) | G1–G5 |
| Controlled download: request → owner consent → Manager/Admin approval → requester Factor 3 → single use | IMPLEMENTED + VERIFIED | Tests; Playwright 05 (second fetch 409) | H1–H6 |
| Modification copy → revision upload (Factor 3) → approval → anchor on the root token; originals never overwritten | IMPLEMENTED + VERIFIED | Tests; Playwright 05 (v2 anchored in block 17943) | I1–I4 |
| Cumulative modification history in watermarks, from DB records only | IMPLEMENTED + VERIFIED | Watermark tests | I5 |

## 5. Watermarking

| Requirement | Status | Evidence / tests | Manual |
|---|---|---|---|
| PDF: every page diagonal + QR + control page | IMPLEMENTED + VERIFIED | Tests; downloaded files checked at file level (Playwright 05b) | J1 |
| DOCX, PPTX: native watermark shapes, structure preserved | IMPLEMENTED — MANUAL TEST REQUIRED | Reopened with python-docx and python-pptx; not opened in desktop Office | J2, J3 |
| XLSX: charts, pivots and images preserved (edited at package level); header/footer + control sheet | IMPLEMENTED — MANUAL TEST REQUIRED | Fixed this round (`test_xlsx_charts_images_and_parts_preserved_byte_for_byte`); Excel rendering not tested | J4 |
| Images: tiled overlay + band + QR; text rendered to protected PDF | IMPLEMENTED + VERIFIED | Tests | J5 |
| Unsupported types refused (never passed through) | IMPLEMENTED + VERIFIED | Refused at upload and at view time | E3 |
| Tamper detection of a copy's watermark fields | IMPLEMENTED + VERIFIED | `test_qr_verification`; compare UI on the verify page | J6, R1 |

## 6. QR verification

| Requirement | Status | Evidence / tests | Manual |
|---|---|---|---|
| QR carries only a verification reference; the public page shows minimal fields; signed-in employees see role-scoped detail | IMPLEMENTED + VERIFIED | Tests; Playwright 07 and 07b (no MAC, location, viewer name or IP when public) | K3 |
| Invalid references fail safely | IMPLEMENTED + VERIFIED | Playwright 07 | K4 |
| Scanning with a real phone camera over the LAN | IMPLEMENTED — MANUAL TEST REQUIRED | QR URLs use the LAN address when `PUBLIC_BASE_URL` is localhost | K1, K2, L8 |

## 7. Physical assets

| Requirement | Status | Evidence / tests | Manual |
|---|---|---|---|
| Manager/Admin only; serial + (MAC xor unique address); global normalised uniqueness enforced by the DB | IMPLEMENTED + VERIFIED | `test_physical_assets` (14); Playwright 06 (MAC in another notation refused, serial refused) | L1–L5 |
| One alert per duplicate attempt; raw identifiers never logged | IMPLEMENTED + VERIFIED | Fixed this round (double alerting) | L3 |
| NFT card with exactly 5 fields (LexCorp2 styling) | IMPLEMENTED + VERIFIED | `test_asset_cards`; Playwright 07 | L7 |
| Role-based redaction (MAC, unique address, location) | IMPLEMENTED + VERIFIED | Playwright 07 (hidden from custodian user and public; shown to Manager/Auditor) | L9 |
| Lifecycle, status (Factor 3), maintenance, audit | IMPLEMENTED + VERIFIED | `test_physical_lifecycle`; Playwright 06 and 12 | L10 |

## 8. AI risk detection and alert escalation

| Requirement | Status | Evidence / tests | Manual |
|---|---|---|---|
| Alert chain Auditor → Manager → Admin; dismiss (with note) or forward; Admin revokes with Factor 3 through the shared revocation mechanism; history append-only | IMPLEMENTED + VERIFIED | `test_security_alerts` (11); Playwright 08 and 09 | N1–N6, O1–O5 |
| An alert for a department without an independent manager is never parked | IMPLEMENTED + VERIFIED | Fixed this round (auditor forward goes to Admin; Admin take-over) | N6 |
| AI never revokes or blocks by itself | IMPLEMENTED + VERIFIED | The gate only acts on human-escalated alerts | — |
| Revocation ends live sessions and removes ledger roles | IMPLEMENTED + VERIFIED | Playwright 09; `test_revocation_removes_onchain_roles` | O2, O4 |
| **AI model quality** | PARTIAL | The bundled Isolation Forest rated 11/11 ordinary actions HIGH/CRITICAL (native tiers). Calibrated alerting (`AI_ALERT_MODE`, default "calibrated") now alerts only on activity more anomalous than ordinary reference activity; the native label is kept. Detection quality is **not established**: no labelled evaluation data exists | M1 |
| Deterministic integrity rules: unregistered or mismatched mint, unapproved anchor, unexpected role grant, relay misuse, role-sync failure | IMPLEMENTED + VERIFIED | Indexer and relay tests; triggered for real during the Playwright run | M2 |

## 9. Audit trail and indexer

| Requirement | Status | Evidence / tests | Manual |
|---|---|---|---|
| Audit history append-only in the database (UPDATE, DELETE and TRUNCATE rejected, even for the owner) | IMPLEMENTED + VERIFIED | Migration 0011; `test_audit_append_only` (5); integrity checker | P2 |
| Audit filters (category, risk, result, escalation, asset, identity, dates) | IMPLEMENTED + VERIFIED | `test_audit_filters`; Playwright 12 | P1 |
| Indexer: per-log de-duplication, verified cursor, retries failed windows, never rewrites the registry, never creates identities, starts at the deployment block | IMPLEMENTED + VERIFIED | Fixed this round: several events in one transaction were being dropped (`test_every_event_in_one_transaction_is_recorded`); `test_indexer_cursor` (8) | P3 |
| Mint actor = transaction sender | IMPLEMENTED + VERIFIED | Fixed this round | — |
| Role of the actor stored per audit event | PARTIAL | Resolved by joining the current identity, not stored at event time (unchanged from the previous report) | — |

## 10. Blockchain and infrastructure

| Requirement | Status | Evidence / tests | Manual |
|---|---|---|---|
| Besu 13371, 3 new validators (keys generated locally, git-ignored), empty alloc, zero-fee | IMPLEMENTED + VERIFIED | Rebuild record; `qbft_getValidatorsByBlockNumber` | Q1 |
| RPC on 127.0.0.1 only; ETH/NET/WEB3/QBFT only; no CORS; host allow-list | IMPLEMENTED + VERIFIED | curl probes (403 CORS / Host; admin and debug methods disabled) | Q4, R6 |
| Browser chain access only through the authenticated relay (method allow-list; own-wallet signer; LexCorp2 contract only) | IMPLEMENTED + VERIFIED | `test_chain_roles_and_relay` (11); all Playwright transactions went through it | Q5 |
| On-chain roles follow the identity registry (grant, demote, revoke, periodic reconcile, orphan removal) | IMPLEMENTED + VERIFIED | Tests; orphan revoked live; integrity checker | D9, O4 |
| Registrar key rotation | IMPLEMENTED + VERIFIED | Performed live after an in-session exposure (`rotate_registrar.js`) | — |
| Postgres on 127.0.0.1 with a generated password; development password rejected | IMPLEMENTED + VERIFIED | Rebuild record | R6 |
| Production configuration fails closed | IMPLEMENTED + VERIFIED | `test_secret_config`; production smoke run refused to start with the development `.env` | A2 |
| Container image | UNVERIFIED | Non-root user and production default are written, but the image was not built or run in this session | — |

## 11. Frontend

| Requirement | Status | Evidence | Manual |
|---|---|---|---|
| Original LexCorp2 institutional design system; no third-party branding | IMPLEMENTED + VERIFIED | `frontend/src/styles/app.css`; screenshots; the organisation default changed to "LexCorp2" | D6 |
| All major pages redesigned and wired to real data (no invented statistics) | IMPLEMENTED + VERIFIED | Playwright 01–12 | — |
| Responsive at 1920, 1366, 768 and 390 px | IMPLEMENTED + VERIFIED | Playwright 10 and 11 (no overflow, no off-screen controls, drawer works) | — |
| No console errors or failed critical requests | IMPLEMENTED + VERIFIED | Playwright 10 and 11 | — |
| Accessibility basics (labels, focus rings, dialogs, reduced motion, skip link, status not by colour alone) | PARTIAL | Built in; no full audit with assistive technology | — |

## 12. Process

| Item | Status | Notes |
|---|---|---|
| Tests not weakened | IMPLEMENTED + VERIFIED | Changed only to (a) present real factors or credentials where new controls require them, (b) assert stricter or corrected behaviour (for example one alert instead of two, alerts reaching Admin instead of being parked), or (c) move 3 config tests into the stricter `test_secret_config.py` |
| Secrets never printed | PARTIAL | One exposure occurred in-session (a diagnostic imported another local project's package, whose validation error echoed three values). All three were rotated, including an on-chain registrar handover, and the root cause was fixed (`hide_input_in_errors`). The wg-easy portal password appeared once via a tracked comment that was already public in git history |
| Local commits only; nothing pushed | IMPLEMENTED + VERIFIED | `git status` shows the branch ahead of origin |
| Manual checklist executed | NOT IMPLEMENTED | Ready for the owner; not executed |

## 13. Known limitations and owner decisions

1. **Git history still contains** the retired validator keys, the public Hardhat keys, personal files that were in `backup_prod/` and `offchain_storage/`, and the WireGuard keys (`wg0.conf`). Some of these commits are on the remote. The retired items are no longer used, but the **WireGuard keys and the wg-easy password must be rotated**. Rewriting published history is the owner's decision.
2. **AI model quality is not established** (see section 8).
3. **Office rendering** of watermarked copies has not been checked by a person. Office views are text-only PDF renderings; layout is not reproduced.
4. **react-router advisory** (open redirect via backslash) is fixed only in v7. It was assessed as not exploitable here: link targets are fixed paths and serials are URL-encoded. Tracked.
5. **Development toolchain advisories** (46 in Hardhat dev dependencies) do not ship.
6. **Old Postgres container** `lexcorp_postgres_legacy_sihv2` and its volume are kept (stopped). Other local LexCorp copies that used it will not connect with the development password.
7. **A globally installed editable package** from another local project (`lexcorp_sih_backend`) provides a top-level `app` module. It can shadow imports when scripts run from other directories. LexCorp2's scripts insert `backend/` first.
8. **Backups** in `db_backups/` contain data from retired test identities. Delete them after validation.
