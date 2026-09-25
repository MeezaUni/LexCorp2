# LexCorp2 — Requirements Verification Matrix

State at commit `6a0bbbb` + docs commit (2026-09-26). Automated suite: **189 passed, 0 failed** (`backend/tests`, isolated `lexcorp_sih_test` DB, real TOTP codes and real ES256 WebAuthn signatures via a software authenticator — no MFA bypass). Live DB at Alembic `0010_indexer_state`.

Legend: ✅ IMPLEMENTED + VERIFIED · ⚠️ IMPLEMENTED — MANUAL TEST REQUIRED · ⚠️ PARTIAL · ❌ NOT IMPLEMENTED · ❓ UNVERIFIED

"Manual" column refers to sections of `backend/Final_Manual_Test_Checklist.md` (none executed yet — manual status is therefore open everywhere).

## Identity & authentication

| Req (spec §) | Status | Evidence | Files | Automated tests | Manual | Notes |
|---|---|---|---|---|---|---|
| Wallet-based identity, DID `did:ethr:13371:<wallet>` (8, 50) | ✅ | all 22 live users on 13371; legacy DIDs reported, never rewritten | services/auth.py | test_security_regression::test_legacy_dids_reported_not_rewritten | 1.2 | no 31337 DIDs exist live |
| Unknown wallets never auto-created (8) | ✅ | provision rejects, no row | api/auth.py | test_auth_identity::test_unknown_wallet_cannot_provision_or_autocreate, test_siwe_flow | — | was auto-creating USERs |
| Wallet address typed manually for login (8) | ⚠️ | modal never pre-fills | WalletModal.jsx | test_auth_identity login tests | 1.4 | UI behaviour |
| Encrypted wallet at rest (8) | ⚠️ | scrypt keystore unlocked by server-held secret released only to a session; round-trip verified in Node with the real walletCore.js | walletCore.js, auth.py `/wallet-key`, migration 0004 | test_wallet_key_released_only_to_session_and_rotated_on_reset | 1.2 | was plaintext private key in localStorage |
| First-time import with 3h single-use hashed PIN bound to wallet (9) | ✅ | scrypt hash, atomic consume, expiry, wrong-wallet | api/auth.py, core/crypto.py, migration 0003 | 6 tests in test_auth_identity (success/invalid/expired/reused/bound/nonce replay) | 1.2 | exact 3h lifetime tested |
| Mandatory Login TOTP1 + Passkey1 before any access; server-enforced; direct URL blocked (10) | ✅ | "setup" JWT scope rejected by every app endpoint | dependencies.py, SetupWizard.jsx | test_wallet_import_success_gives_setup_only_session, test_setup_requires_both… | 1.3 | |
| Three purpose-specific factors; no cross-satisfaction (11) | ✅ | per-purpose TOTP secrets + passkey scopes + action-bound single-use step-up | services/mfa.py | test_factor1_cannot_satisfy_factor2, test_passkey3…factor2_cannot_satisfy_factor3, test_totp3_and_factor2_totp…, test_step_up_token_bound_to_action_and_single_use, test_passkey_factors | 1.6 | passkey 1 previously satisfied F3 |
| Real passkeys: challenge→assertion→verify→purpose (12) | ✅ (server) / ⚠️ (browser) | py_webauthn verification with UV required, DB challenges | services/mfa.py, api.js | Passkey1 login, Passkey2 view+submit, Passkey3 mint+approve+modify, wrong purpose, invalid sig, no-UV, replay — test_auth_identity | 1.3–1.6 | real Windows Hello not automatable |
| No self-service login reset; admin reset w/ Factor 3, new PIN, sessions revoked, setup forced (13, 14) | ✅ | | api/auth.py, Identity.jsx | test_user_cannot_self_reset_login_factors, test_admin_reset_flow…, test_admin_cannot_reset_without_request_or_self, test_non_admin_cannot_approve_reset | 1.7 | |
| Sessions: JWT expiry, versioning, one session, inactivity, disabled, logout, revocation (15) | ✅ | | dependencies.py | test_single_active_session_and_logout, test_inactivity_timeout, test_disabled_account_rejected, test_security_regression session tests | 1.8 | |
| IP binding terminates session; trusted-proxy handling (15) | ✅ (logic) / ⚠️ (real network) | X-Forwarded-For only from TRUSTED_PROXIES | dependencies.py, vite.config.js | test_ip_change_terminates_session, test_forwarded_for_ignored_from_untrusted_peer | 1.8 | VPN/proxy deployments must set TRUSTED_PROXIES |
| TOTP replay protection & secrets encrypted | ⚠️ PARTIAL | replay blocked; new secrets encrypted; **legacy plaintext secrets are re-encrypted only on next successful use** | services/mfa.py, core/crypto.py | test_login_with_totp1… (replay), test_totp_secrets_encrypted_at_rest | — | see limitations |

## RBAC & departments

| Req | Status | Evidence | Files | Tests | Manual | Notes |
|---|---|---|---|---|---|---|
| Roles enforced server-side (6) | ✅ | | services/access.py | test_rbac_scoping (10), role tests across suite | 5 | |
| Department scoping incl. manager extra depts; no API bypass (7, 37) | ✅ | filtered in SQL; out-of-scope = 404 | access.py, assets.py, users.py, audit.py | test_registry_scoped_by_role, test_manager_direct_api_bypass_rejected, test_managed_departments_extend_manager_scope | 3.5, 5.2–5.4 | |
| Manager user creation: dropdown from server, backend re-validates (7) | ✅ | departments table (0005) | users.py, AdminDashboard.jsx | test_user_creation_department_validated_server_side | 5.4 | |
| Previously unauthenticated endpoints closed (52) | ✅ | registry, cards, QR, audit, indexer, VC, check-access… | assets.py, audit.py, indexer.py | test_previously_public_endpoints_require_session | 5.1 | |

## Digital assets

| Req | Status | Evidence | Files | Tests | Manual | Notes |
|---|---|---|---|---|---|---|
| Creation: CRT ID, server SHA-256, immutable content-addressed storage, audit (17) | ✅ | hash recomputed from stored bytes | assets.py | test_document_workflow, test_action_ids, test_protected_copies_api | 2.1 | client hash was trusted |
| View requires Factor 2 + policy; VW ID persisted (18) | ✅ | | assets.py | test_document_viewing, test_passkey2_view_and_submit | 2.3 | |
| Delegated access via Manager/Admin approval (19) | ✅ | ACR IDs, separation of duties | assets.py, grants.py | test_delegated_access (10) | 2.5 | |
| Max view count, atomic, only successful views (20) | ✅ | 8 parallel views vs limit 3 → exactly 3 | grants.py | test_view_limit_is_atomic_under_concurrency, test_view_limit_counts_only_successful_views, test_unsupported_type_refused_without_consuming_view | 2.5 | |
| Accessible-until expiry, tz-aware (21) | ✅ | | assets.py | test_expiry | 2.5 | |
| View ≠ download (22) | ✅ | | grants.py | test_view_permission_separate_from_download | 2.5 | |
| View watermark = viewer, short wallet, trusted IP, date, VW ID, QR; owner never shown (23) | ✅ | | watermark.py | test_view_watermark_names_viewer_not_owner…, test_view_watermark_never_shows_owner… | 2.3 | |
| Controlled download: request, owner consent, Manager/Admin approval, requester Factor 3, DL ID, single use (24) | ✅ | token-URL & direct-vault downloads removed (410) | assets.py | test_download_workflow_success, test_non_owner_download_needs_owner_consent…, test_download_cannot_bypass_approval_or_expiry | 2.6 | |
| Modification: request→approval→F3 download→upload→hash→MOD ID→pending→approval (25, 27) | ✅ | | assets.py `_create_revision` | test_revise_document_success, test_revision_rules…, test_download_modification_workflow | 2.7 | UI revision flow was calling a non-existent endpoint |
| Revision lineage v1,v2,v3; original never overwritten (26, 48) | ✅ | byte-level SHA-256 checks | assets.py, migration 0006 | test_creation_view_download_modification_ids_and_versions, test_modification_watermark_history_cumulative | 2.7 | |
| Cumulative, deterministic modification history in watermarks; uploaded watermark text not trusted (28, 29, 61) | ✅ | | watermark.py, assets.py | test_modification_watermark_history_cumulative, test_uploaded_file_watermark_text_is_not_trusted, test_modification_history_cumulative… | 2.7 | |
| Format support PDF/DOCX/PPTX/XLSX/images/TXT (30, 60) | ✅ (structure) / ⚠️ (open in Office) | reopened with pypdf/python-docx/python-pptx/openpyxl; rotation, alpha, fields, QR decoded (OpenCV) | watermark.py | test_watermark_engine (10) | 2.4 | XLSX: openpyxl drops charts/pivots/images; unsupported types → 415 |
| Digital QR verification + tamper detection (31, 46, 62) | ✅ | | api/verify.py, VerifyAction.jsx | test_qr_verification (5) | 2.8 | |
| Action IDs CRT/VW/DL/MOD unique, persisted, linked (45) | ✅ | atomic per-day counter | action_ids.py | test_action_id_format_and_uniqueness_under_concurrency | — | legacy-format IDs kept |

## Physical assets

| Req | Status | Evidence | Files | Tests | Manual | Notes |
|---|---|---|---|---|---|---|
| Admin/Manager only; Serial + (MAC xor Unique Address) (32, 33) | ✅ | | assets.py, physical.py | test_physical_assets (13) | 3.1 | |
| Global normalised uniqueness, DB-level; duplicates audited without raw values; no partial creation (34) | ✅ | functional unique indexes (0008) | physical.py, migration 0008 | test_duplicate_*_attempt_audited, test_uniqueness_is_global…, test_database_rejects_normalised_duplicates_directly | 3.2 | 8 legacy live assets lack both identifiers (not modified) |
| NFT card: only 5 fields (35) | ✅ | | asset_card.py | test_asset_certificate_svg_card_success, test_card_has_only_allowed_fields_and_scope | 3.3 | |
| Verification redaction (36) | ✅ | | assets.py verify-data | test_verification_public_minimal_authorized_detailed | 3.4 | |
| Lifecycle audit events (38) | ✅ | CREATED/APPROVED/MINTED/CUSTODIAN/STATUS/MAINTENANCE/VERIFIED; on-chain AssetTransferred via indexer | assets.py | test_physical_lifecycle (6) | 3.5 | ASSET_TRANSFERRED is recorded as the indexer's `AssetTransferred` |
| Mint only after approval, confirmed against chain (49) | ✅ (server) / ⚠️ (UI signing) | receipt + contract state checks; fabricated tx rejected by live node | assets.py `_confirm_on_chain`, ManagerDashboard.jsx | test_chain_confirm (4), test_mint_confirm_* | 2.2, 3.3 | approval calldata was never submitted before |

## AI, audit, blockchain

| Req | Status | Evidence | Files | Tests | Manual | Notes |
|---|---|---|---|---|---|---|
| Local Isolation Forest preserved (39, 53) | ✅ | model unchanged; now also scores API views/downloads/revisions/physical registration | services/ai.py, alerts.py | test_ai_high_risk_raises_alert… | 4 | model quality not evaluated |
| Dedicated alert; Auditor→Manager→Admin; dismiss/forward; revoke via existing mechanism; history (39–43, 59) | ✅ | | services/alerts.py, identity.py, AlertQueue.jsx | test_security_alerts (9) | 4 | |
| AI never replaces deterministic auth (53) | ✅ | transfer/revoke gate now only on human-escalated alerts | services/ai.py | test_subject_cannot_act_and_escalated_alert_gates_sensitive_ops | — | behaviour change |
| Audit filters (44) | ✅ | | api/audit.py, AuditorDashboard.jsx | test_audit_filters (3) | — | |
| Audit fields per event (63) | ⚠️ PARTIAL | actor, asset, action ID, IP, result, chain refs on chain events; **role is resolved by join, not stored per event** | dependencies.record_audit | across suite | — | |
| Besu 13371, 3 QBFT validators, contract, receipts (49) | ✅ | eth_chainId 0x343b, 3 validators, contract code present, live receipts read | — | test_*_real_besu_rejects_fabricated_tx | 0.2 | no redeploy / reset performed |
| Indexer complete & non-destructive | ✅ | all asset events of the live contract indexed; wipe paths removed | event_indexer.py, migration 0010 | test_indexer_cursor (7), test_event_indexer (4) | — | |

## Process requirements

| Req | Status | Notes |
|---|---|---|
| Migrations, no data wipe (51) | ✅ | Alembic 0002–0010; backups before irreversible/backfilling steps in `db_backups/` |
| Tests not weakened / deleted (54) | ✅ | tests changed only to (a) present real factors instead of the removed bypass, (b) assert spec-required behaviour that replaced old behaviour — each listed in commit messages |
| Manual checklist (64) | ⚠️ | written; **not executed** |
| Local commits only (67) | ✅ | nothing pushed |

**NIST:** NIST SP 800-63-aligned practices are observed (phishing-resistant authenticators with UV, replay protection, session binding and timeouts); full compliance has not been independently established.
