# Architecture Overview

**LexCorp: blockchain-based secure platform for identity, access control and digital asset management**
(problem statement 26125).

This document maps each part of the system to the files that implement it.

## Components

| Layer | What it does | Location |
|---|---|---|
| Web app | React 18 + Vite single-page app; pages per role | `frontend/src/pages/`, `frontend/src/components/` |
| Wallet | In-browser Ethereum wallet (ethers.js), stored only as an encrypted keystore | `frontend/src/services/walletCore.js`, `web3.js`, `chainActions.js` |
| API | FastAPI routers | `backend/app/api/` (`auth`, `users`, `assets`, `verify`, `audit`, `alerts`, `chain`, `indexer`) |
| Core | Settings, database, crypto, client-IP resolution, rate limits, safe file parsing | `backend/app/core/` |
| Services | Domain logic (MFA, access, grants, watermarking, verification, ledger, risk) | `backend/app/services/` |
| Data | SQLAlchemy models, Alembic migrations (PostgreSQL) | `backend/app/models/`, `backend/migrations/` |
| Smart contract | `AssetNFT` (ERC-721 + OpenZeppelin AccessControl) | `contracts/contracts/AssetNFT.sol`, tests in `contracts/test/` |
| Blockchain | Private Hyperledger Besu network, QBFT, 3 validators, zero gas (chain 13371) | `network/besu/` |
| Ledger indexer | Reads contract events into the audit trail and cross-checks it | `backend/app/indexer/event_indexer.py` |
| Remote access | OpenVPN + company SSO at every connection; public verify-only address | `network/vpn/` |
| Risk model | Local behavioural AI (training and evaluation scripts) | `backend/app/services/risk/`, `backend/ml/` |

## Identity and authentication

1. **Identity.** Each person has an Ethereum wallet created in their own browser. The private key is
   kept as an ethers v3 JSON keystore (scrypt + AES-128-CTR) that is unlocked with a wrapping
   secret the server releases only to an authenticated session (`GET /api/auth/wallet-key`). The
   key never reaches the server. The wallet address becomes a `did:ethr:13371:<address>` identifier.
2. **Provisioning.** An Admin (or a Manager, within their departments) registers the address with a
   role and department and issues a one-time provisioning PIN (stored only as a hash, valid three
   hours). The person provisions the wallet on their device with it
   (`backend/app/api/users.py`, `backend/app/api/auth.py`, `backend/app/services/identity.py`).
3. **Enrolment and sign-in.** Before anything else, the person enrols a login authenticator (TOTP 1)
   and a login passkey (WebAuthn, Passkey 1). Sign-in is the wallet plus either factor.
4. **Three factors, each bound to a purpose** (`backend/app/services/mfa.py`):
   - Factor 1 (login): session establishment.
   - Factor 2: view a document, submit a document, request access or a download.
   - Factor 3: mint, approve, modify, download, and every administrative action.

   A factor for one purpose never satisfies another; step-up proofs are single-use and bound to one
   action. A person may opt in to using their login factors for Factor 2 and/or 3.
5. **Sessions.** An HttpOnly, SameSite=Strict browser-session cookie holding a JWT (30 minutes),
   bound to the client IP and a session version (one active session per account). Signed out after
   15 minutes without activity, when the network address changes, or when LexCorp is closed.

## Assets and documents

- **Registration.** A user submits a document or device; the file goes to the off-chain vault
  (`OFFCHAIN_STORAGE_DIR`) and only its SHA-256, token ID, owner and approval are recorded on the
  ledger. Only a Manager or Admin can approve, and the approver's own wallet signs the mint; the
  backend's chain key holds only `REGISTRAR_ROLE` and can never mint (`backend/app/services/chain.py`).
  Separation of duties: no User or Manager decides on their own request; a Manager's own revision
  goes to another Manager for the department or an Administrator.
- **Delegated access.** Owners grant view and download rights with view limits and expiry
  (`backend/app/services/grants.py`, `backend/app/services/access.py`).
- **Protected copies.** Every view or download is a derived copy with a visible watermark (viewer,
  wallet, IP, time, View/Download ID), a QR code and an invisible copy mark; the copy's SHA-256 is
  recorded (`backend/app/services/watermark.py`, `hidden_mark.py`). Returned revisions are checked
  element by element and the watermark is removed before storage (`watermark_strip.py`,
  `copy_integrity.py`).
- **Verification.** The QR opens a public, read-only verify page; Auditors get the full check detail
  (`backend/app/api/verify.py`, `backend/app/services/verification.py`).

## Audit and risk

- **Audit trail.** Every security-relevant action is written to `audit_events`, which the database
  makes append-only (edits and deletes are refused); ledger events are indexed into the same trail
  and cross-checked against the chain.
- **Risk model.** 32 behavioural features computed from each person's own 30-day history
  (`backend/app/services/risk/features.py`) feed two local scikit-learn models: an Isolation Forest
  trained on normal activity and a gradient-boosted classifier trained on labelled scenarios
  (`model.py`; training in `backend/ml/train.py`). Live scoring is in `live.py`. HIGH and CRITICAL
  events raise alerts that escalate Auditor -> Manager -> Admin (`backend/app/services/alerts.py`).
- **Deterministic rules** catch tampered returns, duplicate registrations and denied access with
  certainty; the AI covers behaviour no rule describes.

## Security architecture

- No private key in the backend can mint or approve; privileged ledger actions are signed in the
  browser by the acting person's wallet. The chain relay forwards only transactions the session's
  own wallet signed, addressed to the LexCorp contract (`backend/app/api/chain.py`).
- Roles are enforced on-chain (`MINTER_ROLE`, `ANCHOR_ROLE`, `MANAGER_ROLE`, `AUDITOR_ROLE`) and
  synchronised with the identity registry.
- Uploaded files are parsed defensively: no XML external entities or DTDs, ZIP size/entry/name
  limits, image pixel limits, PDF page limits (`backend/app/core/safe_files.py`).
- The application has no public port; remote staff connect through the VPN. Only the verify pages
  are published (`network/vpn/README.md`).

## Standards

- W3C DID v1.1 (`did:ethr`), W3C Verifiable Credentials 2.0 (JWT-VC, `backend/app/services/vc.py`)
- ERC-721, OpenZeppelin Contracts 5.x (AccessControl, ERC721)
- NIST SP 800-63B-4 (authenticators), W3C WebAuthn Level 2, RFC 6238 (TOTP)
- NIST SP 800-207 (zero trust)

## Prototype-vs-production gaps

- No formal smart-contract audit.
- Private Besu network on a single machine; no geographically separated validators.
- No HSM for key material.
- The AI model is trained on simulated activity (plus any Auditor decisions exported back).
- Single indexer instance (no high availability).
