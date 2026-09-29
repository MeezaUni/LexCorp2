# LexCorp — Complete Project Brief

This brief is written so that anyone in the team can build their own presentation without
reading the code. It covers:
- the problem statement;
- what LexCorp does and how it works;
- the technology;
- what is new about it;
- how it compares with existing products;
- the honest status of the prototype.

| | |
|---|---|
| Team | LexCorp |
| Team ID | 160076 |
| Problem statement | **SIH26125** — Blockchain-Based Secure Platform for Identity, Access Control, and Digital Asset Management |
| Category | Software |
| Suggested theme | Blockchain & Cybersecurity (confirm against the SIH portal) |
| Product name | **LexCorp**, "Asset Assurance & Custody" |
| One-line pitch | A permissioned-blockchain platform where every person has a self-owned cryptographic identity, every document and device is an NFT bound to its owner, every permission is enforced by a smart contract, every action leaves a tamper-proof trail, and nobody outside the organisation's network gets in without signing in again with the company login. |

---

## 1. The problem (from the problem statement)

Organisations rely on **centralised identity and access management**. That creates these risks:

- **Single point of failure.** One compromised identity server or admin account exposes everything.
- **Identity theft and unauthorised access.** A stolen password is often all an attacker needs, and misuse frequently goes unnoticed.
- **Editable logs.** Audit logs in a central database can be changed or deleted by whoever controls it.
- **Disconnected ownership records.** Digital and physical asset ownership sits in separate or semi-centralised systems (spreadsheets, asset registers, file shares). Proving *who owns what*, *who accessed what*, and *whether a record is authentic* is hard and unreliable.
- **Untraceable leaks.** Sensitive documents are copied and forwarded with no way to identify the source of a leak.

**What the problem statement asks for:**
- decentralised identifiers (DIDs) with cryptographic authentication;
- digital assets as NFTs bound to identities;
- smart contracts where only authorised administrators create and assign NFTs;
- role-based access control (RBAC) for Admin, Manager, Auditor and User, enforced by smart contracts;
- every operation recorded immutably: identity creation, NFT creation, allocation, access rights, transfers and permission changes.

**Who needs this:** defence establishments and defence PSUs, government departments,
research labs, and enterprises handling classified or regulated documents and equipment.

---

## 2. Our solution in one picture

```
 Remote person ──VPN (company sign-in at every connection)──┐
 Person on site ────────────────────────────────────────────┴─► LexCorp web app ──► Secure API (factors, approvals)
                                                                                        │
                                 ┌──────────────────────────────────────────────────────┼──────────────────────────┐
                                 ▼                                                      ▼                          ▼
                     AssetNFT smart contract                                Encrypted database              Audit + AI engine
                     on a private Hyperledger                               (files, personal data,          (append-only log, ledger
                     Besu blockchain                                        requests; only hashes           indexer, behavioural
                     (roles, NFTs, events)                                  go on-chain)                    risk model, alerts)
```

The pieces, and what each does:
- **Identity.** Each person is a wallet address with a DID, `did:ethr:13371:<wallet>`. They prove who they are by cryptographic signature, plus login factors.
- **Access control.** Admin, Manager, Auditor and User are real roles inside the smart contract, not just checks in our server.
- **Assets.** Every approved document or physical device is minted as a **unique NFT** bound to its owner's DID.
- **Trust.** Every sensitive action is recorded on the blockchain and in a database log that cannot be edited. Any copy of a document, or the label of any device, can be verified by scanning its QR code.
- **Reach.** LexCorp is never published on the internet. From outside, people connect through a VPN that asks for the company login at every connection.

---

## 3. Functionality, from start to finish

### 3.1 Identity lifecycle

1. **Registration by an administrator.** The admin enters name, role, department and the person's wallet address, and confirms with their own Factor 3.
   - Best practice: the person creates their own wallet in the browser, so **the admin never sees their private key**.
   - A "generate for them" path exists for people who can't, with an explicit warning.
2. **One-time provisioning PIN.** The system issues a single-use PIN that expires after 3 hours. It is stored only as a hash and shown once.
3. **Provisioning.** The person opens LexCorp, enters their wallet recovery phrase and the PIN. The wallet stays in their browser; the key never goes to the server.
4. **Mandatory enrolment before anything else works:**
   - **Login TOTP**: an authenticator app code (Microsoft or Google Authenticator);
   - **Login passkey**: WebAuthn/FIDO2, for example Windows Hello, a phone or a security key.
5. **Purpose-bound extra factors:**
   - **Factor 2**, for viewing and submitting;
   - **Factor 3**, for approving, minting, modifying, downloading and administration.

   By default each has its own authenticator entry and/or passkey. A person may instead choose to confirm Factor 2 or Factor 3 with their login factors, a choice that itself needs the login factor. Either way, **each proof is single-use and bound to one specific action**.
6. **Passkeys on every device.** A person can add a login passkey on each device they use (PC, laptop, phone; up to 10 per purpose). Adding or removing one needs the login factor, never just the session, and the last login passkey can only be replaced through an administrator reset. A passkey works only at the address where it was created (a browser rule that stops phishing), so everyone uses the same address locally and over the VPN.
7. **Sign-in.** Wallet address plus login TOTP or login passkey.
   - The session lives only in a secure HttpOnly cookie; the browser's JavaScript never sees a token.
   - **One session per account.** Signing in on a second device ends the first; both sides are recorded in the audit trail, and the first device's page signs out within 20 seconds with the reason.
   - The session ends after 15 minutes idle, after 30 minutes regardless, or if the network address changes. Over the VPN every connection gets a new address, so reconnecting means signing in again.
8. **Locked out?** The person requests a reset: from their identity page, or from the sign-in screen by signing the request with their wallet. An admin approves with Factor 3; old login factors are removed, a new PIN is issued and all sessions end. There is **no self-service reset** an attacker could abuse.
9. **Role change or revocation.** Done by an admin with Factor 3. The person's sessions end immediately, and their **on-chain roles are updated or removed automatically**.

### 3.2 Roles and departments (RBAC)

| Role | What they can do | On-chain roles granted automatically |
|---|---|---|
| **Admin** | Register identities, assign roles and departments, approve reset requests, revoke identities, approve assets, final stage of alert review | MINTER, ANCHOR, MANAGER |
| **Manager** | Register physical assets, approve or reject creations, downloads, modifications and delegations for their departments, sign mints with their own wallet, second stage of alert review | MINTER, ANCHOR, MANAGER |
| **Auditor** | Read the full audit trail, first stage of security-alert review (dismiss or forward), see sensitive physical-asset details | AUDITOR |
| **User** | Register documents (for approval), view their own and delegated documents, request downloads and modifications, delegate access to their documents | none |

- **Departments.** For example Avionics, Radar Systems and Cyber Security; admins can add more. Managers see only their departments, plus extra departments an admin grants them.
- **Where it is enforced:**
  - on the **server**, including department filtering in the database queries;
  - in the **smart contract**, whose role checks decide who can mint, anchor or transfer.
- The interface hides what a role can't use, but **security never depends on the interface**.
- **Separation of duties.** Nobody can approve their own submission, and nobody can decide on a security alert about themselves.

### 3.3 Digital assets (documents)

- **Supported formats:** PDF, Word (DOCX), PowerPoint (PPTX), Excel (XLSX) and images (PNG, JPEG).
- The file type is checked from the actual bytes, not the extension; the size limit is 50 MB.

**Step by step:**
1. **Register.** A user uploads a document with Factor 2.
   - The server computes its **SHA-256 fingerprint** and stores the file off-chain in the vault.
   - A creation ID is issued (`CRT-YYYYMMDD-NNNN`).
2. **Approve and mint.** A Manager or Admin reviews and approves with Factor 3.
   - **The approving officer's own wallet signs the blockchain transaction** that mints the NFT to the owner's DID, carrying the file hash.
   - The server records it only after checking the transaction receipt *and* the contract's resulting state.
3. **View.** Opening a document needs Factor 2 and produces a **fresh watermarked copy** with a view ID (`VW-…`). The watermark shows:
   - "CONFIDENTIAL";
   - viewer name, short wallet address, network address, date and view ID;
   - a QR code;
   - a control page at the end.

   Office files are shown as a watermarked PDF, so the original file is never handed out just by viewing it.
4. **Delegate access.** The owner shares a document with another identity. A Manager approves and can set a **view limit** (for example 2 views) and an **expiry time**. Viewing and downloading are separate permissions.
5. **Controlled download:**
   - the requester asks, with Factor 2;
   - the **owner consents**, with Factor 3;
   - a **Manager approves**, with Factor 3;
   - the requester fetches it with Factor 3, **once only** (download ID `DL-…`).

   The downloaded file carries a watermark naming who downloaded it and the owner.
6. **Modify:**
   - the user requests a modification copy (`MOD-…`), which a Manager approves;
   - they edit it offline and upload the revision with Factor 3;
   - LexCorp checks the returned copy's watermark and QR against its own record, removes its watermark layers, and the revision is approved and **anchored on-chain as version 2** of the same NFT.

   Originals are never overwritten, the full version history is kept, and later copies list the modification history. A returned copy whose watermark was edited is refused and raises a tamper alert with the evidence.
7. **Every action has an ID and a QR.** Anyone who scans the QR on a printed or forwarded copy sees whether it is authentic. Signed-in employees see more detail, depending on their role.

**Watermarking per format:**
- **PDF:** a diagonal mark and a QR on every page, plus a control page.
- **Word and PowerPoint:** native watermark shapes, plus a control section or slide.
- **Excel:** header and footer plus a control sheet, **keeping charts, pivots and images intact**.
- **Images:** a tiled mark plus an information band with a QR.

### 3.4 Physical assets (equipment)

1. **Register (Manager or Admin).** Serial number, **MAC address *or* a unique device address**, department, location and custodian.
   - Uniqueness is enforced across the whole registry, including different notations. For example, `02:1A:2B…` and `021a2b…` count as the same MAC.
   - A duplicate attempt is refused and raises exactly one security alert. The raw identifier is never written to logs, only a fingerprint.
2. **Approve and mint.** Another officer approves with Factor 3, and the device becomes an **NFT** assigned to the custodian's DID.
3. **NFT card.** A downloadable card with exactly five fields: serial number, token ID, creation date, department and QR. No sensitive data.
4. **QR check.** Scanning the device's QR with a phone shows "Registered LexCorp asset, confirmed on the ledger" with minimal public fields. Signed-in staff see more, depending on role.
5. **Role-based redaction.** MAC address, device address and location are visible to Managers and Auditors, but hidden from ordinary custodians and the public.
6. **Lifecycle.** Status changes (for example Active, Maintenance, Retired) need Factor 3. There is a maintenance log and a timeline, and everything is audited.

### 3.5 Security alerts: AI plus rules, humans decide

**Two sources of alerts:**
1. **Deterministic integrity rules** (always on), for example:
   - a mint that wasn't approved;
   - a mint whose data doesn't match the approved record;
   - an anchor of an unapproved file hash;
   - an unexpected role grant on the contract;
   - a duplicate device registration;
   - a returned document copy whose watermark was edited;
   - misuse of the blockchain relay.
2. **AI-assisted risk analysis**, a local model (nothing leaves the organisation). Each action is judged **against the person's own habits over the last 30 days**, rebuilt from the audit trail. It uses 32 features, including:
   - time of day and weekend, and how far this is from the person's usual working hours;
   - today's volume against their usual day, and actions in the last hour;
   - downloads and copies, and their share of recent activity;
   - documents never touched before, and documents of other departments or other people;
   - refused or failed attempts (sign-ins, factor codes, access denials);
   - a network address not seen for this person in 30 days;
   - tamper and duplicate flags, the kind of action, and the person's role.

   **Two models, combined:**
   - an **Isolation Forest** that learns what ordinary work looks like and flags anything unusual, including misuse nobody simulated;
   - a **gradient-boosted classifier** (scikit-learn HistGradientBoosting) trained on labelled misuse scenarios.

   **How it behaves:**
   - Alert levels are fixed during training so that only about **0.1% of ordinary activity reaches HIGH**: the alert volume is predictable instead of "everything".
   - Every alert gives its reasons in plain words, for example "12 documents never touched before, in 24 h; 13 actions in the last hour (usual about 3)".
   - **One incident, one alert:** a person has at most one open AI alert per 24 hours. It updates to the strongest evidence as the incident continues, and its severity only rises (each rise recorded).
   - Scored actions include document views, downloads, registrations, revisions, **sign-ins**, access grants, approvals and failed attempts.
   - Auditors' dismiss and revoke decisions can be exported as training labels to retrain the model on real activity.

   **Measured** on months of simulated activity for 3 organisations (244 people), trained on the earlier months and tested on the last 36 days:
   - 9 of 10 misuse scenarios caught in every attack, including a deliberately slow leak spread over a week; tampered returns are caught every time by the rules;
   - about **0.74 false alerts per 100 people per day**;
   - **79%** of HIGH alerts were real misuse;
   - ranking quality (ROC AUC) 0.992 (the anomaly detector alone: 0.960).

   An automated browser test (Playwright) also passed in the running app: ordinary work raised no alert, and a burst of 12 never-touched documents raised exactly one AI alert with plain-word reasons.

**Human escalation chain:**
- **Auditor** reviews first: dismiss with a note, or forward.
- The department **Manager** reviews next: dismiss, or forward.
- An **Administrator** makes the final decision. Only an admin can **revoke the identity**, with Factor 3.
- If no independent Manager covers the department, forwarding goes straight to the admin so the alert is never stuck, and the Auditor is told this before forwarding.

**What revocation does:**
- ends the person's live sessions immediately;
- blocks sign-in;
- removes their roles from the smart contract;
- keeps all their history.

**The AI never blocks or revokes anyone by itself**; it only advises.

### 3.6 Audit trail and ledger integrity

- **Append-only audit log.**
  - Database triggers reject any UPDATE, DELETE or TRUNCATE on the audit tables, even from the database owner.
  - Every event records the actor, the actor's role **at that moment**, time, asset, network address, result, risk and alert state.
  - **Every event has a risk level** and shows where it came from: scored by the AI, set by an integrity rule, or a baseline from the event type (routine events LOW, sensitive ones such as PIN reissues, login resets, revocations and role changes MEDIUM).
  - Filters: category, role, risk, result, escalation, asset, identity and date range.
- **Blockchain indexer.** Continuously reads contract events, de-duplicates them, verifies its position against the chain, and cross-checks every on-chain event against the approved records in the database. Mismatches raise alerts.
- **Role reconciliation.** A background job makes sure the roles on the smart contract always match the identity registry, and removes "orphan" roles no one should hold.
- **Integrity check script.** One command checks the whole environment (9 checks):
  - the contract deployment (chain, bytecode, registrar role);
  - the database schema;
  - the audit triggers;
  - no plaintext secrets;
  - no plaintext provisioning PINs;
  - every recorded asset matches the blockchain (serial, hash, owner);
  - the indexer position;
  - on-chain roles match the registry;
  - no alert parked at a stage nobody covers.

### 3.7 Remote access: VPN with the company login at every connection

LexCorp is **never published on the internet**. People on the organisation's network reach it
directly; people outside connect through a VPN, and **every connection asks for the company
login**.

1. **First time:** the person signs in to the company portal and downloads the VPN profile.
   - For the demo, a stand-in portal (clearly labelled as a demonstration, no real company's branding) runs at `lexcorp-portal.vercel.app`, with "Sign in with Google" playing the company login. Only an allowlist of approved accounts can download.
   - In a real organisation this download sits behind its existing employee portal.
2. **Every connection:** OpenVPN opens the browser to the company login (Google for the demo). The connection is accepted only for a verified email on the allowlist. A VPN client that can't do the browser sign-in is refused, even with a valid profile.
3. **Connected:** the device gets its own address and a single route, to LexCorp over HTTPS. Nothing else on the network is reachable through the VPN, and the person's own internet traffic doesn't use it.
4. **Then** they sign in to LexCorp as usual: the VPN only gets them to the door.

**How it is built:**
- **OpenVPN Community Edition** with **openvpn-auth-oauth2** (open source) asking the identity provider. In a company, Google is swapped for the company's provider (Microsoft Entra ID, AD FS, Keycloak) through the same OIDC standard.
- A **public gateway** (a free Oracle Cloud VM) runs the VPN and the sign-in page. The machine running LexCorp keeps an encrypted **WireGuard link** open to it, opened from inside, so it works even behind carrier-grade NAT with no ports opened at the site. This mirrors a real deployment: VPN appliance at the edge, application on the internal network.
- **Caddy** serves the app and the sign-in page with free **Let's Encrypt** certificates obtained through **DuckDNS**, so passkeys work remotely.
- Several devices can be connected at once, and **every connection gets a new address**, so devices are told apart in the audit trail and reconnecting ends the LexCorp session.
- Verified with a laptop on another network and a phone: portal sign-in and download, Google sign-in on connect, access granted, app reached.

---

## 4. Technical architecture

### 4.1 Technology stack

| Layer | Technology |
|---|---|
| Blockchain | **Hyperledger Besu**, a private permissioned Ethereum network: **QBFT** consensus, **3 validator nodes**, chain ID 13371, 2-second blocks, zero gas fees |
| Smart contract | **Solidity** ERC-721 "AssetNFT v3" using **OpenZeppelin 4.9 AccessControl, Pausable, ReentrancyGuard**; built and tested with **Hardhat** |
| Backend | **Python FastAPI**, SQLAlchemy (async), **PostgreSQL 16**, Alembic migrations, **web3.py** |
| Frontend | **React 18 + Vite**, **ethers.js v6** (wallet in the browser), WebAuthn passkeys, responsive design (desktop, tablet, phone) |
| Authentication | TOTP (RFC 6238, `pyotp`), WebAuthn/FIDO2 (`webauthn`), JWT session in an HttpOnly cookie bound to the network address, scrypt-hashed PINs |
| Encryption | Fernet/MultiFernet (AES-128-CBC + HMAC) with key rotation for secrets at rest; separate keys for sessions, credentials, data and the blockchain operator |
| Watermarking | ReportLab + pypdf (PDF), python-docx (Word), python-pptx (PowerPoint), package-level OOXML editing (Excel), Pillow (images), QR codes, OpenCV (reading QR codes on returned copies) |
| AI | scikit-learn **Isolation Forest** + **HistGradientBoosting classifier**, one shared feature builder for training and live scoring, thresholds fixed to a target false-alert share, plain-word explanations |
| Remote access | **OpenVPN Community Edition** + **openvpn-auth-oauth2** (OIDC sign-in per connection), **WireGuard** site link, **Caddy** with Let's Encrypt via **DuckDNS**, gateway on an **Oracle Cloud Always Free** VM, stand-in portal on **Vercel** |
| Verifiable credentials | W3C VC-style JWT credentials (KYC credential issuance via the API) |
| Testing | pytest (278 backend tests), Hardhat/Mocha (23 contract tests), live-blockchain tests, **Playwright** end-to-end browser verification (12 flows, plus an automated AI-alert test) |
| Infrastructure | Docker Compose (PostgreSQL, Besu nodes, VPN gateway and site); blockchain RPC and database bound to localhost only |

### 4.2 The smart contract (AssetNFT v3)

**Roles:**
- **DEFAULT_ADMIN**: the governance key, kept offline.
- **REGISTRAR**: the backend's operator key. It can only *grant and revoke* the operational roles below, and **can never hold them itself**, so a stolen server key cannot mint or alter assets.
- **MINTER, ANCHOR, MANAGER, AUDITOR**: the operational roles, held only by people's wallets.

**Functions:**
- `mint` (physical asset NFT), `mintDigitalAsset` (document NFT with file hash);
- `updateDigitalAsset` (anchor a new approved version);
- `transferAsset` (managed custody transfer, MANAGER only), and revoke.

**Rules and events:**
- **Free transfers and approvals are disabled.** An NFT moves only through a managed, role-checked transfer, so ownership can't be sold or moved off-platform.
- Every change emits an event: AssetMinted, DigitalAssetMinted, DigitalAssetUpdated, AssetTransferred, AccessPermissionGranted/Revoked, role events.
- The contract can be **paused** in an emergency.
- At every start, LexCorp checks that the deployed contract's bytecode is exactly the audited source.

**Proven on the live network:** an unauthorised wallet's mint is **rejected by the contract itself**. An authorised minter succeeds, and fails again once its role is revoked.

### 4.3 How a transaction flows (security path)

1. The officer clicks "Approve and sign". The browser asks for Factor 3.
2. The officer's wallet in the browser signs the mint transaction.
3. The transaction goes through LexCorp's **authenticated blockchain relay**. The relay:
   - checks the method is on an allow-list;
   - checks the signer is the logged-in person's own wallet;
   - checks the target is the LexCorp contract only.
4. Besu validators reach consensus with QBFT, so the block is final in about 2 seconds.
5. The server checks the receipt *and* reads the contract state back before marking the asset "recorded".
6. The indexer independently sees the event and cross-checks it against the approval.

### 4.4 Data placement (privacy by design)

- **On-chain:** token IDs, serial numbers, file **hashes**, owner **DIDs**, roles and events. No names, no files, no MAC addresses.
- **Off-chain:** files, TOTP secrets (encrypted), personal details and request data, in PostgreSQL and file storage on the organisation's own machine.
- This supports data protection law such as India's **DPDP Act 2023**: personal data stays erasable and controllable off-chain, while its integrity proof is on-chain.

### 4.5 Hardening

- The app **refuses to start in production** if any secret is missing, weak or shared between purposes, if debug mode is on, or if an origin is not HTTPS. The default mode is production, so it fails closed.
- The blockchain RPC listens only on localhost, exposes only read and consensus APIs, rejects cross-origin browser access, and has admin and debug methods disabled.
- The database listens only on localhost, with a generated password.
- Remote access only through the VPN (above); the app itself has no public port.
- Security headers are set, and uploads are limited to types the system can watermark.
- A container image of the backend is built and runs as a non-root user (ledger features in the container not yet verified).

---

## 5. Innovation and uniqueness

1. **Identity, access control and asset ownership in one platform.** Most products do one of these; LexCorp links all three through the same DID and the same smart contract.
2. **RBAC enforced by the blockchain itself.** Roles live in the smart contract, and our own server key *cannot* mint. Even a fully compromised backend can't forge asset ownership.
3. **Human-signed transactions.** The approving officer's own wallet signs every mint, so the ledger proves *which person* approved each asset, not just "the system".
4. **Purpose-bound, single-use factors.** Separate proofs for logging in, for viewing and submitting, and for approving and administering. Each proof works for exactly one action. Stealing one factor, or replaying one, doesn't unlock anything else.
5. **Traceable documents.** Every view and download is a unique watermarked copy with a QR code, so a leaked photo or printout identifies its source. Tampering with the watermark is detected and refused.
6. **Controlled sharing.** Delegation with view limits and expiry. Downloads need the owner's consent *and* a manager's approval, and can be fetched only once.
7. **Physical assets as NFTs.** Equipment is bound to a serial and MAC or unique address, with global duplicate detection, QR labels and role-based redaction. This bridges digital and physical custody in one registry.
8. **Behavioural AI that judges each person against their own habits**, measured rather than assumed: about 0.74 false alerts per 100 people per day on simulated data, one alert per incident with plain-word reasons, and humans deciding along Auditor → Manager → Admin.
9. **Company login at the network door.** Remote access through a VPN that asks the company's identity provider at every connection, with a fresh address per connection so every remote action is traceable to a device.
10. **Continuous self-verification.** An indexer and a role reconciler constantly compare the blockchain, the database and the identity registry, and flag any drift.
11. **Permissioned, zero-fee and fast.** Private Besu QBFT gives blockchain trust without public exposure, gas costs or slow finality.
12. **Tamper-proof even inside the database.** Audit tables reject edits and deletes at the database level, not just in the application.

---

## 6. Existing products, and how LexCorp is different

These are established, mature products, each strong at what it does. LexCorp's difference is
that it **combines** identity, on-chain access control, asset ownership and document traceability,
all anchored on a permissioned blockchain.

| Category | Examples | What they do well | Gap that LexCorp addresses |
|---|---|---|---|
| Centralised identity & access (IAM / SSO) | Microsoft Entra ID (Azure AD), Okta, Ping Identity | Mature single sign-on, MFA, conditional access | A central authority and a central log: whoever controls the server controls identities and the history. No ownership record for assets. LexCorp uses self-owned wallet identities and on-chain roles, with an immutable trail (and can still use the organisation's SSO at the VPN door). |
| Identity governance | SailPoint, Saviynt | Access reviews, provisioning workflows | Governance records live in a central database; no cryptographic proof of who approved what, and no asset provenance. |
| Self-sovereign identity (SSI) | Hyperledger Indy/Aries (Sovrin), Microsoft Entra Verified ID, Privado ID (Polygon ID) | Decentralised identifiers and verifiable credentials | Focus on *proving identity*. They don't enforce organisation RBAC over assets or manage asset NFTs and document control. LexCorp uses DIDs *and* ties them to on-chain roles and asset ownership. |
| IT asset management | ServiceNow ITAM, Snipe-IT | Asset inventories, lifecycle tracking | Records are editable in a central database, and there's no public or QR proof of authenticity. LexCorp mints each device as an NFT with unique hardware identifiers and QR verification. |
| Document protection / DRM | Microsoft Purview Information Protection, Adobe Document Cloud | File encryption, sensitivity labels, access policies | Tied to one vendor's cloud and central logs. LexCorp adds per-copy forensic watermarks and QR, on-chain hash anchoring and version history, and an approval chain for every download. |
| Blockchain provenance | Hyperledger Fabric solutions (for example IBM Food Trust), VeChain, Guardtime KSI | Supply-chain provenance, data-integrity timestamps | Usually provenance only, without identity management, multi-factor access control, or document viewing and download control. |
| Government document platforms (India) | DigiLocker | Issuance and verification of official documents for citizens | A citizen-document service run by a central authority, not an organisation's internal access control, asset custody and audit system. |

**In one sentence:** existing tools make you trust the operator of a central system. LexCorp
makes the rules (roles, ownership, history) **verifiable by cryptography and enforced by a smart
contract**, while keeping sensitive data private inside the organisation.

---

## 7. Feasibility and viability

**Already built:** LexCorp is a working prototype, not a concept.

| Evidence | Result |
|---|---|
| Automated backend tests (API, security, workflows, database, AI, sessions) | 278 passed |
| Smart-contract authorisation tests | 23 passing |
| Live blockchain tests (real transactions on Besu) | 3 passed; an unauthorised mint is rejected on-chain |
| End-to-end browser verification (Playwright, 4 roles, desktop/tablet/phone) | 12 of 12 flows passed; 12 defects found and fixed |
| AI risk model, measured on simulated activity (36 held-back days, 244 people) | 9 of 10 misuse scenarios caught every time; about 0.74 false alerts per 100 people per day; 79% of HIGH alerts real misuse |
| Automated AI-alert test in the running app (Playwright) | Passed: no alert for ordinary work, one explained alert for a burst |
| Remote access (VPN with Google sign-in, from another network and a phone) | Connected and reached the app; unapproved clients refused |
| Environment integrity check | 9 checks |
| Dependency security audit (Python) | No known vulnerabilities |

**Why it is feasible:**
- **Open-source stack.** No licence costs (Besu, OpenZeppelin, FastAPI, PostgreSQL, React, OpenVPN, WireGuard, Caddy).
- **Zero gas fees** on the permissioned chain, so cost doesn't grow with usage.
- **Zero running cost for the demo:** Oracle Cloud Always Free (VPN gateway), Vercel Hobby (portal), DuckDNS and Let's Encrypt (names and certificates).
- **Runs on modest hardware:** one server for a pilot, and the VPN gateway runs on a free 1 GB cloud VM; add validators and nodes to scale.
- **Works in any modern browser** on desktop or phone, with passkeys through Windows Hello, Android or iPhone, and OpenVPN Connect on phones and laptops.
- **Deployable on-premises** for air-gapped or defence environments; nothing depends on a public blockchain.

**Risks and how we handle them:**

| Risk | Mitigation |
|---|---|
| Stolen or lost keys and passwords | Separate factors per purpose (TOTP + passkey); admin-approved reset with a new PIN; governance and server keys split and rotatable |
| Unauthorised NFT minting | Role checks inside the contract; the server key can't mint; the officer's own wallet signs; the indexer flags any unapproved mint |
| An insider leaks a document | Per-copy watermarks with viewer, time and QR; view limits and expiry; approvals for downloads; behavioural AI and rule alerts |
| Access from outside the organisation | No public port; VPN with the company login at every connection and an allowlist; each connection gets its own address |
| One account used from two places | One session per account; the takeover is recorded on both sides and the older device is signed out |
| Personal data on an immutable ledger | Only hashes and DIDs on-chain; personal data off-chain (DPDP-friendly) |
| Non-technical users and crypto wallets | In-browser wallet creation, passkeys (Windows Hello or phone), plain-language interface |
| A validator node fails | QBFT tolerates node faults as validators are added (production: 4 or more validators across sites) |
| AI false alarms | Thresholds fixed to a small, known false-alert share; one alert per incident; humans review; the AI can't act alone |

---

## 8. Impact and benefits

**Who benefits:**
- **Organisations** (defence, PSUs, government, R&D): no single point of failure, provable custody of every document and device, faster audits, and leak traceability.
- **Administrators:** grant and revoke access in one step, enforced on-chain immediately. Revocation ends sessions everywhere.
- **Auditors:** a complete, tamper-proof history of who did what, when and from where, with a risk level on every event, searchable in seconds.
- **Employees:** one self-owned identity, passwordless passkey sign-in on each of their devices, and remote access with the login they already have.
- **External verifiers** (inspection teams, partners): scan a QR to confirm authenticity without accessing internal systems.

**What it delivers:**
- **Security:** tamper-proof records, traceable leaks, no shared passwords, insider misuse detected early, and no internet exposure.
- **Economic:** open source, no gas fees, less fraud and asset loss, and lower audit and compliance effort.
- **Operational:** faster, trackable approvals, instant QR verification, and one registry for digital and physical assets.
- **Compliance:** supports DPDP Act 2023 privacy principles, NIST SP 800-63B-style authentication, and audit readiness.

---

## 9. Demo walkthrough (for slides or a video)

1. The Admin registers a Manager, an Auditor and two Users. Each receives a one-time PIN.
2. A User creates a wallet in the browser, provisions it with the PIN, and enrols an authenticator app and a Windows Hello passkey.
3. The User uploads a PDF (Factor 2). The Manager approves, and their wallet signs the mint. The block number appears.
4. The User views the document and sees the watermark with their name, network address, date, view ID and QR.
5. The User delegates the document to a colleague with a 1-view limit. The second view is refused.
6. A download request goes through owner consent, then manager approval, then a one-time fetch. The file is watermarked with a DL ID.
7. The Manager registers a device by MAC address. A duplicate in a different notation is refused and an alert is raised.
8. The device is approved and minted. A phone scans its QR and sees "confirmed on the ledger".
9. **Remote access:** on a laptop on another network, sign in to the company portal, download the VPN profile, connect (Google sign-in), and open LexCorp. An unapproved Google account is refused.
10. A user suddenly opens many documents they have never touched: one AI alert appears with plain-word reasons. It goes Auditor → Manager → Admin, and the Admin revokes the identity. The user's live session ends, and their on-chain roles are removed.
11. The Auditor filters the tamper-proof audit trail, with a risk level on every event. An attempt to delete audit rows directly in the database fails.

**Screenshots:** `docs/evidence/playwright/` (dashboard, watermarked view, mobile verify page,
physical asset, alerts, AI alert, audit and others).

---

## 10. Honest status and future work

**Implemented and verified by automation:** everything in sections 3 and 4, except the items below.

**Needs human testing** (the manual checklist, `backend/Final_Manual_Test_Checklist.md`, is ready and the team is running it):
- Windows Hello and real authenticator apps on several devices;
- scanning QR codes with a real phone camera;
- opening watermarked Word, PowerPoint and Excel files in desktop Office;
- the remote-access refusals (an unapproved account, a client without browser sign-in) recorded as evidence;
- a screen-reader accessibility check.

**Partial or future work:**
- **AI detection quality is measured on simulated data only.** The method works on these patterns; how well it does on a real organisation needs real activity reviewed by Auditors, whose decisions feed retraining. New people look unusual in their first days, because they have no history yet.
- **Custody transfer between owners** is supported by the smart contract (`transferAsset`, MANAGER only) and a backend helper, but a full user-interface workflow for it is future work.
- **Verifiable credentials:** KYC credential issuance exists at API level (JWT format, HMAC-signed). A wallet-held credential flow and asymmetric signatures are future work.
- **Office viewing** shows a text rendering of Word, PowerPoint and Excel files as a watermarked PDF; the layout is not reproduced. Downloads keep the original format.
- **Production deployment:** 4 or more validators across sites, a hardware security module for the governance key, per-person VPN certificates from the organisation's PKI, and verifying ledger features inside the container.
- Future ideas: mobile app, IoT tags or NFC for devices, and multi-organisation federation of Besu networks.

---

## 11. References

1. W3C, *Decentralized Identifiers (DIDs) v1.0* — https://www.w3.org/TR/did-core/
2. DIF, *did:ethr method / ethr-did-resolver* — https://github.com/decentralized-identity/ethr-did-resolver
3. W3C, *Verifiable Credentials Data Model 2.0* — https://www.w3.org/TR/vc-data-model-2.0/
4. EIP-721, *Non-Fungible Token Standard* — https://eips.ethereum.org/EIPS/eip-721
5. OpenZeppelin, *Access Control* — https://docs.openzeppelin.com/contracts/4.x/access-control
6. Hyperledger Besu documentation, QBFT consensus — https://besu.hyperledger.org
7. W3C, *Web Authentication (WebAuthn) Level 2* / FIDO2 — https://www.w3.org/TR/webauthn-2/
8. IETF RFC 6238, *TOTP: Time-Based One-Time Password Algorithm* — https://www.rfc-editor.org/rfc/rfc6238
9. NIST SP 800-63B, *Digital Identity Guidelines: Authentication* — https://pages.nist.gov/800-63-3/
10. F. T. Liu, K. M. Ting, Z.-H. Zhou, *Isolation Forest*, IEEE ICDM 2008 — https://doi.org/10.1109/ICDM.2008.17
11. scikit-learn, *HistGradientBoostingClassifier* — https://scikit-learn.org/stable/modules/ensemble.html#histogram-based-gradient-boosting
12. OpenID Foundation, *OpenID Connect Core 1.0* — https://openid.net/specs/openid-connect-core-1_0.html
13. OpenVPN Community Edition — https://openvpn.net/community/ ; openvpn-auth-oauth2 — https://github.com/jkroepke/openvpn-auth-oauth2
14. WireGuard — https://www.wireguard.com
15. *Digital Personal Data Protection Act, 2023* (India) — https://www.meity.gov.in
16. OWASP *Application Security Verification Standard (ASVS)* — https://owasp.org/www-project-application-security-verification-standard/

---

## 12. Glossary (for non-technical slides)

- **Blockchain (permissioned):** a shared ledger run by approved computers (validators) that agree on every record, so no single party can quietly change history.
- **DID (decentralised identifier):** an ID the person owns, derived from their wallet, proven by a cryptographic signature rather than a password stored on a server.
- **Wallet:** the person's private key, which signs actions. In LexCorp it stays in their browser.
- **NFT (non-fungible token):** a unique digital token. Here, one per document or device, recording who owns it.
- **Smart contract:** a program on the blockchain that enforces rules automatically, such as who may mint.
- **RBAC:** role-based access control, where permissions depend on your role (Admin, Manager, Auditor, User).
- **QBFT:** the agreement method the validators use; final in seconds and tolerant of node failures.
- **TOTP:** the 6-digit code from an authenticator app that changes every 30 seconds.
- **Passkey (WebAuthn/FIDO2):** passwordless sign-in with Windows Hello, a phone or a security key.
- **Hash (SHA-256):** a unique fingerprint of a file. Any change to the file changes the hash.
- **Watermark:** visible marks on a copy identifying who opened it, when, and a QR to verify it.
- **Isolation Forest:** a machine-learning method that learns what normal behaviour looks like and spots what doesn't fit, without needing examples of attacks.
- **Gradient-boosted classifier:** a machine-learning method that learns known misuse patterns from labelled examples.
- **VPN:** an encrypted tunnel from a device to the organisation's network. In LexCorp, connecting asks for the company login every time.
- **OIDC (OpenID Connect):** the standard that lets one system ask a company's login service (Google, Microsoft Entra ID, Keycloak) who a person is.
