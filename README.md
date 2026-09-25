#  LexCorp — Enterprise Blockchain Identity & Asset Management Platform

> **Smart India Hackathon (SIH 2026)**  
> **Problem Statement ID:** 26125  
> **Organization:** Bharat Electronics Limited (BEL), Ministry of Defence  
> **Team:** LexCorp  

---

##  Executive Summary

LexCorp is an air-gapped, zero-trust enterprise security platform designed specifically for defense contractors and supply chain provenance. It combines **W3C Decentralized Identifiers (DID)**, **W3C Verifiable Credentials (VC 2.0)**, **ERC-721 On-Chain Digital Asset Twins**, and an **Embedded Local AI Anomaly Detection Engine** to secure defense assets and mission-critical access control.

The platform provides a sovereign infrastructure for identity, authorization, and asset lifecycle management—all governed by deterministic smart contracts and strict off-chain multi-factor authentication policies.

---

## Detailed Enterprise Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 CLIENT-SIDE INTERFACE                                  │
│  ┌───────────────────────┐   ┌───────────────────────┐   ┌──────────────────────────┐  │
│  │   Manager Dashboard   │   │   Auditor Dashboard   │   │  Public QR Verification  │  │
│  │  (Mint/Transfer Asset)│   │  (Immutable AI Stream)│   │   (/verify/:serial)      │  │
│  └───────────┬───────────┘   └───────────┬───────────┘   └────────────┬─────────────┘  │
└──────────────┼───────────────────────────┼────────────────────────────┼────────────────┘
               │ (Non-Custodial Signatures)│                            │
               ▼                           │ (Read-Only Queries)        │
┌──────────────────────────────┐           │                            │
│  ENTERPRISE BLOCKCHAIN LAYER │           │                            │
│  - EVM Smart Contracts       │           │                            │
│  - ERC-721 Digital Twin      │           │                            │
│  - On-Chain RBAC Access Ctrl │           │                            │
│  - Zero-Gas / IBFT2 Private  │           │                            │
└──────────────┬───────────────┘           │                            │
               │ Emits On-Chain Events     │                            │
               ▼ (AssetMinted/Transferred) │                            │
┌──────────────────────────────────────────┼────────────────────────────┼────────────────┐
│           AIR-GAPPED BACKEND & AI ENGINE │ (FastAPI)                  │                │
│  ┌───────────────────────────────────┐   │                            │                │
│  │ Event Indexer (Idempotent Poller) ├─┐ │                            │                │
│  └───────────────────────────────────┘ │ │                            │                │
│  ┌───────────────────────────────────┐ │ │   ┌────────────────────────┴──────────────┐ │
│  │ Embedded Local AI Risk Engine     │◄┴─┼───┤ REST API Endpoints                    │ │
│  │ (IsolationForest / Scikit-Learn)  │   │   │ - GET /api/audit/events               │ │
│  └───────────────────────────────────┘   │   │ - GET /api/assets/serial/:serial/qr   │ │
│  ┌───────────────────────────────────┐   │   │ - POST /api/auth/verify-vc            │ │
│  │ Local SQLite / Audit Trail DB     │◄──┘   └───────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. Multi-Factor Authentication (MFA) Hierarchy

Central to the Zero-Trust posture is our 3-tiered authentication requirement. A user must step up authentication as the risk of the action increases.
- **Factor 1 (Session / Verification)**: Cryptographic wallet signature via `Sign-In with Ethereum (SIWE)`. Proves possession of the private key map to a specific `did:ethr`.
- **Factor 2 (Read / Propose)**: WebAuthn/Passkey (Hardware-backed biometrics) or fall-back 6-digit TOTP. Required for viewing classified documents, proposing new asset creations, proposing to share an asset, or submitting document revisions.
- **Factor 3 (Critical / Executive)**: WebAuthn/Passkey or 6-digit TOTP enforced on the **approver** side. Required for Managers/Admins to approve sharing proposals, execute direct digital/physical asset minting, approve document revisions, or revoke a compromised identity.

*Technical Note on WebAuthn*: Passkey verification (`navigator.credentials.get`) uses ECDSA (P-256) keypairs securely stored in the user's TPM/Secure Enclave. The backend (`FIDO2` parser) issues dynamic challenges that prevent replay attacks. It acts as the primary biometric authentication layer seamlessly alongside the application, bypassing the need for manual TOTP entry when hardware support is present.

### 2. Tiered Security Incident Escalation & Triaging

Security alerts spawned from the AI Risk Engine or failed MFA attempts enter a strictly defined State Machine within the `AuditEvent` database model.
*   `OPEN`: The default state of a high-risk anomaly detected by the AI.
*   **Auditor Workflow**: Auditors actively monitor `OPEN` alerts. They can **"Dismiss"** false positives or **"Forward to Manager"** (`alert_status: FORWARDED_TO_MANAGER`).
*   **Manager Workflow**: Managers see forwarded alerts. They have contextual domain knowledge and can either **"Dismiss"** or **"Escalate to Admin"** (`alert_status: ESCALATED_TO_ADMIN`).
*   **Admin Workflow**: Admins intercept escalated tickets representing critical threats. They possess the button to **"Deactivate / Revoke Identity"** which programmatically invalidates the compromised user's session, disables their WebAuthn/TOTP secrets, and flags the `did:ethr` as revoked on-chain.

### 3. Share View Quotas & The Zero-Trust File Access Lifecycle

Instead of static, perpetual sharing, the sharing lifecycle introduces deterministic expiry and access limits.
1. `USER A` requests to share `Asset 1` with `USER B`.
2. A `DocumentAction` of type `SHARE` is logged as a proposal.
3. A `MANAGER` is prompted via Factor 3 approval to sign the action.
4. During approval, the Manager inputs an explicit **Max Allowed Views** constraint.
5. Upon approval, an `AssetAccessGrant` record is constructed off-chain storing `(asset_serial, grantee_did, max_views, views_count)`.
6. Whenever `USER B` fetches the document via `/api/assets/document/view/{asset_serial}`, the backend atomically increments the `views_count`. If `views_count >= max_views`, access is HTTP 403 Forbidden—even if the on-chain registry still technically considers them an active viewer.

### 4. Document Revision Control & Approval Pipeline

When a user modifies a registered asset/document:
1. They propose a revision via `/api/assets/document/revise/propose`, storing the new hash and IPFS CID/metadata in a `MODIFICATION` action.
2. An authorized Manager/Admin intercepts the `MODIFICATION` request in their pending queue.
3. Upon verifying the new hash, the Manager clicks "Approve". 
4. The system dynamically generates an **unsigned calldata payload** (`prepareUpdateDigitalAssetCalldata`) representing the on-chain update.
5. The Manager signs the transaction directly via MetaMask. The backend never handles the manager's private key. The on-chain `Asset` is then updated to point to the new hash, effectively versioning the document.

### 5. Blockchain Layer (Enterprise EVM)
- Runs on **Hyperledger Besu** in a private network configuration using **QBFT/IBFT 2.0 consensus**.
- **Zero-Gas / Feeless Environment**: The gas price limit is configured to `0 wei`. There are no tokens, cryptocurrencies, or transaction costs, bypassing financial compliance hurdles and ensuring high enterprise throughput.
- Acts specifically as an immutable registry for digital twins (ERC-721 wrappers) and an authorization manifest, abstracting away massive file storage (which is kept off-chain but immutably hashed on-chain).

### 6. Air-Gapped AI Risk Engine
- Built explicitly for defense deployments containing **NO third-party cloud dependencies** (No AWS AI, No OpenAI).
- Utilizes `scikit-learn` `IsolationForest` natively embedded within the Python FastAPI backend.
- It actively evaluates indexed `AssetMinted`, `Transfer`, and `AccessAttempted` events evaluating attributes like IP velocity, geographic impossibility (if IPs are tracked in future updates), role mismatched access patterns, and time-of-day anomalies.
- Flags events with `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` `risk_labels` in real-time.

---

## Quick Start (Local Setup)

### Prerequisites
- Node.js v18+
- Python 3.10+
- Git

### 1. Start Local Blockchain (Terminal 1)
```bash
cd contracts
npm install
npx hardhat node
```

### 2. Deploy Smart Contracts (Terminal 2)
```bash
cd contracts
npx hardhat run scripts/deploy.js --network localhost
```

### 3. Start Air-Gapped Backend & AI Indexer (Terminal 3)
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8000
```
- API Documentation: `http://localhost:8000/docs`

### 4. Start React Frontend (Terminal 4)
```bash
cd frontend
npm install
npm run dev
```
- Web Application: `http://localhost:5173`

---

##  Security Compliance Matrix

| Requirement | LexCorp Implementation |
|---|---|
| **Identity Standard** | W3C DID v1.1 (`did:ethr`) |
| **Authentication** | SIWE + WebAuthn/Passkeys (TPM-backed) + TOTP |
| **RBAC** | `USER`, `MANAGER`, `ADMIN`, `AUDITOR` |
| **Key Custody** | Strict Client-Side Non-Custodial Calibration |
| **Blockchain** | Zero-Gas Permissioned Consortium EVM (IBFT2) |
| **Security Alerts** | State-Machine Triaging (OPEN -> FORWARDED -> ESCALATED -> RESOLVED) |
| **Access Control** | Deterministic View Quotas (`AssetAccessGrant`) + On-Chain Mapping |
| **AI Anomaly Detection** | Air-Gapped Local Scikit-Learn Model (`IsolationForest`) |

---

## 👥 Team LexCorp
Built with ❤️ for **Smart India Hackathon 2026**.
V2.1 - Enhanced Security Governance Implementation.
