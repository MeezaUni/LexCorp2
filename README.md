#  LexCorp — Enterprise Blockchain Identity & Asset Management Platform

> **Smart India Hackathon (SIH 2026)**  
> **Problem Statement ID:** 26125  
> **Organization:** Bharat Electronics Limited (BEL), Ministry of Defence  
> **Team:** LexCorp  

---

##  Executive Summary

LexCorp is an air-gapped, zero-trust enterprise security platform combining **W3C Decentralized Identifiers (DID)**, **W3C Verifiable Credentials (VC 2.0)**, **ERC-721 On-Chain Digital Asset Twins**, and **Embedded Local AI Anomaly Detection** to secure defense assets, supply chain provenance, and mission-critical access control.

The platform now features an integrated security governance workflow including biometric-backed **Passkey authentication**, a tiered **security incident escalation system**, secure **asset sharing with view quotas**, and a **document-revision-and-approval lifecycle**.

---

##  Enterprise Architecture & Design Principles

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
- **Factor 1 (SIWE)**: Cryptographic wallet signature for session initiation.
- **Factor 2**: WebAuthn/Passkey or 6-digit TOTP for asset proposals, sharing requests, and document revisions.
- **Factor 3 (Critical)**: WebAuthn/Passkey or 6-digit TOTP required for Manager/Admin approvals, direct asset minting, and security revocation actions.
- **Passkey Support**: Integrated WebAuthn support across all forms as an alternative to TOTP for improved UX and security.

### 2. Governance & Security Workflows
- **Tiered Security Incident Escalation**: 
    - Alerts are triaged by Auditors.
    - **Forward to Manager**: Auditor -> Manager.
    - **Escalate to Admin**: Manager -> Admin.
    - **Revoke Identity**: Admin can trigger identity revocation for critical threats.
- **Share View Quotas**: When sharing assets, managers can optionally enforce `max_views`. The backend enforces these limits via `AssetAccessGrant` tracking.
- **Document Revision lifecycle**: Proposed modifications (`MODIFICATION` action types) are stored as pending proposals requiring Factor-3 approval before on-chain asset updates.

---

##  Quick Start (Local Setup)

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
| **Authentication** | SIWE + WebAuthn/Passkey + TOTP |
| **RBAC** | `USER`, `MANAGER`, `ADMIN`, `AUDITOR` |
| **Key Custody** | Strict Client-Side Non-Custodial |
| **Blockchain** | Zero-Gas Permissioned Consortium EVM |
| **Security Alerts** | State-Machine (OPEN -> FORWARDED -> ESCALATED -> RESOLVED) |
| **Access Control** | Deterministic View Quotas + On-Chain RBAC |
| **AI Anomaly Detection** | Air-Gapped Local Scikit-Learn Model |

---

## 👥 Team LexCorp
Built with ❤️ for **Smart India Hackathon 2026**.
V2.1 - Enhanced Security Governance Implementation.
