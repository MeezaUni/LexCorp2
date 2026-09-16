# 🛡️ LexCorp — Enterprise Blockchain Identity & Asset Management Platform

> **Smart India Hackathon (SIH 2026)**  
> **Problem Statement ID:** 26125  
> **Organization:** Bharat Electronics Limited (BEL), Ministry of Defence  
> **Team:** LexCorp  

---

## 📌 Executive Summary

LexCorp is an air-gapped, zero-trust enterprise security platform combining **W3C Decentralized Identifiers (DID)**, **W3C Verifiable Credentials (VC 2.0)**, **ERC-721 On-Chain Digital Asset Twins**, and **Embedded Local AI Anomaly Detection** to secure defense assets, supply chain provenance, and mission-critical access control.

---

## 🏛️ Enterprise Architecture & Design Principles

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

### 1. Non-Custodial Zero-Trust Security
- **The backend never custodies a private key.** All state-changing operations (minting, transfers, revocations, and role delegations) are signed client-side via hardware cryptographic signers.
- **Enterprise Transition Note:** While the interactive hackathon demo utilizes browser-based Web3 signers (MetaMask), an enterprise defense deployment replaces this with **FIPS 140-2 Level 3 Hardware Security Modules (HSMs)**, **PIV/CAC Smart Cards via WebHID**, or **WebAuthn/Passkeys backed by device TPMs**.

### 2. Zero-Gas Enterprise Consortium Blockchain
- Runs on private enterprise EVM networks (**Hyperledger Besu / ConsenSys Quorum / Polygon Edge**) using **QBFT/IBFT 2.0** consensus.
- Gas price is configured to `0 wei` with zero monetary tokens, eliminating financial speculation, regulatory hurdles, and network congestion.

### 3. W3C DID & Verifiable Credentials (VC 2.0)
- Identity is mapped to standard **W3C DIDs** (`did:ethr:<chainId>:<address>`).
- Personnel credentials (e.g., clearance level, operator authorization) are issued as cryptographically signed **JWT-VCs** conforming to W3C VC 2.0 standards.

### 4. Cryptographic Asset Tagging (QR Verification)
- High-security physical assets are tagged with dynamic, tamper-evident cryptographic QR codes.
- Anyone can scan the QR tag to trigger the `/verify/:serial` public registry check directly against the smart contract.

### 5. Embedded Air-Gapped AI Risk Engine
- Anomaly detection is performed entirely **locally** via an embedded `IsolationForest` machine learning model.
- **Zero Cloud AI Dependencies:** No data is transmitted to third-party cloud APIs (OpenAI, AWS, etc.), adhering strictly to defense air-gap protocols.
- Evaluates real-time event frequency, velocity, and parameter anomalies, tagging each indexed event as **LOW**, **MEDIUM**, or **HIGH** risk.

---

## 🚀 Quick Start (Local Setup)

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
- Health check: `http://localhost:8000/health`

### 4. Start React Frontend (Terminal 4)
```bash
cd frontend
npm install
npm run dev
```
- Web Application: `http://localhost:5173`

---

## 🧪 Verification & Feature Walkthrough

### 1. Asset Minting & QR Generation (Manager View)
1. Navigate to `http://localhost:5173` and connect wallet.
2. Under the **Manager Dashboard**, enter an Asset Serial (e.g., `BEL-RADAR-2026-001`).
3. Click **Mint Digital Twin on Blockchain** and approve the transaction.
4. The cryptographic QR code is generated dynamically.

### 2. Public On-Chain Verification
1. Scan the QR code or navigate to `http://localhost:5173/verify/BEL-RADAR-2026-001`.
2. Inspect on-chain metadata, owner DID, and real-time validity status.

### 3. AI-Powered Auditor Trail (Auditor View)
1. Switch to the **Auditor Dashboard** tab.
2. Observe real-time block indexing of the `AssetMinted` event.
3. Check the **AI Risk Assessment** badge (`LOW`, `MEDIUM`, or `HIGH`) evaluated by the local `IsolationForest` model.

---

## 🔒 Security Compliance Matrix

| Requirement | LexCorp Implementation |
|---|---|
| **Identity Standard** | W3C DID v1.1 (`did:ethr`) |
| **Credential Standard** | W3C VC 2.0 (JWT-VC) |
| **Key Custody** | Strict Client-Side Non-Custodial |
| **Blockchain** | Zero-Gas Permissioned Consortium EVM |
| **Audit Trail** | Immutable Event-Sourced Indexer |
| **AI Anomaly Detection** | Air-Gapped Local Scikit-Learn Model |

---

## 👥 Team LexCorp
Built with ❤️ for **Smart India Hackathon 2026**.
V2 Initialized
