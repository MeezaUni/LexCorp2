# LexCorp SIH V2 - Complete Project Overview

## What This Project Is
An enterprise-grade **Blockchain Identity & Asset Management Platform** built for Smart India Hackathon 2026. It uses a private Hyperledger Besu consortium network, ERC-721 NFTs for physical and digital asset tokenization, decentralized identity (DID) based access control, and an AI-powered behavioral anomaly detection engine for real-time risk scoring.

---

## Architecture Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Blockchain | Hyperledger Besu (QBFT PoA, Chain ID 13371) | Immutable asset registry & audit trail |
| Smart Contract | Solidity 0.8.24 + OpenZeppelin (ERC721, AccessControl) | AssetNFT with dual-layer RBAC |
| Backend | FastAPI (Python 3.14) + SQLAlchemy + SQLite | API layer, event indexer, AI risk engine |
| AI Engine | Scikit-learn IsolationForest | Real-time behavioral anomaly scoring |
| Frontend | React + Vite + ethers.js v6 + MetaMask | Dashboards for Admin/Manager/User/Auditor |
| Off-chain Storage | Local filesystem (secure vault) | Document storage with SHA-256 anchoring |

---

## Directory Structure

```
LexCorp-SIH-V2/
├── contracts/                  # Hardhat project
│   ├── contracts/AssetNFT.sol  # Main smart contract
│   ├── scripts/
│   │   ├── deploy.js           # Deploy contract
│   │   ├── seed_demo.js        # Seed demo assets
│   │   ├── grant_manager.js    # Grant MANAGER_ROLE
│   │   └── grant_roles.js      # Grant various roles
│   ├── deployments/localhost.json  # ABI + address (auto-generated)
│   ├── hardhat.config.js       # Network config (gasPrice: "auto")
│   └── package.json
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI app, lifespan, CORS
│   │   ├── core/config.py      # Settings from env vars
│   │   ├── core/database.py    # SQLAlchemy async engine
│   │   ├── models/domain.py    # User, Asset, AuditEvent, etc.
│   │   ├── api/
│   │   │   ├── assets.py       # /api/assets/* routes
│   │   │   ├── auth.py         # SIWE wallet auth + JWT
│   │   │   ├── users.py        # /api/users/* CRUD
│   │   │   ├── audit.py        # /api/audit/* event queries
│   │   │   └── indexer.py      # /api/indexer/* controls
│   │   ├── services/
│   │   │   ├── contract.py     # Web3 contract read/calldata prep
│   │   │   ├── ai.py           # IsolationForest anomaly engine
│   │   │   ├── auth.py         # JWT token logic
│   │   │   └── qr.py           # QR code generation
│   │   └── indexer/
│   │       └── event_indexer.py  # Polls blockchain events → DB
│   ├── offchain_storage/       # Uploaded documents stored here
│   ├── lexcorp_demo.db         # SQLite database (auto-created)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Router (React Router)
│   │   ├── context/AuthContext.jsx  # Wallet auth state
│   │   ├── pages/
│   │   │   ├── AdminDashboard.jsx      # User mgmt, role assignment
│   │   │   ├── ManagerDashboard.jsx    # Mint/Transfer/Revoke assets
│   │   │   ├── UserDashboard.jsx       # View assigned assets, download
│   │   │   ├── AuditorDashboard.jsx    # Audit trail + AI risk scores
│   │   │   ├── AssetRegistry.jsx       # Global asset list
│   │   │   ├── Identity.jsx            # DID/VC management
│   │   │   └── Verify.jsx             # Public asset verification
│   │   └── services/
│   │       ├── api.js          # Axios API client
│   │       └── web3.js         # ethers.js contract interactions
│   ├── vite.config.js          # Dev server + /api proxy → :8000
│   └── package.json
└── network/besu/               # Besu node config + Docker
    ├── docker-compose.yml      # 3-node QBFT cluster
    ├── networkFiles/genesis.json
    └── data/node{1,2,3}/       # Persistent blockchain data
```

---

## Smart Contract: AssetNFT.sol

**Address**: `0x5FbDB2315678afecb367f032d93F642f64180aa3` (changes on redeployment)
**Chain ID**: 13371
**Token Standard**: ERC-721 ("LexCorpEnterpriseAsset" / "LEXASSET")

### Roles (OpenZeppelin AccessControl)
- `DEFAULT_ADMIN_ROLE` → Deployed to deployer (`0xf39Fd...`)
- `MANAGER_ROLE` → Can mint, transfer, revoke assets
- `AUDITOR_ROLE` → Read-only compliance access to all assets

### Key Functions
| Function | Access | Description |
|----------|--------|-------------|
| `mint(to, tokenId, serial, ownerDID)` | MANAGER | Physical asset NFT |
| `mintDigitalAsset(to, tokenId, serial, ownerDID, fileHash, offchainURI)` | MANAGER | Digital asset with SHA-256 hash |
| `transferAsset(to, tokenId, newOwnerDID)` | MANAGER | Transfer + rebind DID |
| `revoke(tokenId)` | MANAGER | Burn asset permanently |
| `updateDigitalAsset(tokenId, requesterDID, newFileHash, newURI)` | Owner/Admin/READ_WRITE | Update off-chain reference |
| `grantAssetAccess(tokenId, targetDID, level)` | Owner/Manager | Grant READ(1) or READ_WRITE(2) |
| `revokeAssetAccess(tokenId, targetDID)` | Owner/Manager | Remove access |
| `checkAssetAccess(tokenId, requesterDID, callerAddress)` | View | Check authorization |
| `recordAccessAttempt(tokenId, actorDID, granted, reason)` | Anyone | Emit audit event on-chain |

### Events (Indexed by Event Indexer)
- `AssetMinted`, `DigitalAssetMinted`, `DigitalAssetUpdated`
- `AssetTransferred`, `AssetRevoked`
- `AccessPermissionGranted`, `AccessPermissionRevoked`
- `AccessAttempted` (includes `granted` bool + `reason` string)

---

## Backend Services

### Event Indexer (`event_indexer.py`)
- Polls Besu every 2 seconds for new blocks
- Parses all contract events into `audit_events` table
- Passes each event to the AI risk engine for real-time scoring
- Idempotent: skips already-indexed tx_hashes
- On fresh contract deployment, starts indexing from block 0

### AI Risk Engine (`services/ai.py`)
- Scikit-learn IsolationForest model
- Features: `rolling_failure_rate_24h`, `rolling_event_frequency_1h`, `role_escalation_index`
- Classifies events as LOW / MEDIUM / HIGH risk
- Scores stored in `AuditEvent.risk_score` and `AuditEvent.risk_label`

### Contract Service (`services/contract.py`)
- Backend NEVER holds private keys
- Only reads on-chain state and prepares unsigned transaction calldata
- Frontend signs all state-changing transactions via MetaMask
- Auto-reloads `localhost.json` when contract is redeployed

### Authentication (`auth.py`)
- SIWE (Sign-In with Ethereum) wallet-based auth
- Nonce-based replay protection (5 min TTL per NIST SP 800-63-4)
- JWT tokens for session management

---

## Frontend Dashboards

### Admin Dashboard (`AdminDashboard.jsx`)
- List/create/delete users
- Assign roles (ADMIN, MANAGER, AUDITOR, USER)
- Fund user wallets with test ETH

### Manager Dashboard (`ManagerDashboard.jsx`)
- **Mint Digital Asset**: Upload file → SHA-256 hash → sign mint tx via MetaMask
- **Mint Physical Asset**: Enter serial + recipient → sign mint tx
- **Grant/Revoke Access**: Per-asset DID-based permission management
- **Transfer Asset**: Transfer ownership + rebind DID
- **Revoke Asset**: Burn NFT permanently
- Pre-flight `checkManagerRole()` — unauthorized attempts logged on-chain via `recordAccessAttempt`

### User Dashboard (`UserDashboard.jsx`)
- View assigned assets (owned + granted)
- Download files (requires MetaMask signature for on-chain audit log)
- View asset metadata, permissions, ownership info

### Auditor Dashboard (`AuditorDashboard.jsx`)
- Full audit trail from `audit_events` table
- Filter by event type, actor DID, asset serial
- AI risk scores displayed per event
- Real-time stats: total events, high-risk count, unique actors

### Asset Registry (`AssetRegistry.jsx`)
- Global read-only view of all minted active assets
- Search by serial number, view on-chain metadata

---

## How Data Flows (End-to-End Mint Flow)

1. **User uploads file** → Frontend calls `POST /api/assets/upload-document`
2. **Backend** stores file in `offchain_storage/`, returns SHA-256 hash + URI
3. **Frontend** calls `POST /api/assets/mint-digital/prepare` to get calldata
4. **MetaMask** pops up → user signs the transaction
5. **Besu node** mines the tx → emits `DigitalAssetMinted` event
6. **Event Indexer** picks up the event → writes to `audit_events` table
7. **AI Engine** scores the event → stores risk_score/risk_label
8. **Asset Registry** now shows the new asset (reads from chain + DB)

---

## Known Issues & Gotchas

### 1. Assets Disappear on Contract Redeployment
- **Cause**: Redeploying `AssetNFT.sol` creates a new contract address with empty state
- **Fix**: Run `npx hardhat run scripts/seed_demo.js --network localhost`
- **Prevention**: Don't redeploy unless you want to wipe chain state

### 2. Backend Must Be Restarted After Code Changes
- Uvicorn without `--reload` serves stale compiled code
- **Always start with**: `uvicorn app.main:app --reload --port 8000`
- Symptoms: `405 Method Not Allowed` on valid POST endpoints

### 3. Hardhat gasPrice
- `hardhat.config.js` must use `gasPrice: "auto"` not hardcoded values
- Besu EIP-1559 base fee is ~875,000,000 wei, not 7 wei

### 4. Frontend Port
- Default Vite port is 5173; if occupied, Vite auto-increments to 5174
- Check `vite.config.js` proxy — must point to `http://127.0.0.1:8000`

### 5. seed_demo.js Addresses
- The script previously used hardcoded addresses that don't match Hardhat signers
- Now uses `(await hre.ethers.getSigners())[0/1/2].address` dynamically
- Admin = signer[0], User1 = signer[1], User2 = signer[2]

---

## How to Start Everything

```bash
# 1. Start Besu Blockchain (3-node QBFT cluster)
cd network/besu
docker compose up -d
# Wait ~10s for consensus

# 2. Deploy Smart Contract (only if not already deployed)
cd contracts
npx hardhat run scripts/deploy.js --network localhost

# 3. Seed Demo Assets (only after fresh deployment)
npx hardhat run scripts/seed_demo.js --network localhost

# 4. Start Backend (FastAPI + Event Indexer)
cd backend
uvicorn app.main:app --reload --port 8000

# 5. Start Frontend (Vite dev server)
cd frontend
npm run dev

# Access at http://localhost:5173
```

---

## MetaMask Setup

1. Add Custom Network:
   - RPC URL: `http://localhost:8545`
   - Chain ID: `13371`
   - Currency: `LEX`
2. Import Test Accounts (private keys from `hardhat.config.js`):
   - Admin: `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`
   - User1: `0x70997970C51812dc3A010C7d01b50e0d17dc79C8`
   - User2: `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC`

---

## Planned but Not Yet Implemented

### User & Asset Deletion (from plan file)
- `DELETE /users/{user_id}` backend endpoint (hard delete from DB)
- Delete button in AdminDashboard UI
- `revokeAsset()` already exists in `web3.js`
- Revoke Asset panel needed in ManagerDashboard UI

---

## Key Config Values

| Setting | Value | Location |
|---------|-------|----------|
| RPC URL | `http://127.0.0.1:8545` | `backend/app/core/config.py` |
| Chain ID | `13371` | `hardhat.config.js` |
| Database | `lexcorp_demo.db` (SQLite) | `backend/app/core/config.py` |
| Contract Address | `0x5FbDB2315678afecb367f032d93F642f64180aa3` | `contracts/deployments/localhost.json` |
| Backend Port | `8000` | `backend/app/main.py` |
| Frontend Port | `5173` (or `5174`) | `frontend/vite.config.js` |
| JWT Secret | `CHANGE-ME-IN-PRODUCTION` | `backend/app/core/config.py` |
| Event Poll Interval | ~2 seconds | `backend/app/indexer/event_indexer.py` |
