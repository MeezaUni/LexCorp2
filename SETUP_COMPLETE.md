# LexCorp Platform - Final Setup Complete ✅

**Updated:** 2026-09-17 00:21 IST

---

## 🎉 Platform Ready for Use

### Admin Account Status
- **Wallet:** `0x95ea9708BCf136d710A4b8e76FE20F895ecA003A`
- **Private Key:** `0x74745bf7bdc8ae82687ac8ac993fd752130fe45ed8d126818414105b71244809`
- **Role:** ADMIN
- **Balance:** 1700 ETH ✅
- **Smart Contract Role:** MANAGER_ROLE ✅

---

## 🔧 All Issues Resolved

### 1. ✅ Backend Authentication Fixed
- **Issue:** Missing `Optional` import in auth.py
- **Fix:** Added `from typing import Optional`
- **Status:** Backend running on port 8000

### 2. ✅ Smart Contract Permissions
- **Issue:** Admin didn't have MANAGER_ROLE on contract
- **Fix:** Granted MANAGER_ROLE via `grantRole` transaction
- **Status:** Admin can now mint, transfer, and revoke assets

### 3. ✅ Wallet Funding
- **Issue:** Admin wallet had 0 ETH balance
- **Fix:** Funded with 1700 ETH for gas fees
- **Status:** Admin can execute all transactions

---

## 🚀 Available Operations

### As ADMIN (`0x95ea9708BCf136d710A4b8e76FE20F895ecA003A`), you can:

#### User Management
- ✅ Create MANAGER users
- ✅ Create USER accounts
- ✅ Update user roles (respects hierarchy)
- ✅ Deactivate users (soft delete)
- ✅ Fund other users' wallets (1000 ETH via backend API)

#### Asset Operations
- ✅ Mint Digital Assets (documents, certificates)
- ✅ Mint Physical Assets (hardware, equipment)
- ✅ Transfer Digital Assets (ADMIN only)
- ✅ Transfer Physical Assets (ADMIN + MANAGER)
- ✅ Grant access permissions
- ✅ Revoke access permissions
- ✅ Revoke/burn assets

#### Security Features
- ✅ TOTP 2FA setup and validation
- ✅ WebAuthn/Passkey registration and authentication
- ✅ AI risk blocking (HIGH-risk actors blocked automatically)

---

## 💰 Funding Other Users

### From Frontend (Admin Dashboard):
1. Go to Admin Dashboard → User List
2. Click "Fund" button next to any user
3. Sends 1000 LEX (ETH) to that user's wallet

### From CLI:
```bash
cd contracts
FUND_RECIPIENT=0x<user_wallet_address> FUND_AMOUNT=1000 npx hardhat run scripts/fund_wallet.js --network localhost
```

### From Backend API:
```bash
# Get user ID first
curl http://localhost:8000/api/users

# Fund user by ID
curl -X POST http://localhost:8000/api/users/{user_id}/fund \
  -H "Authorization: Bearer <your_jwt_token>"
```

---

## 📊 Service Status

| Service | Port | Status | URL |
|---------|------|--------|-----|
| Hardhat Node | 8545 | 🟢 Running | http://localhost:8545 |
| Backend API | 8000 | 🟢 Running | http://localhost:8000 |
| Event Indexer | - | 🟢 Running | Background process |
| Frontend | 5173 | 🟢 Running | http://localhost:5173 |

---

## 🧪 Quick Test Workflow

### 1. Login
```
1. Open http://localhost:5173
2. Click "Import Mnemonic/Key"
3. Paste: 0x74745bf7bdc8ae82687ac8ac993fd752130fe45ed8d126818414105b71244809
4. Set encryption password
5. Connect and sign SIWE message
```

### 2. Create a MANAGER User
```
1. Go to Admin Dashboard
2. Click "Generate Keypair" (or enter existing wallet)
3. Fill in name and contact
4. Select role: MANAGER (USER also available)
5. Click "Save & Provision User"
6. Note: ADMIN role NOT in dropdown (hierarchy enforced)
```

### 3. Mint a Digital Document
```
1. Go to User Dashboard → Mint Digital Document
2. Upload a PDF/document file
3. Enter Token ID (e.g., 301)
4. Enter Document Identifier
5. Click "Mint & Anchor Digital Document"
6. Transaction signed with your wallet
```

### 4. Share Document & Revoke Access
```
1. User Dashboard → Manage Access Sharing
2. Grant Access:
   - Select your document
   - Enter recipient DID or wallet
   - Choose READ or READ_WRITE
   - Click "Grant Access Permission on-Chain"
   
3. Revoke Access (NEW):
   - Scroll to "Revoke Document Access Permission"
   - Select document
   - Enter target DID
   - Click "Revoke Access Permission on-Chain"
```

### 5. Test Role Hierarchy
```
Login as MANAGER:
- Admin Dashboard shows only "USER" in role dropdown ✅
- Cannot create MANAGER or ADMIN ✅

Login as USER:
- No user creation UI shown ✅
- Can mint digital documents ✅
- Cannot mint physical assets ✅
```

---

## 📁 Project Structure

```
LexCorp2/
├── contracts/          # Smart contracts & Hardhat
│   ├── scripts/
│   │   ├── deploy.js
│   │   ├── fund_wallet.js         # Fund any wallet with ETH
│   │   └── grant_admin_manager_role.js
│   └── deployments/
│       └── localhost.json         # Deployed contract address
├── backend/            # FastAPI server
│   ├── app/
│   │   ├── api/        # REST endpoints
│   │   ├── services/   # Business logic
│   │   └── models/     # Database models
│   └── seed_admin.py   # Admin user seeder
├── frontend/           # React + Vite
│   └── src/
│       ├── pages/      # Dashboard UIs
│       └── services/   # API & Web3 clients
└── logs/               # Service logs
    ├── hardhat.log
    ├── backend.log
    ├── indexer.log
    └── frontend.log
```

---

## 🛑 Stop All Services

```bash
# Kill by port
lsof -ti:8545 | xargs kill -9  # Hardhat
lsof -ti:8000 | xargs kill -9  # Backend
lsof -ti:5173 | xargs kill -9  # Frontend
```

---

## 📝 Changes Summary

### Backend (9 files modified)
1. `app/api/auth.py` - Fixed TOTP, WebAuthn, added `Optional` import
2. `app/api/users.py` - Role hierarchy enforcement, soft-delete
3. `app/api/assets.py` - Digital vs Physical permission matrix, AI risk checks
4. `app/services/security.py` - TOTP ±60s window, input validation
5. `app/services/ai.py` - Added `check_actor_risk_level` function

### Frontend (3 files modified)
1. `pages/UserDashboard.jsx` - Added revoke access UI, simplified identity card
2. `pages/AdminDashboard.jsx` - Dynamic role filtering, soft-delete labels
3. `pages/ManagerDashboard.jsx` - Physical custody terminology

### Smart Contracts
1. `AssetNFT.sol` - Already deployed at `0x5FbDB2315678afecb367f032d93F642f64180aa3`
2. Admin granted MANAGER_ROLE on-chain

---

## ✅ Verification Checklist

- [x] TOTP verification works with Google Authenticator
- [x] WebAuthn registration and login work on localhost
- [x] ADMIN cannot create ADMIN users (hierarchy enforced)
- [x] MANAGER cannot create MANAGER users (hierarchy enforced)
- [x] USER cannot create any users (hierarchy enforced)
- [x] USER can mint digital documents
- [x] USER cannot mint physical assets
- [x] MANAGER can transfer physical assets only
- [x] USER can grant and revoke access permissions
- [x] AI risk blocking prevents HIGH-risk operations
- [x] User deletion is soft (preserves audit trails)
- [x] Admin has 1700 ETH for gas
- [x] Admin can fund other users

---

**🟢 Platform Status: FULLY OPERATIONAL**

**Next Steps:**
1. Open http://localhost:5173
2. Import admin private key
3. Start testing the corrected authorization model!

---

*For detailed monitoring and troubleshooting, see `SERVICE_STATUS.md`*
