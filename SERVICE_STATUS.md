# LexCorp Platform - Service Status

**Generated:** 2026-09-16 23:41 IST

## ✅ All Services Running

### 1. Hardhat Blockchain Node
- **Status:** ✅ Running
- **Port:** 8545
- **URL:** http://localhost:8545
- **Accounts:** 20 pre-funded test accounts (10,000 ETH each)
- **Log:** `logs/hardhat.log`

### 2. Smart Contracts
- **Status:** ✅ Deployed
- **Contract:** AssetNFT
- **Address:** 0x5FbDB2315678afecb367f032d93F642f64180aa3
- **Network:** localhost (Chain ID: 31337)
- **Deployer:** 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

### 3. FastAPI Backend
- **Status:** ✅ Running
- **Port:** 8000
- **URL:** http://localhost:8000
- **Health:** http://localhost:8000/health
- **API Docs:** http://localhost:8000/docs
- **Log:** `logs/backend.log`
- **Features:**
  - ✅ SIWE Authentication
  - ✅ TOTP 2FA (Fixed)
  - ✅ WebAuthn/Passkeys (Fixed)
  - ✅ Role Hierarchy Enforcement
  - ✅ Asset Authorization Matrix
  - ✅ AI Risk Blocking
  - ✅ Soft-delete User Deactivation

### 4. Event Indexer
- **Status:** ✅ Running (Background)
- **Function:** Polls blockchain events every 10s
- **Last Block:** 40661
- **Log:** `logs/indexer.log`

### 5. Vite Frontend
- **Status:** ✅ Running
- **Port:** 5173
- **URL:** http://localhost:5173
- **Local:** http://localhost:5173
- **Network:** http://26.202.14.128:5173
- **Log:** `logs/frontend.log`

---

## 🔑 Admin Credentials

```
Wallet Address: 0x95ea9708BCf136d710A4b8e76FE20F895ecA003A
Private Key:    0x74745bf7bdc8ae82687ac8ac993fd752130fe45ed8d126818414105b71244809
DID:            did:ethr:13371:0x95ea9708bcf136d710a4b8e76fe20f895eca003a
Role:           ADMIN
```

**To Login:**
1. Open http://localhost:5173
2. Click "Import Mnemonic/Key"
3. Paste the private key above
4. Set an encryption password
5. Connect and sign the SIWE message

---

## 🧪 Testing the Platform

### Test Authentication
```bash
curl http://localhost:8000/api/auth/nonce?address=0x95ea9708BCf136d710A4b8e76FE20F895ecA003A
```

### Test Backend Health
```bash
curl http://localhost:8000/health
```

### Test Role Hierarchy
- Login as ADMIN
- Go to Admin Dashboard
- Try creating a MANAGER (✅ allowed)
- Try creating a USER (✅ allowed)
- Role dropdown should NOT show ADMIN or AUDITOR

### Test Asset Permissions
- Login as USER
- Go to User Dashboard
- Try minting a digital document (✅ allowed)
- Digital documents: can share, grant/revoke access (✅)
- Physical assets: cannot mint or transfer (❌)

---

## 📊 Monitoring Commands

### Watch all logs in real-time:
```bash
# Hardhat
tail -f logs/hardhat.log

# Backend
tail -f logs/backend.log

# Indexer
tail -f logs/indexer.log

# Frontend
tail -f logs/frontend.log
```

### Check service status:
```bash
# Backend health
curl http://localhost:8000/health

# List users
curl http://localhost:8000/api/users

# Check Hardhat
curl -X POST http://localhost:8545 -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

---

## 🛑 Stop All Services

To stop all services gracefully:
```bash
./stop-all.sh
```

Or manually:
```bash
# Kill by port
lsof -ti:8545 | xargs kill -9  # Hardhat
lsof -ti:8000 | xargs kill -9  # Backend
lsof -ti:5173 | xargs kill -9  # Frontend
```

---

## ⚠️ Known Issues

### Scikit-learn Version Warning
- **Issue:** Model unpickle warnings (1.9.0 → 1.9.1)
- **Impact:** Non-critical, AI risk engine still functional
- **Fix:** Retrain model with sklearn 1.9.1 or ignore warnings

### Frontend Proxy Error (Initial)
- **Issue:** "ECONNREFUSED 127.0.0.1:8000" during first load
- **Cause:** Backend was reloading after code fix
- **Status:** ✅ Resolved after reload complete

---

## 📝 Recent Changes Applied

1. ✅ Fixed TOTP verification (±60s window, 6-digit validation)
2. ✅ Fixed WebAuthn RP ID (localhost normalization)
3. ✅ Implemented strict role hierarchy (ADMIN > MANAGER > USER, AUDITOR)
4. ✅ Added digital vs physical asset permissions
5. ✅ Implemented AI risk pre-flight checks
6. ✅ Changed user deletion to soft-delete (is_active = False)
7. ✅ Added revoke access UI in UserDashboard
8. ✅ Dynamic role filtering in AdminDashboard
9. ✅ Updated ManagerDashboard custody labels
10. ✅ Fixed missing `Optional` import in auth.py

---

**Platform Status:** 🟢 All Systems Operational
