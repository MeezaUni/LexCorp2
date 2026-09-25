# LexCorp2 — Final Manual Test Checklist

Written for someone who has **not** used LexCorp2 before. Every test says what to do, what you should see, what must be rejected, and what evidence to capture. Automated tests (189, `backend/tests`) already cover the server rules; this checklist covers what only a person can confirm: real browsers, real Windows Hello passkeys, real phones scanning QR codes, and real on-chain transactions.

Record for every test: ✅ pass / ❌ fail, date, tester, and the screenshot file names.

---

## 0. Before you start

### 0.1 Start the system (in this order)

| Component | Command (from the repo root `LexCorp2/`) | You should see |
|---|---|---|
| PostgreSQL | `docker compose -f docker-compose.yml up -d postgres` | `docker ps` shows `lexcorp_postgres` **(healthy)** on port 5432 |
| Besu (3 QBFT validators) | `docker compose -f network/besu/docker-compose-active.yml up -d` | `besu_node1..3` **(healthy)**; RPC on `127.0.0.1:8545` |
| DB schema | `cd backend && python -m alembic upgrade head` | ends at `0010_indexer_state (head)` |
| Backend | `cd backend && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000` | `http://127.0.0.1:8000/health` → `{"status":"ok",...,"indexer":"running"}` |
| Frontend | `cd frontend && npm run dev` | Vite prints `http://localhost:5173` and a LAN URL |

**Never** run `init.sh`/`init.bat`, delete `network/besu/data`, or redeploy the contract — that destroys the chain.

### 0.2 Sanity checks (capture a screenshot of each result)

1. Chain ID — `curl -s -X POST -H "content-type: application/json" --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}" http://127.0.0.1:8545` → `"result":"0x343b"` (= 13371).
2. Validators — same call with `"method":"qbft_getValidatorsByBlockNumber","params":["latest"]` → exactly **3** addresses.
3. Contract — `contracts/deployments/localhost.json` address is `0x0165878A594ca255338adfa4d48449f69242Eb8F`.
4. Open `http://localhost:5173` → the **LexCorp Authentication** dialog appears (no dashboard behind it).

### 0.3 What you need

- A Windows PC with **Windows Hello** (PIN / fingerprint / face) — passkeys are platform passkeys.
- A phone with **Google Authenticator** or **Microsoft Authenticator** (you will add up to 3 entries per test identity).
- A phone camera for QR tests (phone on the same network as the PC).
- One existing **ADMIN** identity able to sign in, plus these test identities created by that admin during the tests:

| Name to create | Role | Department |
|---|---|---|
| Test Manager Avi | MANAGER | Avionics |
| Test User A | USER | Avionics |
| Test User B | USER | Avionics |
| Test Auditor | AUDITOR | Cyber |

Keep each identity's recovery phrase / private key (shown once by the admin's **Generate Wallet** helper) and its PIN private and off screenshots.

> **Screenshot rule:** never capture PINs, recovery phrases, private keys or TOTP secret/QR screens.

---

## 1. Identity & authentication

### 1.1 Create an identity and its provisioning PIN (Admin)
1. Admin → **Admin** tab → create **Test User A** (USER, Avionics). The **Department** list shows only real departments.
2. **See:** a one-time PIN, shown once, "valid 3 hours".
3. **Must be rejected:** creating a second user with the same wallet (409).
4. **Evidence:** screenshot of the created row (not the PIN).

### 1.2 First-time wallet import
1. In a private browser window: **First-Time Import** → paste Test User A's recovery phrase/key + the PIN.
2. **See:** you are taken to **Mandatory Security Setup** (not a dashboard).
3. **Must be rejected (repeat separately):**
   - a wrong PIN → "Invalid provisioning PIN";
   - the correct PIN a **second** time after success → "already been used";
   - a PIN older than 3 hours (ask the admin for a new identity and wait, or test later) → "expired";
   - a different wallet's key with this PIN → rejected.
4. **Evidence:** screenshot of each rejection message.

### 1.3 Mandatory setup: Login TOTP 1 + Login Passkey 1
1. On the setup screen: **Set up authenticator app** → scan the QR with your phone → enter the code → **Verify & enable**.
2. Status stays **REQUIRED** for the passkey; the dashboard is still not reachable.
3. While setup is incomplete, type `http://localhost:5173/` into the address bar and refresh → you still land on the setup screen.
4. **Register Login Passkey** → Windows Hello prompt → approve.
5. **See:** you land on the dashboard.
6. **Evidence:** setup screen with TOTP CONFIGURED + passkey REQUIRED; then the dashboard.

### 1.4 Login
1. Sign out. **Sign In** → type the wallet address by hand → TOTP 1 code → **Sign in with Authenticator** → dashboard.
2. Sign out → type address → **Sign in with Login Passkey** → Windows Hello → dashboard.
3. **Must be rejected:** wrong 6 digits; the same code used twice within 30 s; a wallet address you mistyped by one character; an address that was never provisioned. All show the same generic failure.
4. **Evidence:** both successes, one failure.

### 1.5 Factor 2 and Factor 3 enrollment (My Identity)
1. **My Identity** → set up **View/Submission Auth (Factor 2)** TOTP (new phone entry) and **Mint/Approval Auth (Factor 3)** TOTP.
2. Passkeys card → purpose **Factor 2** → register (Windows Hello); then **Factor 3** → register (you will be asked for a current Factor 3 code if Factor 3 TOTP already exists).
3. **See:** passkeys listed with [FACTOR 2] / [FACTOR 3] tags; the Login passkey has **no Remove button**.
4. **Evidence:** My Identity page with all factors active.

### 1.6 Wrong-purpose factors (must all be rejected)
Use the **Submit Document** form (needs Factor 2) and a Manager approval (needs Factor 3):
1. Enter a **TOTP 1** code where Factor 2 is asked → rejected "Invalid Factor 2 …".
2. Enter a **TOTP 2** code where Factor 3 is asked → rejected "Invalid Factor 3 …".
3. Choose **Use Passkey** for Factor 2 and pick your **Login** passkey in the Windows prompt → rejected "Wrong-purpose passkey".
4. Same with your Factor 2 passkey where Factor 3 is required → rejected.
5. **Evidence:** each rejection message.

### 1.7 Login reset (admin assistance)
1. As Test User A: **My Identity** → the Login Authenticator card says "cannot be reset self-service". Click **REQUEST ADMIN ASSISTANCE**.
2. As Admin: **Admin** tab → pending reset → approve with **Factor 3** (6-digit code, or leave empty to use Passkey 3).
3. **See:** a **new** PIN (shown once). Test User A's open browser session is signed out on its next action.
4. Test User A: old TOTP 1 and old login passkey no longer sign in. **First-Time Import** with the new PIN → setup screen again → configure new TOTP 1 + Passkey 1.
5. **Must be rejected:** approving the reset without Factor 3; an admin approving their own reset; the old PIN.
6. **Evidence:** reset request row, approval screen (no PIN in shot), post-reset setup screen.

### 1.8 Sessions
1. **Single session:** sign in as Test User A in Chrome, then in Edge → Chrome's next click returns to the sign-in dialog.
2. **Inactivity:** stay idle 15 minutes → signed out ("inactivity").
3. **IP change:** sign in on the PC via `http://<PC-LAN-IP>:5173`, then switch the PC to a different network (e.g. phone hotspot) and click anything → "Session terminated: client IP address changed"; signing in again works. (On a single machine you can also: sign in via `http://localhost:5173`, then copy the `lexcorp_token` value from DevTools → Application → Local Storage and replay it from another machine with `curl -H "Authorization: Bearer <token>" http://<PC-LAN-IP>:8000/api/auth/me` → 401, and the original browser session is then also dead.)
4. **Logout:** Sign out, press the browser Back button → no data, sign-in dialog.
5. **Evidence:** each message.

---

## 2. Digital documents

Use Test User A (owner), Test Manager Avi (approver), Test User B (grantee), Admin.

### 2.1 Create → submit
1. Test User A → **Submit Document** → choose a **PDF** → upload → fill title/serial/recipient → Factor 2 → submit.
2. **See:** "Document proposal CRT-YYYYMMDD-NNNN submitted". Note the CRT ID.
3. Repeat later with a **DOCX**, **PPTX**, **XLSX**, **PNG/JPG** and **TXT** (used in 2.4).

### 2.2 Approval + on-chain mint
1. Test Manager Avi → **Manager** tab → pending document → **Approve** with Factor 3.
2. **See:** "Unlocking your wallet… Transaction … sent… approved and minted on-chain (token #…, block …)".
3. **Must be rejected:** Test User A approving their own document; a manager from another department.
4. **Evidence:** success message with token and block number. Cross-check: Auditor → audit log filter **Category = DIGITAL** shows `DOCUMENT_MINTED` with the tx hash.

### 2.3 Controlled view + watermark + QR
1. Test User A → **My Assets** → **View (Watermarked)** → Factor 2 (code or passkey).
2. **See:** the document opens in a new tab with a **diagonal, semi-transparent** "CONFIDENTIAL" marking on every page, a QR in the corner, and a final **LexCorp Document Control** page listing: *Viewed by: <your name>*, *Wallet: 0x1234...abcd* (shortened), *IP: <your IP>*, *Date: DD Month YYYY*, *View ID: VW-YYYYMMDD-NNNN*.
3. The **owner's** name does **not** appear unless the viewer is the owner.
4. Scan the QR with your phone → **LexCorp Record Verification** page opens showing "Authentic LexCorp record (public view)" — no names, no IPs.
5. **Evidence:** watermarked page, control page, phone screenshot of the verification page.

### 2.4 Watermark per format (repeat 2.3 for each file type)
| Type | Expect |
|---|---|
| PDF | every page marked; control page appended; QR scannable |
| DOCX | opens in Word; faint diagonal watermark in the page background (header layer); header line + QR; control section at the end; original paragraphs/tables intact |
| PPTX | opens in PowerPoint; every slide has rotated faint text + QR; one extra control slide at the end |
| XLSX | opens in Excel; **Page Layout** view/print preview shows the watermark header/footer; extra **LexCorp Control** sheet with QR; original values/formulas intact (charts/pivots are **not** preserved — known limitation) |
| PNG/JPG | faint diagonal text over the image; a pink band added **below** the image with the block + QR |
| TXT | delivered as a watermarked **PDF** |
| other (e.g. .zip, .exe) | refused: "cannot be served as a protected copy" |

Evidence: one screenshot per type.

### 2.5 Delegated access (request → approval → limits)
1. Test User A → **Grant Access** → target Test User B's DID → purpose → (optionally tick "Also request download") → Factor 2 → submit (**ACR-…** ID).
2. Before approval: Test User B tries **View** → rejected "You have no approved access…".
3. Test Manager Avi → approve the ACR with Factor 3, setting **Max Allowed Views = 2** and **Accessible Until** = 10 minutes from now; leave "allow download" unticked.
4. Test User B → View twice → both succeed; third time → "View limit reached (2 successful views)".
5. Enter a wrong Factor 2 code once before viewing → rejected, and it does **not** use up a view.
6. Create another grant with a 3-minute expiry; after it passes → "Your access to this document expired".
7. With a view-only grant, Test User B → **Request Download** → "view-only; download is not permitted".
8. **Evidence:** each message; Auditor → audit filter **Category = ACCESS** shows `ACCESS_GRANTED`, `ACCESS_LIMIT_REACHED`, `ACCESS_EXPIRED`.

### 2.6 Controlled download
1. Test User B (grant **with** download) → **Request Download** → Factor 2 → **DL-…**.
2. **My download & modification requests** shows "awaiting owner consent". Test User A (owner) → **Download requests awaiting your consent** → **Approve** (Factor 3).
3. Test Manager Avi → approve the DL with Factor 3.
4. Test User B → **Download (Factor 3)** → file saves; its control block says *Downloaded by: Test User B*, *Download ID: DL-…* and *Owner: Test User A (0x…)*.
5. **Must be rejected:** downloading before approval; downloading the same DL twice ("already been used"); the manager trying to fetch it; an approval older than 24 h ("expired").
6. **Evidence:** downloaded file control block; rejection messages.

### 2.7 Modification → revision → approval
1. Test User A → **Request Modification** → Factor 2 → **DL-…** (MODIFICATION).
2. Manager approves (Factor 3). Test User A → **Download (Factor 3)**.
3. Edit the downloaded content in its editor, save a **new** file.
4. **My download & modification requests** → "Upload revised file" → pick the edited file → Factor 3.
5. **See:** "Revision MOD-YYYYMMDD-NNNN submitted as version 2 (pending approval)" and a SHA-256 prefix.
6. **Must be rejected:** uploading the unchanged original ("identical to an existing version"); reusing the same modification download; a second modification request while v2 is pending.
7. Manager approves the MOD (Factor 3) → the wallet anchors the new hash on-chain ("anchored on-chain").
8. Repeat 1–7 once more to create **version 3**.
9. View version 3 → the control page lists *Modification ID: MOD-…(v2)* then *Modification ID: MOD-…(v3)*, oldest first, with *Modified by wallet* and date; nothing overlaps the document body.
10. **Evidence:** lineage in My Assets (v1, v2, v3), the control page of v3.

### 2.8 QR verification & tamper detection
1. Scan the QR on any protected copy (or open `/verify/action/<VW-or-DL-ID>`).
2. Signed out: public view only. Signed in as the owner or Manager: creator, versions with hashes, modification trail.
3. On the verification page, type the watermark fields exactly → "Matches the authoritative record". Change **Viewed by** to another name → "Does NOT match … possible tampering".
4. Upload the genuine downloaded PDF → MATCH. Open it in any PDF editor, change the name on the control page, save, upload → MISMATCH.
5. Visit `/verify/action/VW-19990101-0001` and `/verify/action/hello` → "No LexCorp record" / not a reference.
6. **Evidence:** MATCH and MISMATCH screens; Auditor alert queue shows the tamper alert (§4).

---

## 3. Physical assets

### 3.1 Registration (Admin / Manager only)
1. Test Manager Avi → **Submit Hardware** → Serial, "Does this asset have a MAC address?" **Yes** → MAC `00:1A:2B:3C:4D:5E` → Factor 2 → submit (**CRT-…**).
2. Again with **No** → Unique Address `UA-TEST-0001`.
3. **Must be rejected:** Yes without a MAC; No without a Unique Address; a malformed MAC (`ZZ:…`); Test User A (USER) or the Auditor trying to register at all.
4. **Evidence:** both CRT IDs; rejection messages.

### 3.2 Global uniqueness
Each must be rejected with a clear message and **no** new row in the registry:
1. Same serial in lower case / with spaces.
2. Same MAC written differently (`00-1a-2b-3c-4d-5e`, `001A.2B3C.4D5E`).
3. Same Unique Address in different case.
4. A MAC already used by a **Cyber** asset, registered from Avionics (uniqueness is global).
5. **Evidence:** messages; Auditor → filter **Category = PHYSICAL, Result = DENIED** shows `DUPLICATE_*_ATTEMPT` rows — open one: it shows a *value_fingerprint*, **not** the MAC.

### 3.3 Approval, mint and NFT card
1. Admin approves Test Manager Avi's hardware (Factor 3) → wallet sends the mint → "approved and minted on-chain".
2. Registry → the asset → **Card**. **See ONLY:** Serial Number, NFT / Token ID, Creation Date, Department, QR. **Must NOT appear:** MAC, Unique Address, CRT ID, any 0x wallet, DID, hash, asset name.
3. **Evidence:** the card (print preview is fine).

### 3.4 Physical verification
1. Scan the card's QR while signed out → Serial, Token ID, Department, status, dates only.
2. Signed in as Test Manager Avi (same dept) or Admin/Auditor → also MAC/Unique Address, Creation ID, approval (proposer/approver), lifecycle history.
3. Signed in as Test User A (no scope) → still the public view.
4. **Evidence:** the three views.

### 3.5 Lifecycle & scoping
1. Manager → assign custody, record maintenance, change status to **MAINTENANCE** (Factor 3). Each appears in the verification page's lifecycle and in the audit log.
2. A manager of another department cannot see, assign, maintain or change the asset (not found / 403), even by editing URLs or request bodies.

---

## 4. AI high-risk alert chain

A high-risk alert appears automatically when the AI engine or a security rule flags an event HIGH (the tamper test in §2.8 and the duplicate tests in §3.2 are reliable triggers).

1. **Auditor** → dashboard → **High-Risk Security Alerts — AUDITOR REVIEW** lists the alert: identity, role, short wallet, risk level/score, reason, time, IP, related asset/action.
2. Auditor → **Dismiss — False Alarm** (a reason is required) on one alert.
3. Auditor → **Forward to Manager** on another.
4. **Manager** of that department → the alert appears in their queue → **Forward to Admin** (or dismiss another one).
5. **Admin** → **Revoke Identity** → confirm → reason → Factor 3.
6. **See:** the subject is signed out on their next click and can no longer sign in with TOTP or passkey.
7. **History** button shows RAISED → FORWARDED_TO_MANAGER → FORWARDED_TO_ADMIN → IDENTITY_REVOKED with who/when/notes.
8. **Must be rejected:** a manager from another department seeing the alert; the Auditor acting after forwarding; anyone acting on an alert about themselves; revocation without Factor 3.
9. **Evidence:** each queue, the history panel, the revoked user's rejected sign-in.

---

## 5. Security checks (all must be rejected)

| # | Try | Expected |
|---|---|---|
| 5.1 | Open `http://localhost:8000/api/assets/registry` in a fresh private window | 401 |
| 5.2 | As Test User A, call `GET /api/assets/by-owner/<Admin wallet>` (DevTools console `fetch`) | 403 |
| 5.3 | As Test Manager Avi, `GET /api/assets/<token of a Cyber asset>` | 404 |
| 5.4 | As a Manager, create a user with `"department":"Cyber"` in the request body | 403 |
| 5.5 | `GET /api/assets/document/download/anything.pdf` | 410 (direct vault download disabled) |
| 5.6 | Replay a used `X-Step-Up-Token` header | 401 |
| 5.7 | Use a step-up token minted for **view** on a **submit** | 401 |
| 5.8 | Open the dashboard URL while in setup-only state | setup screen only |
| 5.9 | Expired access / exhausted view count | 403 with reason |
| 5.10 | Changed IP | session terminated (§1.8) |
| 5.11 | Invalid QR reference | "No LexCorp record" |
| 5.12 | Revised file whose text claims a fake history | verification & control page show only the database history |

---

## 6. Sign-off

| Area | Result | Tester | Date | Evidence files |
|---|---|---|---|---|
| Startup & chain checks | | | | |
| Identity & authentication | | | | |
| Digital documents | | | | |
| Physical assets | | | | |
| AI alert chain | | | | |
| Security checks | | | | |
