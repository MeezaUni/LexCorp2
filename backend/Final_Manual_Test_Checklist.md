# LexCorp2 — Final Manual Test Checklist

This checklist is for a person who has never used LexCorp2. It is **not executed yet**.
Automated tests (248 backend, 23 contract, 3 live-ledger) and browser automation
(`docs/Playwright_Verification_Report.md`) have covered the server rules and UI flows.
This checklist covers what only you can confirm:
- real Windows Hello passkeys and a real phone authenticator app;
- scanning QR codes with a real phone camera;
- opening downloaded files in desktop Office;
- a real network change;
- your own judgement on whether the product is acceptable.

For each test, tick **PASS** or **FAIL**, write notes, and save the evidence named. Keep
screenshots under `docs/evidence/manual/<test-id>.png`.

> **Screenshot rule:** never capture a provisioning PIN, recovery phrase, private key,
> TOTP secret or TOTP enrolment QR. Crop or cover them first.

---

## What you need

- The Windows PC this repository is on, with **Windows Hello** set up (PIN, fingerprint or face).
- **Docker Desktop** running.
- A phone with **Microsoft Authenticator** or **Google Authenticator**, on the same Wi-Fi as the PC.
  Each identity adds 3 entries: login, Factor 2 and Factor 3.
- Microsoft Word, PowerPoint and Excel for section J.
- **Five separate browser profiles**, because each browser profile holds exactly one
  identity's wallet. In Chrome use Profile menu → Add → "Continue without an account",
  creating one profile per identity: Admin, Manager, User A, User B, Auditor. Do not use
  private windows: closing them deletes the wallet.
- Always open **http://localhost:5173**. Passkeys are bound to `localhost`, so they do not
  work at `127.0.0.1` or at the LAN address. The phone uses the LAN address only for QR pages.

### Identities you will create

| ID | Name | Role | Department | How the wallet is created |
|---|---|---|---|---|
| ADM | Security Administrator | Administrator | Cyber Security | Bootstrap script (already done; see A3) |
| MGR | Test Manager | Manager | Avionics | By the person, in the Manager profile ("Create a wallet") |
| USA | Test User A | User | Avionics | By the admin ("generate a wallet for them"), custodial path |
| USB | Test User B | User | Radar Systems | By the person ("Create a wallet") |
| AUD | Test Auditor | Auditor | Cyber Security | By the person ("Create a wallet") |

Keep each identity's wallet address, recovery phrase and PIN in a password manager,
never in screenshots.

---

## A. Environment startup

### A1 — Start all services
- **Purpose:** bring up PostgreSQL, Besu, the backend and the frontend.
- **Preconditions:** Docker Desktop running; a terminal (Git Bash or PowerShell) in the repository root `LexCorp2/`.
- **Steps:**
  1. `docker compose up -d postgres`
  2. `npm run besu:up`, then `npm run chain:wait`
  3. `npm run contract:verify`
  4. `npm run migrate`
  5. `npm start`. Leave this terminal open; it runs the backend and frontend. (`npm start` also repeats steps 1–4 on its own, so on later days `npm start` alone is enough.)
- **Expected:**
  - `docker ps` shows `lexcorp_postgres (healthy)` and `besu_node1`, `besu_node2`, `besu_node3` Up.
  - Step 3 prints 14 lines, all starting `PASS`.
  - Step 4 ends at `0012_audit_log_index`.
  - Step 5 prints a frontend "Network" URL such as `http://192.168.x.x:5173`.
- **Evidence:** A1-docker-ps.png, A1-verify-deployment.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### A2 — Health and integrity
- **Purpose:** confirm the stack is consistent before testing.
- **Preconditions:** A1 passed.
- **Steps:**
  1. Open `http://127.0.0.1:8000/health` in a browser.
  2. In a second terminal: `cd backend && python scripts/verify_integrity.py`
- **Expected:**
  - Health shows `"chain_verified": true`, `"indexer": "running"`, `"environment": "development"`.
  - The integrity script ends with `9/9 checks passed`.
- **Evidence:** A2-health.png, A2-integrity.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### A3 — Bootstrap administrator material is available
- **Purpose:** the first administrator's wallet and PIN exist only on this PC.
- **Preconditions:** A1.
- **Steps:**
  1. Open `secrets/bootstrap_admin_wallet.json` (recovery phrase) and `secrets/bootstrap_admin_pin.txt` (PIN and expiry) in a text editor.
  2. If the PIN has expired, run `cd backend && python scripts/bootstrap_admin.py --reissue-pin`, then reopen the PIN file.
- **Expected:** both files exist. The PIN expiry is in the future.
- **Evidence:** A3-files-listed.png, showing the file names only, never the contents.
- [ ] PASS  [ ] FAIL — Notes: ______

### A4 — Phone can reach the PC
- **Purpose:** QR tests need the phone to reach the PC over Wi-Fi.
- **Preconditions:** A1; phone on the same Wi-Fi.
- **Steps:** on the phone, open `http://<the Network address from A1>:5173/verify/token/1`.
- **Expected:** the LexCorp2 "Asset verification" page opens and shows "Not verified: Asset not found". If it does not load, allow port 5173 through Windows Defender Firewall for private networks and retry.
- **Evidence:** A4-phone.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## B. First-time provisioning

### B1 — Provision the first Administrator
- **Purpose:** wallet plus single-use PIN provisioning.
- **Preconditions:** A3; Admin browser profile.
- **Steps:**
  1. Open `http://localhost:5173`, then the **First-time provisioning** tab.
  2. Paste the recovery phrase from `bootstrap_admin_wallet.json` and the PIN.
  3. Click **Provision wallet and continue to security setup**.
- **Expected:** the **Security enrolment** screen appears, with "Login authenticator (TOTP 1): Required" and "Login passkey (Passkey 1): Required". No menu or dashboard is visible.
- **Evidence:** B1-enrolment.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### B2 — Login TOTP 1 enrolment
- **Purpose:** first login factor.
- **Preconditions:** B1.
- **Steps:**
  1. **Start authenticator setup**.
  2. Scan the QR with the phone app.
  3. Type the 6-digit code, then **Confirm authenticator**.
- **Expected:** step 1 turns green ("Configured"). The phone app entry is named "LexCorp2 Login (Factor 1)".
- **Evidence:** B2-step1-done.png, taken after enrolment so no QR is visible.
- [ ] PASS  [ ] FAIL — Notes: ______

### B3 — Login Passkey 1 with Windows Hello
- **Purpose:** real platform passkey.
- **Preconditions:** B2.
- **Steps:**
  1. **Register login passkey**.
  2. Complete the Windows Hello prompt.
- **Expected:** Windows Hello appears. Afterwards the dashboard opens: masthead "LexCorp2", sidebar, and the greeting "Good …, Security Administrator".
- **Evidence:** B3-windows-hello.png (the prompt), B3-dashboard.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### B4 — Enrolment cannot be skipped
- **Purpose:** the application is unreachable before both login factors exist.
- **Preconditions:** do this during D5 for any new identity, after provisioning and before enrolment.
- **Steps:** in the address bar open `http://localhost:5173/digital`, then `/admin`.
- **Expected:** the enrolment screen is still shown; no data pages open.
- **Evidence:** B4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### B5 — PIN is single use
- **Purpose:** a used PIN cannot be used again.
- **Preconditions:** B1 done; any other browser profile.
- **Steps:** First-time provisioning, using the same recovery phrase and the same PIN.
- **Expected:** refused, with a message that the PIN is invalid or already used.
- **Evidence:** B5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## C. Authentication

### C1 — Sign in with Login TOTP 1
- **Preconditions:** B3.
- **Steps:**
  1. Sidebar → **Sign out**.
  2. Type the admin wallet address (do not paste from the screen) and a fresh 6-digit code.
  3. **Sign in with authenticator code**.
- **Expected:** the dashboard opens.
- **Evidence:** C1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### C2 — Sign in with Login Passkey 1
- **Steps:** Sign out → type the wallet address → **Sign in with login passkey** → Windows Hello.
- **Expected:** the dashboard opens.
- **Evidence:** C2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### C3 — Wrong factor and unknown wallet refused
- **Steps:**
  1. Sign in with a wrong 6-digit code.
  2. Sign in with an invented address `0x1111111111111111111111111111111111111111` and any code.
- **Expected:** both are refused with the same generic message, which does not reveal whether the wallet exists.
- **Evidence:** C3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### C4 — Set up Factor 2 and Factor 3
- **Preconditions:** signed in as ADM.
- **Steps:** **My identity** → "Factor 2: view and submit" → **Set up authenticator** → **Generate key** → scan → **Confirm**. Repeat for Factor 3. Then, in the Factor 3 panel, **Register passkey on this device**: enter the Factor 3 code → **Continue** → Windows Hello.
- **Expected:** both panels show "Protected". Factor 3 lists a passkey. Registering the passkey asked for the Factor 3 code first.
- **Evidence:** C4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### C4b — Use the login factors for Factor 2 (the quick option)
- **Purpose:** a person can choose to confirm Factor 2 or Factor 3 actions with the authenticator and passkey they sign in with, instead of setting up separate ones.
- **Preconditions:** an identity whose Factor 2 panel shows "Not set up" (for example USB right after D5, before setting up its Factor 2).
- **Steps:**
  1. **My identity** → Factor 2 panel → **Use my login factors** → enter the **login** authenticator code (or **Use login passkey** → Windows Hello).
  2. Open a delegated or own document → **View document** → enter the login authenticator code.
  3. Immediately repeat step 2 with the same code.
  4. **My identity** → Factor 2 → **Use separate factors instead** → confirm with the login factor.
- **Expected:**
  1. The panel shows "Uses login factors", and the dashboard shows "Uses login factors" for Factor 2.
  2. The view opens.
  3. The repeated code is refused; the next code works.
  4. The panel returns to "Not set up", and viewing is refused until a Factor 2 authenticator or passkey is set up.
- **Evidence:** C4b.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### C5 — Factors cannot stand in for each other
- **Preconditions:** a document exists (E4), USA has no Factor 2 passkey, and USA's Factor 2 does not use the login factors (C4b).
- **Steps:**
  1. As USA open the document → **View document** → enter the **Factor 3** code in the Factor 2 box.
  2. Click **Use Passkey 2** when no Passkey 2 is registered.
- **Expected:** both are refused ("Invalid Factor 2 …" or "No active Factor 2 passkey…").
- **Evidence:** C5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### C6 — Logout revokes the session
- **Steps:** Sign out, then press the browser Back button and reload.
- **Expected:** the sign-in screen shows "You signed out." No data is displayed.
- **Evidence:** C6.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### C7 — 15-minute inactivity limit
- **Steps:** sign in, leave the tab untouched for 16 minutes, then click any menu item.
- **Expected:** you are returned to sign-in with a message that the session ended after inactivity.
- **Evidence:** C7.png, with the clock visible.
- [ ] PASS  [ ] FAIL — Notes: ______

### C8 — 30-minute absolute session lifetime
- **Steps:** sign in and keep working, clicking at least every 10 minutes, for 31 minutes.
- **Expected:** after 30 minutes the next action returns you to sign-in. This is intended: sessions last at most 30 minutes.
- **Evidence:** C8.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### C9 — Session ends when your network address changes
- **Purpose:** IP binding.
- **Preconditions:** a laptop that can switch networks (for example Wi-Fi to a phone hotspot), signed in at `http://localhost:5173` on that laptop.
- **Steps:** sign in, switch the laptop to the other network, then click a menu item.
- **Expected:** if the effective address the backend sees changes, the session ends ("client IP address changed"). Running everything on `localhost`, the backend always sees `127.0.0.1`, so no change is detectable. In that case mark **N/A (single-host setup)** and note it.
- **Evidence:** C9.png, or a note.
- [ ] PASS  [ ] FAIL  [ ] N/A — Notes: ______

### C10 — Login reset by an administrator
- **Preconditions:** USA is fully set up (D5).
- **Steps:**
  1. As USA: **My identity** → **Ask an administrator to reset my login factors** → reason → **Send request**.
  2. As ADM: **Administration** → "Login reset requests" → **Approve reset** → Factor 3.
  3. Note the new PIN (do not screenshot it).
  4. As USA, reload.
- **Expected:**
  - USA's session ends.
  - USA can no longer sign in with the old TOTP 1 or Passkey 1.
  - USA provisions again with the new PIN, and must enrol new login factors.
- **Evidence:** C10-request.png, C10-approved.png (PIN masked), C10-reenrol.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### C10b — An administrator's own reset
- **Purpose:** an administrator can't approve their own reset, so the page must send them to the right person.
- **Steps:**
  1. As ADM while it is the only administrator: **My identity** → Login factors.
  2. After D2 registers a second administrator (or temporarily register one), reload **My identity** as ADM.
- **Expected:**
  1. No "Ask an administrator" button. A notice says you are the only administrator and that the server operator resets it with `python backend/scripts/bootstrap_admin.py --reset-login`.
  2. The button reads **Ask another administrator to reset my login factors**. After sending, the request appears for the other administrator only, never in ADM's own list.
- **Evidence:** C10b-sole.png, C10b-other.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### C11 — Locked-out request from the sign-in screen
- **Steps:** Sign in → **Locked out** tab → paste USB's recovery phrase → reason → **Send signed reset request**.
- **Expected:** "Request recorded". ADM sees USB under "Login reset requests".
- **Evidence:** C11.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## D. Roles and departments

### D1 — Departments
- **Steps:** as ADM, **Administration** → **Add department** → "Test Range" → **Add**.
- **Expected:** "Test Range" appears in the list and in the department drop-downs.
- **Evidence:** D1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### D2 — Register the Manager with a self-generated wallet
- **Steps:**
  1. In the Manager profile: sign-in screen → **Create a wallet** → **Generate wallet on this device**. Record the recovery phrase privately, tick the box, then **Clear it from the screen**. Copy only the address.
  2. As ADM: **Administration** → **Register identity**. Name "Test Manager", role Manager, department Avionics; paste the address → **Register** → Factor 3.
- **Also check:** while the dialog is open, click **Contact number** and **Wallet address** and type. The cursor stays in the field you clicked.
- **Expected:**
  - A dialog shows the PIN "once".
  - Ledger roles read `ANCHOR_ROLE, MANAGER_ROLE, MINTER_ROLE`.
  - The admin never saw the recovery phrase.
- **Evidence:** D2-registered.png (PIN masked).
- [ ] PASS  [ ] FAIL — Notes: ______

### D3 — Register the Auditor and User B (self-generated)
- **Steps:** repeat D2 for AUD (Auditor, Cyber Security) and USB (User, Radar Systems).
- **Expected:** ledger roles are `AUDITOR_ROLE` for AUD and "None (user role)" for USB.
- **Evidence:** D3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### D4 — Register User A with the custodial path
- **Steps:** **Register identity** → name, role User, department Avionics → **The person cannot create one: generate a wallet for them**. Record the phrase privately, tick the acknowledgement → Register → Factor 3.
- **Expected:** a warning that you now know this person's recovery phrase. The PIN is shown once.
- **Evidence:** D4.png (phrase and PIN masked).
- [ ] PASS  [ ] FAIL — Notes: ______

### D5 — Each identity provisions and enrols
- **Steps:** in each identity's own profile, run B1, B2 and B3 using that identity's recovery phrase and PIN, then set up Factor 2 and Factor 3 as in C4.
- **Expected:** all four reach their dashboard.
- **Evidence:** D5-<id>.png for each.
- [ ] PASS  [ ] FAIL — Notes: ______

### D6 — Navigation per role
- **Steps:** note the sidebar items for each identity.
- **Expected:**

  | Role | Sidebar items |
  |---|---|
  | User | Dashboard, Digital assets, Physical assets, My requests, My identity |
  | Auditor | the User items plus Security alerts and Audit trail |
  | Manager | Dashboard, Digital assets, Physical assets, Requests & approvals, Security alerts, Audit trail, My identity, People |
  | Admin | as Manager, with Administration instead of People |

  Nothing refers to any other organisation's branding.
- **Evidence:** D6-<role>.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### D7 — A User cannot reach restricted areas
- **Steps:**
  1. As USA open `http://localhost:5173/admin`, then `/alerts`, then `/audit`.
  2. In the same browser open `http://localhost:5173/api/alerts` and `http://localhost:5173/api/audit/stats`.
- **Expected:** the pages show "Not available for your role". The API URLs return `{"detail":"Not authorized…"}` (HTTP 403).
- **Evidence:** D7.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### D8 — Manager scope and extra departments
- **Steps:**
  1. As MGR, note which physical and digital assets are visible (only Avionics, plus assets MGR owns).
  2. As ADM: **Administration** → Test Manager → **Departments** → tick "Radar Systems" → Save.
  3. MGR signs out and back in.
- **Expected:** before the change MGR cannot see Radar Systems items. After it, Radar Systems items are visible.
- **Evidence:** D8-before.png, D8-after.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### D9 — Role change updates ledger roles
- **Steps:** as ADM: **Change role** on USB → Manager → Factor 3. Then change USB back to User.
- **Expected:**
  - USB's session ends at each change.
  - The Audit trail (category "Identity administration") shows ROLE_CHANGED.
  - Category "Ledger and roles" shows the ledger roles granted, then revoked.
- **Evidence:** D9.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## E. Digital asset creation

### E1 — Register a PDF document
- **Steps:**
  1. As USA: **Digital assets** → **Register document** → choose a PDF.
  2. Wait for "Stored in the vault".
  3. Title "Test specification", Asset ID `DOC-TEST-001`, department Avionics.
  4. **Submit for approval** → Factor 2.
- **Expected:** "Submitted for approval" with a `CRT-YYYYMMDD-NNNN` ID. The row shows "Pending approval" and "Not yet recorded".
- **Evidence:** E1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### E2 — Register DOCX, PPTX and XLSX documents
- **Steps:** repeat E1 with a Word file (`DOC-TEST-002`), a PowerPoint file (`DOC-TEST-003`) and an Excel file that contains a chart (`DOC-TEST-004`).
- **Expected:** each is accepted and pending.
- **Evidence:** E2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### E3 — Unsupported type refused
- **Steps:** Register document → choose a `.zip` or `.exe` file.
- **Expected:** "Unsupported document type…". Nothing is stored.
- **Evidence:** E3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### E4 — Approval signs the ledger transaction
- **Steps:** as MGR: **Requests & approvals** → `DOC-TEST-001` → **Review** → Approve → Factor 3 → **Approve and sign**.
- **Expected:**
  - "approved and recorded on the ledger (block N)".
  - The document shows "Approved", Lifecycle "Minted", a ledger transaction hash, and "Ledger recorded" in the blue ribbon.
- **Evidence:** E4.png. Repeat for DOC-TEST-002 to 004.
- [ ] PASS  [ ] FAIL — Notes: ______

### E5 — Rejection
- **Steps:**
  1. As USA register `DOC-TEST-005`.
  2. As MGR, Review → **Reject** → reason → Factor 3 → **Confirm rejection**.
- **Expected:** status Rejected. It cannot be viewed by anyone other than the owner and managers.
- **Evidence:** E5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### E6 — No self-approval
- **Steps:**
  1. As MGR register a document `DOC-TEST-006`.
  2. In MGR's own queue look at that row.
  3. Approve it as ADM.
- **Expected:** MGR sees "Another approver must decide". ADM can approve it.
- **Evidence:** E6.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## F. Digital viewing

### F1 — Owner views a document
- **Steps:** as USA open `DOC-TEST-001` → **View document** → Factor 2 code (or **Use Passkey 2** if you registered one).
- **Expected:** the "Protected view, VW-YYYYMMDD-NNNN" dialog shows the PDF with a diagonal watermark.
- **Evidence:** F1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### F2 — View watermark contents
- **Steps:** zoom into the PDF in F1.
- **Expected:** you can read:
  - "CONFIDENTIAL";
  - "Viewed by: Test User A";
  - "Wallet: 0x…" (short form);
  - "IP: …";
  - "Date: DD Month YYYY";
  - "View ID: VW-…";
  - a QR code.

  The owner is **not** named in a view copy. The last page is a "LexCorp Document Control" page.
- **Evidence:** F2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### F3 — Viewing Office documents
- **Steps:** view `DOC-TEST-002` (Word).
- **Expected:** a watermarked **PDF** rendering of the text appears (not a .docx), headed "View rendering of … (text content only; layout not reproduced)".
- **Evidence:** F3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### F4 — View without Factor 2 is impossible
- **Steps:** open `http://localhost:5173/api/assets/document/view/DOC-TEST-001` directly while signed in.
- **Expected:** a JSON error that Factor 2 is required. No document bytes.
- **Evidence:** F4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## G. Delegated access

### G1 — Delegate with limits
- **Steps:**
  1. As USA open `DOC-TEST-001` → **Delegate access** → paste USB's wallet address → suggested view limit 2 → Factor 2.
  2. As MGR (with Radar Systems scope from D8, or as ADM): Review → View limit 2 → Accessible until = 1 hour from now → Approve → Factor 3.
- **Expected:** `DOC-TEST-001` → "Delegated access" shows USB with "0 of 2 views" and the expiry.
- **Evidence:** G1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### G2 — View limit enforced
- **Steps:** as USB open `DOC-TEST-001` → view three times.
- **Expected:** views 1 and 2 succeed, each with its own VW ID. View 3 is refused ("View limit reached").
- **Evidence:** G2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### G3 — Expiry enforced
- **Steps:** repeat G1 for `DOC-TEST-002` with "Accessible until" 5 minutes ahead. Wait 6 minutes, then view as USB.
- **Expected:** refused as expired.
- **Evidence:** G3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### G4 — Revoke a grant
- **Steps:** as USA, `DOC-TEST-002` → Delegated access → **Revoke** on an active grant. Then view as USB.
- **Expected:** refused.
- **Evidence:** G4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### G5 — Other documents stay invisible
- **Steps:** as USB open **Digital assets**.
- **Expected:** only delegated documents appear. Opening `/digital/DOC-TEST-003` shows "This document is not in your scope".
- **Evidence:** G5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## H. Download approval

### H1 — Non-owner requests a download
- **Preconditions:** USB has an active delegation with download allowed on `DOC-TEST-004`. Create one as in G1 with "Allow this identity to request downloads" ticked.
- **Steps:** as USB open `DOC-TEST-004` → **Request download** → purpose → Factor 2.
- **Expected:** "Request DL-… sent". My requests shows "Awaiting owner consent".
- **Evidence:** H1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### H2 — Owner consent, then Manager approval
- **Steps:**
  1. As USA: **My requests** → "Download requests for documents you own" → **Consent** → Factor 3.
  2. As MGR: Requests & approvals → Review → **Confirm approval** → Factor 3.
- **Expected:** the MGR queue shows the request only after owner consent. The request then reads "Approved, ready" for USB.
- **Evidence:** H2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### H3 — Fetch with Factor 3
- **Steps:** as USB: My requests → **Download copy** → Factor 3 → the file downloads.
- **Expected:** the file name contains the DL ID (for example `…DL-YYYYMMDD-NNNN.xlsx`).
- **Evidence:** H3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### H4 — Single use
- **Steps:** try **Download copy** on the same request again, if shown, or reload My requests.
- **Expected:** it is completed and cannot be downloaded again.
- **Evidence:** H4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### H5 — Download watermark
- **Steps:** open the downloaded file. For a PDF, request and download `DOC-TEST-001` the same way.
- **Expected:**
  - "Downloaded by: Test User B", wallet, IP, date and "Download ID: DL-…".
  - In download copies the owner **is** shown ("Owner: Test User A…").
  - A QR code, and the control page, section or sheet.
- **Evidence:** H5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### H6 — Refusals
- **Steps:** repeat H1 and have the owner **Refuse**. Repeat again and have MGR **Reject**.
- **Expected:** the request ends Rejected in both cases, and nothing is downloadable.
- **Evidence:** H6.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## I. Modification

### I1 — Modification copy
- **Steps:**
  1. As USA open `DOC-TEST-001` → **Request modification copy** → purpose → Factor 2.
  2. MGR approves.
  3. USA → My requests → **Download copy** → Factor 3.
- **Expected:** the modification copy is downloaded, watermarked.
- **Evidence:** I1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### I2 — Upload the revision
- **Steps:** edit the original PDF locally (or use any second PDF) → My requests → **Upload revision** → choose the file → Factor 3.
- **Expected:** "Revision MOD-… submitted as version 2; it awaits approval".
- **Evidence:** I2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### I3 — Revision approval and anchoring
- **Steps:** as MGR: Review the MOD request → **Approve and sign** → Factor 3.
- **Expected:** "approved and recorded on the ledger (block N)".
- **Evidence:** I3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### I4 — Version history
- **Steps:** open `DOC-TEST-001`.
- **Expected:**
  - "Versions" lists v1 (Obsolete) and v2 (Anchored) with different SHA-256 values.
  - A notice points to the newer version.
  - v1 still shows "Ledger recorded".
- **Evidence:** I4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### I5 — Modification history in later copies
- **Steps:** view v2 (`DOC-TEST-001-V2`) and look at the control page.
- **Expected:** it lists "Modification ID: MOD-…", "Modified by wallet: 0x…" and the date.
- **Evidence:** I5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## J. Watermark per format

### J1 — PDF
- **Steps:** open an H5 PDF in Edge or Adobe Reader.
- **Expected:** every page has the diagonal mark and a QR, and page content is not covered.
- **Evidence:** J1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### J2 — Word
- **Steps:** download `DOC-TEST-002` (process H) and open it in **Word**.
- **Expected:** it opens without a repair prompt. A faint diagonal watermark and header line appear on every page, and a final "Document Control" section. The original text is intact.
- **Evidence:** J2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### J3 — PowerPoint
- **Steps:** download `DOC-TEST-003` and open it in **PowerPoint**.
- **Expected:** it opens without a repair prompt. Every slide carries the mark and a QR, the original shapes are editable, and a control slide is appended.
- **Evidence:** J3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### J4 — Excel (charts preserved)
- **Steps:** download `DOC-TEST-004` and open it in **Excel**. View → Page Layout.
- **Expected:**
  - It opens without a repair prompt.
  - Cells, formulas **and the chart** are intact.
  - The header shows the watermark line and the footer "CONFIDENTIAL – DL-… – Page x of y".
  - A "LexCorp Control" sheet with a QR is added.
- **Evidence:** J4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### J5 — Image
- **Steps:** register, approve and view a PNG or JPEG image.
- **Expected:** a tiled diagonal mark, and a band below the image with the details and a QR. The picture itself is not cropped.
- **Evidence:** J5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### J6 — Tamper detection
- **Steps:**
  1. Open the QR page of a download (section K), then **Check a copy against this record**.
  2. Type "Downloaded by" exactly as printed → **Compare typed values**.
  3. Change one letter and compare again.
- **Expected:** "Matches the authoritative record", then "Does not match the record: possible tampering".
- **Evidence:** J6.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## K. QR verification (real phone)

### K1 — Scan a view watermark QR
- **Steps:** show the F1 view copy on the PC screen and scan its QR with the phone camera.
- **Expected:** the phone opens `http://<LAN address>:5173/verify/action/VW-…` and shows "Authentic LexCorp2 record (public view)". It does not show the viewer's name, wallet or IP.
- **Evidence:** K1-phone.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### K2 — Scan a download watermark QR
- **Steps:** print, or show on screen, the H5 PDF and scan its QR.
- **Expected:** the same public record page for the DL ID.
- **Evidence:** K2-phone.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### K3 — Authorized detail when signed in
- **Steps:** on the PC, signed in as ADM, open the same `/verify/action/…` URL, replacing the LAN address with `localhost`.
- **Expected:** "(authorized detail)", with creator, performer and network address shown.
- **Evidence:** K3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### K4 — Invalid reference
- **Steps:** on the phone open `/verify/action/VW-20000101-0001`.
- **Expected:** "Not verified", with no stack trace or internal details.
- **Evidence:** K4-phone.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## L. Physical assets

### L1 — Register with a MAC address
- **Steps:**
  1. As MGR: **Physical assets** → **Register asset**.
  2. Name "Navigation unit", serial `PHY-TEST-001`, department Avionics.
  3. "Yes, it has a MAC address" → `02:1A:2B:3C:4D:5E`; location "Lab 1".
  4. Custodian wallet = USA's address → **Submit for approval** → Factor 2.
- **Expected:** "Submitted for approval".
- **Evidence:** L1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L1b — Asset type "Other" needs a description
- **Steps:** Register asset → Asset type **Other**. Try to submit without filling **What is it?**, then fill in "Drone battery" and submit.
- **Expected:** the **What is it?** field appears when Other is chosen, and **Submit for approval** stays disabled until it's filled. After approval the asset page reads "Drone battery registered to …".
- **Evidence:** L1b.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L2 — Register with a unique address
- **Steps:** as L1 with serial `PHY-TEST-002` and "No, use a unique address" → `CHIP-TEST-0002`.
- **Expected:** accepted.
- **Evidence:** L2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L3 — Duplicate serial refused
- **Steps:** register `phy-test-001` (lower case) with a new MAC.
- **Expected:** "Asset serial number already exists". Nothing is created, and exactly **one** alert appears for the Auditor.
- **Evidence:** L3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L4 — Duplicate MAC in another notation refused
- **Steps:** register `PHY-TEST-003` with MAC `021a2b3c4d5e`.
- **Expected:** "MAC address is already registered". The audit details show a fingerprint, never the MAC itself.
- **Evidence:** L4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L5 — Duplicate unique address refused
- **Steps:** register `PHY-TEST-004` with unique address ` chip-test-0002 ` (different case, with spaces).
- **Expected:** "Device unique address is already registered".
- **Evidence:** L5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L6 — Approve and mint
- **Steps:** as ADM (MGR cannot approve their own), Review `PHY-TEST-001` → **Approve and sign** → Factor 3. Do the same for `PHY-TEST-002`.
- **Expected:** recorded on the ledger. The asset page shows Minted, the token, and the ledger transaction.
- **Evidence:** L6.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L7 — NFT card
- **Steps:** as MGR open `PHY-TEST-001` → **Download NFT card** and open the SVG.
- **Expected:** exactly Serial Number, NFT/Token ID, Creation Date, Department and a QR. No MAC, location, wallet or creation ID.
- **Evidence:** L7.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L8 — Scan the physical asset QR with the phone
- **Steps:** scan the card's QR, from screen or print.
- **Expected:** "Registered LexCorp2 asset, confirmed on the ledger" with minimal public fields. No MAC or location.
- **Evidence:** L8-phone.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L9 — Role-based redaction
- **Steps:** open `PHY-TEST-001` as MGR, as AUD and as USA (the custodian).
- **Expected:** MGR and AUD see the MAC and location. USA sees the asset but not the MAC or location, and gets no status, maintenance or card controls. USB cannot open it at all.
- **Evidence:** L9-<role>.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L10 — Status and maintenance
- **Steps:** as MGR: **Change status** → Maintenance → reason → Factor 3. Then **Record maintenance** → "Calibration".
- **Expected:** the Lifecycle timeline and Maintenance log show both entries.
- **Evidence:** L10.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### L11 — Unregistered custodian refused
- **Steps:** register `PHY-TEST-005` with custodian wallet `0x1212121212121212121212121212121212121212`.
- **Expected:** "The recipient must be a registered, active LexCorp2 identity."
- **Evidence:** L11.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## M. AI and rule alerts

### M1 — AI-assisted alert
- **Purpose:** show that AI analysis raises alerts for unusual behaviour.
- **Background:** the model's scores are calibrated against ordinary activity, so normal weekday work does not raise alerts.
- **Steps:**
  1. **Either** perform a User write outside business hours (before 08:00, after 19:00 or at a weekend), for example USA submitting a revision (I1 to I2).
  2. **Or**, to see AI alerts on demand: add `AI_ALERT_MODE=raw` to `backend/.env`, restart `npm start`, view a document as USA, then remove the line and restart again.
- **Expected:** **Security alerts** as AUD shows an alert "Raised by: AI-assisted risk analysis" with a risk score. The detail says the AI score is advice only.
- **Evidence:** M1.png. Note which option you used.
- [ ] PASS  [ ] FAIL — Notes: ______

### M2 — Rule-based alert
- **Steps:** L3 or L4 already produced one.
- **Expected:** "Raised by: Integrity or security rule", severity High.
- **Evidence:** M2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## N. Alert escalation

### N1 — Auditor forwards to the Manager
- **Steps:** as AUD: Security alerts → "Waiting for me" → open an alert about USA (Avionics) → note → **Forward to Manager**.
- **Expected:** it leaves AUD's queue and appears in MGR's queue (Manager review).
- **Evidence:** N1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### N2 — Manager dismisses
- **Steps:** as MGR open it → note "confirmed legitimate" → **Dismiss as false alarm**.
- **Expected:** state Dismissed. The history lists Raised, Forwarded (Auditor) and Dismissed (Manager).
- **Evidence:** N2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### N3 — Manager forwards to the Administrator
- **Steps:** AUD forwards another Avionics alert, then MGR clicks **Forward to Administrator**.
- **Expected:** it appears in ADM's queue.
- **Evidence:** N3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### N4 — Earlier stages become read-only
- **Steps:** as AUD open the alert from N3 with "All visible".
- **Expected:** "You can read it but not act on it". No action buttons.
- **Evidence:** N4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### N5 — Nobody decides on an alert about themselves
- **Steps:** as MGR open an alert whose subject is Test Manager (for example the L3 duplicate attempt).
- **Expected:** "This alert concerns your own identity. Another reviewer must decide."
- **Evidence:** N5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### N6 — Department with no Manager goes straight to Admin
- **Steps:** as AUD forward an alert about USB (Radar Systems). If you gave MGR the Radar Systems scope in D8, remove it first.
- **Expected:** it goes directly to Administrator review, with the note "[no independent manager covers this department]".
- **Evidence:** N6.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## O. Administrator revocation

### O1 — Revoke from an alert
- **Preconditions:** USB is signed in in their own profile.
- **Steps:** as ADM open the N6 alert → decision note → **Revoke identity** → Factor 3 (code, or **Use Passkey 3** with Windows Hello) → **Revoke identity**.
- **Expected:** "Identity revoked from ALT-…".
- **Evidence:** O1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### O2 — The live session ends
- **Steps:** in USB's profile, click any menu item.
- **Expected:** you are returned to sign-in, with a message that the identity was revoked or the session ended.
- **Evidence:** O2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### O3 — Sign-in refused
- **Steps:** try USB's TOTP 1 and Passkey 1.
- **Expected:** both are refused (generic message).
- **Evidence:** O3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### O4 — Ledger roles removed
- **Steps:** as ADM, Audit trail → category "Ledger and roles". Then run `cd backend && python scripts/verify_integrity.py`.
- **Expected:** role changes are recorded (USB had none as a User; for a revoked Manager you would see revocations). The integrity check passes the "on-chain roles match" check.
- **Evidence:** O4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### O5 — History preserved
- **Steps:** as ADM, **Administration** shows USB as "Revoked". Open the alert history and USB's earlier audit events.
- **Expected:** all history is intact.
- **Evidence:** O5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## P. Audit and indexer

### P1 — Audit filters
- **Steps:** as AUD, **Audit trail**. Filter by Category = Downloads, then Risk = High, then Result = Denied or failed, then a date range, then Asset ID = `DOC-TEST-001`. Open one event.
- **Expected:** each filter narrows the list correctly. The event dialog shows actor, time, asset, risk, alert state and reference.
- **Evidence:** P1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### P2 — Audit history cannot be changed, even in the database
- **Steps:** in a terminal: `docker exec -it lexcorp_postgres psql -U lexcorp -d lexcorp_sih -c "DELETE FROM audit_events WHERE true;"`
- **Expected:** `ERROR: LexCorp2 audit history is append-only (DELETE on audit_events rejected)`. Try `UPDATE audit_events SET risk_label='LOW';` too: rejected.
- **Evidence:** P2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### P3 — Indexer catches up after a restart
- **Steps:**
  1. Stop `npm start` (Ctrl+C). The ledger keeps producing blocks while the backend is down.
  2. Wait 2 minutes, then run `npm start` again.
  3. Check `http://127.0.0.1:8000/health`, then run the integrity script.
- **Expected:** the indexer is running and "indexer cursor on this chain and contract" passes (lag under 200 blocks).
- **Evidence:** P3.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### P4 — Integrity script
- **Steps:** `cd backend && python scripts/verify_integrity.py` at the end of your session.
- **Expected:** `9/9 checks passed`.
- **Evidence:** P4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## Q. Blockchain

### Q1 — Deployment and roles
- **Steps:** `npm run contract:verify`.
- **Expected:** 14 PASS lines, including "no publicly known dev account holds any role".
- **Evidence:** Q1.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### Q2 — Live ledger tests
- **Steps:** `npm run test:live` (works in PowerShell and Git Bash).
- **Expected:** `3 passed`.
- **Evidence:** Q2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### Q3 — Unauthorized mint is rejected by the contract itself
- **Steps:** Q2 includes this: a wallet without a role sends a real mint transaction.
- **Expected:** covered by Q2 passing. The receipt status is 0 and no token exists.
- [ ] PASS  [ ] FAIL — Notes: ______

### Q4 — Node RPC not exposed to browsers or the network
- **Steps:**
  1. From the phone browser open `http://<PC LAN address>:8545`.
  2. On the PC run `curl -s -H "Origin: http://evil.example" -X OPTIONS -i http://127.0.0.1:8545 | head -1`
- **Expected:** the phone cannot connect. The PC shows `403 CORS Rejected`.
- **Evidence:** Q4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### Q5 — Transactions appear in the audit trail
- **Steps:** Audit trail → Category "Digital assets" and "Physical assets" → look for "Ledger: document minted" and "Ledger: physical asset minted".
- **Expected:** each E4, I3 and L6 transaction appears with its ledger block.
- **Evidence:** Q5.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## R. Negative and security tests

### R1 — Edited watermark detected
- Covered by J6. Also upload an edited PDF copy with **Upload copy** on the verify page.
- **Expected:** a mismatch is reported.
- [ ] PASS  [ ] FAIL — Notes: ______

### R2 — A step-up proof cannot be reused
- **Steps:** use the same 6-digit Factor 3 code twice within 30 seconds, for two approvals.
- **Expected:** the second is refused (replay protection).
- **Evidence:** R2.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### R3 — Wrong-purpose factor
- Covered by C5.
- [ ] PASS  [ ] FAIL — Notes: ______

### R4 — No access without a session
- **Steps:** in a fresh profile (signed out), open `http://localhost:5173/api/assets/registry` and `http://localhost:5173/api/users`.
- **Expected:** `{"detail":"Authentication required"}`.
- **Evidence:** R4.png.
- [ ] PASS  [ ] FAIL — Notes: ______

### R5 — PIN reuse
- Covered by B5.
- [ ] PASS  [ ] FAIL — Notes: ______

### R6 — Database and ledger bound to this PC only
- **Steps:** from another device on the Wi-Fi, try to connect to `<PC LAN address>:5432` and `:8545`, for example with the phone browser.
- **Expected:** both refused or time out.
- **Evidence:** R6.png.
- [ ] PASS  [ ] FAIL — Notes: ______

---

## S. Cleanup

### S1 — Stop services
- **Steps:** Ctrl+C in the `npm start` terminal; `npm run besu:down`; `docker compose stop postgres`.
- [ ] Done

### S2 — Reset to a clean state (only if you want to test again from scratch)
This destroys the test data you created. It is not needed otherwise.
1. `docker compose up -d postgres`
2. `docker exec lexcorp_postgres psql -U lexcorp -d postgres -c "DROP DATABASE lexcorp_sih" -c "CREATE DATABASE lexcorp_sih OWNER lexcorp"`
3. `npm run besu:up && npm run chain:wait && npm run contract:deploy && npm run contract:verify`. A fresh contract avoids old test tokens showing as "unregistered mint" alerts.
4. `npm run migrate`
5. Delete `secrets/bootstrap_admin_pin.txt` and `secrets/bootstrap_admin_wallet.json`, then run `cd backend && python scripts/bootstrap_admin.py --name "Security Administrator" --department "Cyber Security"`
- [ ] Done

### S3 — Sensitive leftovers
- Delete `db_backups/` once you no longer need to roll back. It holds retired test data.
- Rotate the **WireGuard** keys and the **wg-easy** password. They are in git history (see the matrix, section 13).
- Remove the E2E vault files kept in `_scratch_archive/` when no longer needed.
- [ ] Done

---

## Release decision

Choose one, after completing the checklist:

- [ ] **PASS — ready for release**: every test passed, and the open items in matrix section 13 are resolved or accepted by the owner in writing.
- [ ] **PASS WITH KNOWN LIMITATIONS**: every critical test passed. List the accepted limitations (for example AI model quality, Office view rendering, git history):
      ______________________________________________
- [ ] **FAIL — blocking issues remain**: list the failed test IDs: ______________________

Automated results do not decide this on their own. Decide based on your manual results.

Tester: ____________  Date: ____________  Signature: ____________
