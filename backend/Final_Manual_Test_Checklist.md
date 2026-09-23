# Phase 14: Final Manual Test Checklist

## 1. Multi-Factor Authentication (MFA)
- [ ] Log in as an Administrator using Factor 1 (TOTP or Passkey).
- [ ] Attempt to propose a document `/api/assets/document/propose` without providing Factor 2 (TOTP or Passkey). Verify it fails with HTTP 401.
- [ ] Propose a document supplying valid Factor 2 credentials. Verify success.
- [ ] Attempt to approve a document `/api/assets/document/approval/{id}` without providing Factor 3. Verify it fails with HTTP 401.
- [ ] Approve a document using valid Factor 3 credentials. Verify contract minted on-chain.

## 2. Session Integrity
- [ ] Log in and intercept the generated JWT token. Modify the payload (e.g., change `role` to `ADMIN`). Verify the backend rejects the altered token (401).
- [ ] Generate a valid session. Use an admin API endpoint to revoke user sessions (e.g., incrementing `session_version`). Verify old JWTs are instantaneously invalidated (401).
- [ ] Initiate a request from one IP address, copy the JWT, and submit a curl request from a different IP. Verify it is rejected due to IP-binding restrictions (401).

## 3. Physical Asset Identity & Uniqueness (Phase 2 & 10)
- [ ] Propose a physical asset with a completely unique `serial_number`, `mac_address`, and `device_unique_address`. Verify proposal succeeds.
- [ ] Attempt to propose a new physical asset but reuse the `mac_address` of the previously registered asset. Verify rejection (400) and that a HIGH-RISK AuditEvent is generated and logged.
- [ ] Navigate to `/api/assets/serial/{serial}/verify-data`. Confirm full maintenance and verification data is present and accurate.

## 4. Role-Based Access Control & Redaction (Phase 11 & Phase 8)
- [ ] Log in as a standard USER in the "Avionics" department.
- [ ] Propose a document explicitly assigning it to the "Cyber Warfare" department. Verify rejection (403).
- [ ] Verify an existing physical hardware asset via `/api/assets/verify/{serial_number}`.
  - As a USER from a **different** department, ensure `mac_address`, `device_unique_address`, and `location` are masked/redacted.
  - As a MANAGER from the **exact** department (or as an ADMIN), ensure the full hardware identity parameters are visible in plaintext.

## 5. Physical NFT / QR Passport Certificate Generation (Phase 3)
- [ ] Query `/api/assets/serial/{serial}/card` in a browser.
  - Verify an SVG is rendered natively by the browser.
  - Ensure BEL Branding and Classification Badges are visible.
  - Scan the embedded Base64 QR code with a mobile scanner—ensure it correctly resolves to the LAN IP/verify-URL (e.g., `http://192.168.X.X:5173/verify/...`).

## 6. Document View & Download Watermarking (Phase 5, 6, 8, 9)
- [ ] Attempt to view a digital document as an authorized user (`/api/assets/document/view/{id}`). Confirm the returned file is non-destructively overlaid with a diagonal, semi-transparent watermark containing `VW-YYYYMMDD-XXXX`, the User DID abbreviation, and a tracking QR code.
- [ ] Request an explicit download of the document (`/api/assets/document/download/{id}`). Verify a Factor 3 approval flow is required and enforced.
- [ ] Once approved, download the document and confirm it contains the distinct `DL-YYYYMMDD-XXXX` permanent watermark template, differing from the transient View watermark.
- [ ] View an old, revised document and check the `MOD-YYYYMMDD-XXXX` deterministic lineage history watermark area is preserved for forensics.

## 7. Zero-Knowledge / Non-Destructive Validations
- [ ] Verify that no tables, rows, or historical test data on the DB or Smart Contracts were deleted during these tests, confirming compliance with "Do NOT wipe existing physical asset data" rules.
- [ ] Inspect Hyperledger Besu local node states (Chain ID 13371). Validate that event indices and contract addresses (if unchanged) correspond correctly to minted data.