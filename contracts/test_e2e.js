/**
 * LexCorp E2E Integration Test
 *
 * Exercises every major flow:
 *   1. User registration & listing
 *   2. Document upload (off-chain storage + SHA-256)
 *   3. Physical asset minting on-chain
 *   4. Digital asset minting on-chain
 *   5. Event indexer picks up events
 *   6. AI risk engine scores events
 *   7. Asset registry reflects all assets
 *   8. On-chain access control (grant / check / revoke)
 *   9. Asset transfer on-chain
 *  10. Asset revoke (burn) on-chain
 *  11. Unauthorized mint attempt → logged on-chain
 *  12. Audit trail contains everything
 *  13. User deletion
 *
 * Run:  node test_e2e.js   (backend on :8000, Besu on :8545)
 */

const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const http = require("http");

// ─── Helpers ───────────────────────────────────────────────────────────────

const API = "http://127.0.0.1:8000";
let passed = 0;
let failed = 0;
let total = 0;

function assert(condition, label) {
  total++;
  if (condition) {
    passed++;
    console.log(`  ✅  ${label}`);
  } else {
    failed++;
    console.error(`  ❌  ${label}`);
  }
}

async function api(method, urlPath, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, API);
    const opts = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: { "Content-Type": "application/json" },
    };
    if (body && method !== "GET") {
      const raw = JSON.stringify(body);
      opts.headers["Content-Length"] = Buffer.byteLength(raw);
    }
    const req = http.request(opts, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data || "{}") });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on("error", reject);
    if (body && method !== "GET") req.write(JSON.stringify(body));
    req.end();
  });
}

// Upload a file as multipart (using boundary)
async function uploadFile(filePath) {
  return new Promise((resolve, reject) => {
    const boundary = "----TestBoundary" + Date.now();
    const fileName = path.basename(filePath);
    const fileContent = fs.readFileSync(filePath);
    const header = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="${fileName}"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`
    );
    const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
    const body = Buffer.concat([header, fileContent, footer]);

    const req = http.request({
      method: "POST",
      hostname: "127.0.0.1",
      port: 8000,
      path: "/api/assets/upload-document",
      headers: {
        "Content-Type": `multipart/form-data; boundary=${boundary}`,
        "Content-Length": body.length,
      },
    }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("  LexCorp SIH V2 — Full E2E Integration Test");
  console.log("═══════════════════════════════════════════════════════════\n");

  // ── Signers ──────────────────────────────────────────────────────────
  const [admin, user1, user2] = await hre.ethers.getSigners();
  const auditor = hre.ethers.Wallet.createRandom();
  console.log(`Admin (MANAGER):  ${admin.address}`);
  console.log(`User1:            ${user1.address}`);
  console.log(`User2:            ${user2.address}`);
  console.log(`Auditor:          ${auditor.address}\n`);

  const deployment = require("./deployments/localhost.json");
  const contract = await hre.ethers.getContractAt("AssetNFT", deployment.address, admin);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 1. USER REGISTRATION
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("─── 1. User Registration ───────────────────────────────");

  const adminRes = await api("POST", "/api/users", {
    wallet_address: admin.address,
    name: "Admin Manager",
    role: "ADMIN",
  });
  assert(adminRes.status === 201 || adminRes.status === 200, `Admin registered (status ${adminRes.status})`);

  const user1Res = await api("POST", "/api/users", {
    wallet_address: user1.address,
    name: "Regular User 1",
    role: "USER",
  });
  assert(user1Res.status === 201 || user1Res.status === 200, `User1 registered (status ${user1Res.status})`);

  const user2Res = await api("POST", "/api/users", {
    wallet_address: user2.address,
    name: "Regular User 2",
    role: "USER",
  });
  assert(user2Res.status === 201 || user2Res.status === 200, `User2 registered (status ${user2Res.status})`);

  const auditorRes = await api("POST", "/api/users", {
    wallet_address: auditor.address,
    name: "Compliance Auditor",
    role: "AUDITOR",
  });
  assert(auditorRes.status === 201 || auditorRes.status === 200, `Auditor registered (status ${auditorRes.status})`);

  // List users
  const listRes = await api("GET", "/api/users");
  assert(listRes.status === 200, `User list endpoint works (status 200)`);
  assert(Array.isArray(listRes.data) && listRes.data.length >= 4, `At least 4 users in DB (got ${listRes.data?.length})`);

  // Check DIDs were issued
  const firstUser = listRes.data.find(u => u.wallet_address.toLowerCase() === admin.address.toLowerCase());
  assert(firstUser && firstUser.did && firstUser.did.startsWith("did:ethr:"), `Admin DID issued: ${firstUser?.did}`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 2. DOCUMENT UPLOAD (Off-chain storage)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 2. Document Upload ─────────────────────────────────");

  // Create a test document
  const testDocPath = path.join(__dirname, "test_e2e_doc.txt");
  fs.writeFileSync(testDocPath, `LexCorp E2E Test Document\nTimestamp: ${new Date().toISOString()}\nPurpose: Integration verification`);

  const uploadRes = await uploadFile(testDocPath);
  assert(uploadRes.status === 200, `Document uploaded (status ${uploadRes.status})`);
  assert(uploadRes.data?.file_hash, `SHA-256 hash returned: ${uploadRes.data?.file_hash?.substring(0, 16)}...`);
  assert(uploadRes.data?.offchain_uri, `Offchain URI: ${uploadRes.data?.offchain_uri}`);
  assert(uploadRes.data?.status === "SECURELY_STORED_OFFCHAIN", `Status: ${uploadRes.data?.status}`);

  const fileHash = uploadRes.data.file_hash;
  const offchainURI = uploadRes.data.offchain_uri;

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 3. PHYSICAL ASSET MINTING
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 3. Physical Asset Minting ──────────────────────────");

  const runId = Math.floor(Math.random() * 1000000);
  const physicalTokenId = runId + 1000;
  const physicalSerial = `LEX-E2E-PHYSICAL-${runId}`;
  const user1DID = `did:ethr:13371:${user1.address.toLowerCase()}`;

  // Admin mints physical asset to user1
  const mintPhysicalTx = await contract.connect(admin).mint(
    user1.address,
    physicalTokenId,
    physicalSerial,
    user1DID,
  );
  const mintPhysicalReceipt = await mintPhysicalTx.wait();
  assert(mintPhysicalReceipt.status === 1, `Physical mint tx succeeded (block ${mintPhysicalReceipt.blockNumber})`);

  // Verify on-chain
  const physOwner = await contract.ownerOf(physicalTokenId);
  assert(physOwner.toLowerCase() === user1.address.toLowerCase(), `Physical asset owner is user1`);
  const [physSerial, physDID] = await contract.getAsset(physicalTokenId);
  assert(physSerial === physicalSerial, `Physical serial matches: ${physSerial}`);
  assert(physDID === user1DID, `Physical DID matches`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 4. DIGITAL ASSET MINTING
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 4. Digital Asset Minting ───────────────────────────");

  const digitalTokenId = runId + 2000;
  const digitalSerial = `LEX-E2E-DIGITAL-DOC-${runId}`;

  // Admin mints digital asset to user1
  const mintDigitalTx = await contract.connect(admin).mintDigitalAsset(
    user1.address,
    digitalTokenId,
    digitalSerial,
    user1DID,
    fileHash,
    offchainURI,
  );
  const mintDigitalReceipt = await mintDigitalTx.wait();
  assert(mintDigitalReceipt.status === 1, `Digital mint tx succeeded (block ${mintDigitalReceipt.blockNumber})`);

  // Verify digital asset metadata on-chain
  const [dSerial, dDID, dHash, dURI, dIsDigital] = await contract.getDigitalAsset(digitalTokenId);
  assert(dSerial === digitalSerial, `Digital serial matches`);
  assert(dDID === user1DID, `Digital DID matches`);
  assert(dHash === fileHash, `Digital file hash matches SHA-256`);
  assert(dURI === offchainURI, `Digital offchain URI matches`);
  assert(dIsDigital === true, `is_digital flag is true`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 5. EVENT INDEXER PICKS UP EVENTS
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 5. Event Indexer Verification ──────────────────────");

  // Wait for indexer to poll (it polls every ~2s)
  console.log("  ⏳ Waiting 5s for indexer to poll...");
  await sleep(5000);

  const auditRes = await api("GET", "/api/audit/events?limit=50");
  assert(auditRes.status === 200, `Audit endpoint works (status 200})`);

  const events = auditRes.data?.events || auditRes.data || [];
  const eventList = Array.isArray(events) ? events : [];

  const mintEvents = eventList.filter(e =>
    e.event_type === "AssetMinted" || e.event_type === "DigitalAssetMinted"
  );
  assert(mintEvents.length >= 2, `At least 2 mint events indexed (got ${mintEvents.length})`);

  const physMintEvent = mintEvents.find(e => e.asset_serial === physicalSerial);
  assert(!!physMintEvent, `Physical mint event found in audit trail`);

  const digMintEvent = mintEvents.find(e => e.asset_serial === digitalSerial);
  assert(!!digMintEvent, `Digital mint event found in audit trail`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 6. AI RISK ENGINE SCORING
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 6. AI Risk Engine Verification ─────────────────────");

  if (physMintEvent) {
    assert(
      physMintEvent.risk_score !== null && physMintEvent.risk_score !== undefined,
      `Physical mint event has risk_score: ${physMintEvent.risk_score}`
    );
    assert(
      physMintEvent.risk_label && physMintEvent.risk_label !== "",
      `Physical mint event has risk_label: ${physMintEvent.risk_label}`
    );
    console.log(`  📊 Risk score: ${physMintEvent.risk_score}, Label: ${physMintEvent.risk_label}`);
  }

  if (digMintEvent) {
    assert(
      digMintEvent.risk_score !== null && digMintEvent.risk_score !== undefined,
      `Digital mint event has risk_score: ${digMintEvent.risk_score}`
    );
    assert(
      digMintEvent.risk_label && digMintEvent.risk_label !== "",
      `Digital mint event has risk_label: ${digMintEvent.risk_label}`
    );
    console.log(`  📊 Risk score: ${digMintEvent.risk_score}, Label: ${digMintEvent.risk_label}`);
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 7. ASSET REGISTRY
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 7. Asset Registry ──────────────────────────────────");

  const registryRes = await api("GET", "/api/assets/registry");
  assert(registryRes.status === 200, `Registry endpoint works (status 200})`);

  const registryAssets = Array.isArray(registryRes.data) ? registryRes.data : [];
  assert(registryAssets.length >= 2, `At least 2 assets in registry (got ${registryAssets.length})`);

  const regPhys = registryAssets.find(a => a.token_id === physicalTokenId || a.serial_number === physicalSerial);
  assert(!!regPhys, `Physical asset ${physicalSerial} found in registry`);

  const regDig = registryAssets.find(a => a.token_id === digitalTokenId || a.serial_number === digitalSerial);
  assert(!!regDig, `Digital asset ${digitalSerial} found in registry`);

  // User1's assets
  const user1AssetsRes = await api("GET", `/api/assets/by-owner/${user1.address}`);
  assert(user1AssetsRes.status === 200, `User1 assets endpoint works`);
  const user1Assets = Array.isArray(user1AssetsRes.data) ? user1AssetsRes.data : [];
  assert(user1Assets.length >= 2, `User1 owns at least 2 assets (got ${user1Assets.length})`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 8. ON-CHAIN ACCESS CONTROL
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 8. Access Control (Grant / Check / Revoke) ─────────");

  const tempUser = hre.ethers.Wallet.createRandom();
  const unprivDID = `did:ethr:13371:${tempUser.address.toLowerCase()}`;

  // 8a. Check initial access — unprivileged user should NOT have access
  console.log(`  🔍 DEBUG: Checking access for token ${digitalTokenId}, DID: ${unprivDID}, Caller: ${tempUser.address}`);
  const checkBefore = await api("POST", "/api/assets/check-access", {
    token_id: digitalTokenId,
    requester_did: unprivDID,
    caller_address: tempUser.address,
  });
  console.log(`  🔍 DEBUG: API returned:`, JSON.stringify(checkBefore.data));
  assert(checkBefore.data?.authorized === false, `Unprivileged user initially denied access (authorized: ${checkBefore.data?.authorized})`);

  // 8b. Grant READ access to unpriv user on digital asset
  const grantTx = await contract.connect(admin).grantAssetAccess(
    digitalTokenId,
    unprivDID,
    1, // READ
  );
  const grantReceipt = await grantTx.wait();
  assert(grantReceipt.status === 1, `Grant access tx succeeded`);

  // 8c. Check access again — unpriv user should now have READ
  const checkAfterGrant = await api("POST", "/api/assets/check-access", {
    token_id: digitalTokenId,
    requester_did: unprivDID,
    caller_address: tempUser.address,
  });
  assert(checkAfterGrant.data?.authorized === true, `User now authorized (level: ${checkAfterGrant.data?.permission_level})`);
  assert(checkAfterGrant.data?.permission_level === 1, `Permission level is READ (1)`);

  // 8d. Upgrade to READ_WRITE
  const upgradeTx = await contract.connect(admin).grantAssetAccess(
    digitalTokenId,
    unprivDID,
    2, // READ_WRITE
  );
  const upgradeReceipt = await upgradeTx.wait();
  assert(upgradeReceipt.status === 1, `Upgrade access to READ_WRITE succeeded`);

  const checkUpgraded = await api("POST", "/api/assets/check-access", {
    token_id: digitalTokenId,
    requester_did: unprivDID,
    caller_address: tempUser.address,
  });
  assert(checkUpgraded.data?.permission_level === 2, `Permission level upgraded to READ_WRITE (2)`);

  // 8e. Revoke access
  const revokeAccessTx = await contract.connect(admin).revokeAssetAccess(digitalTokenId, unprivDID);
  const revokeAccessReceipt = await revokeAccessTx.wait();
  assert(revokeAccessReceipt.status === 1, `Revoke access tx succeeded`);

  const checkAfterRevoke = await api("POST", "/api/assets/check-access", {
    token_id: digitalTokenId,
    requester_did: unprivDID,
    caller_address: tempUser.address,
  });
  assert(checkAfterRevoke.data?.authorized === false, `User access revoked (authorized: ${checkAfterRevoke.data?.authorized})`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 9. ASSET TRANSFER
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 9. Asset Transfer ──────────────────────────────────");

  const newOwnerDID = `did:ethr:13371:${user2.address.toLowerCase()}`;

  // Transfer physical asset from user1 to user2
  // user1 is the owner but only MANAGERs can call transferAsset
  // Let's use admin (who has MANAGER_ROLE) to transfer
  const transferTx = await contract.connect(admin).transferAsset(
    user2.address,
    physicalTokenId,
    newOwnerDID,
  );
  const transferReceipt = await transferTx.wait();
  assert(transferReceipt.status === 1, `Transfer tx succeeded`);

  const newOwner = await contract.ownerOf(physicalTokenId);
  assert(newOwner.toLowerCase() === user2.address.toLowerCase(), `Physical asset now owned by user2`);
  const [, newDID] = await contract.getAsset(physicalTokenId);
  assert(newDID === newOwnerDID, `DID rebound to user2 after transfer`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 10. ASSET REVOKE (BURN)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 10. Asset Revoke (Burn) ────────────────────────────");

  const burnTokenId = runId + 3000;
  const burnSerial = `LEX-E2E-BURN-TEST-${runId}`;
  const burnDID = `did:ethr:13371:${user1.address.toLowerCase()}`;

  // Mint an asset specifically to burn
  const mintBurnTx = await contract.connect(admin).mint(
    user1.address,
    burnTokenId,
    burnSerial,
    burnDID,
  );
  await mintBurnTx.wait();
  const burnOwner = await contract.ownerOf(burnTokenId);
  assert(burnOwner.toLowerCase() === user1.address.toLowerCase(), `Burn-test asset minted to user1`);

  // Revoke (burn) it
  const revokeTx = await contract.connect(admin).revoke(burnTokenId);
  const revokeReceipt = await revokeTx.wait();
  assert(revokeReceipt.status === 1, `Revoke tx succeeded`);

  // Verify it's burned — ownerOf should revert (token doesn't exist)
  let isBurned = false;
  try {
    await contract.ownerOf(burnTokenId);
  } catch (e) {
    isBurned = true;
  }
  assert(isBurned, `Burned asset ownerOf() reverts (asset destroyed)`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 11. UNAUTHORIZED MINT ATTEMPT (recordAccessAttempt)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 11. Unauthorized Access Attempt Logging ────────────");

  const unauthorizedTokenId = runId + 4000;
  const unauthorizedDID = `did:ethr:13371:${user2.address.toLowerCase()}`;

  // user2 does NOT have MANAGER_ROLE — record the attempt on-chain
  const recordTx = await contract.connect(user2).recordAccessAttempt(
    unauthorizedTokenId,
    unauthorizedDID,
    false,
    "Unauthorized Mint Attempt - Missing MANAGER_ROLE (E2E Test)",
  );
  const recordReceipt = await recordTx.wait();
  assert(recordReceipt.status === 1, `Unauthorized attempt recorded on-chain`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Wait for indexer to catch up with all events
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n  ⏳ Waiting 5s for indexer to catch up...");
  await sleep(5000);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 12. AUDIT TRAIL
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 12. Audit Trail ────────────────────────────────────");

  const fullAudit = await api("GET", "/api/audit/events?limit=100");
  assert(fullAudit.status === 200, `Full audit query works`);
  const allEvents = Array.isArray(fullAudit.data?.events) ? fullAudit.data.events : (Array.isArray(fullAudit.data) ? fullAudit.data : []);

  // Check we have all event types
  const eventTypes = [...new Set(allEvents.map(e => e.event_type))];
  console.log(`  📋 Event types in audit: ${eventTypes.join(", ")}`);
  assert(eventTypes.includes("AssetMinted"), `Audit has AssetMinted events`);
  assert(eventTypes.includes("DigitalAssetMinted"), `Audit has DigitalAssetMinted events`);
  assert(eventTypes.includes("AccessAttempted"), `Audit has AccessAttempted events`);

  // Check AccessPermissionGranted/Revoked
  const accessEvents = allEvents.filter(e =>
    e.event_type === "AccessPermissionGranted" || e.event_type === "AccessPermissionRevoked"
  );
  assert(accessEvents.length >= 3, `At least 3 access permission events (grant + upgrade + revoke)`);

  // Check transfer event
  const transferEvents = allEvents.filter(e => e.event_type === "AssetTransferred");
  assert(transferEvents.length >= 1, `At least 1 transfer event`);

  // Check revoke/burn event
  const revokeEvents = allEvents.filter(e => e.event_type === "AssetRevoked");
  assert(revokeEvents.length >= 1, `At least 1 revoke event`);

  // Check the unauthorized attempt
  const authAttemptEvents = allEvents.filter(e =>
    e.event_type === "AccessAttempted" && e.actor_did === unauthorizedDID
  );
  assert(authAttemptEvents.length >= 1, `Unauthorized access attempt logged`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 13. USER DELETION
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 13. User Deletion ──────────────────────────────────");

  // Create a temporary user to delete
  const tempRes = await api("POST", "/api/users", {
    wallet_address: hre.ethers.Wallet.createRandom().address, // random Hardhat address
    name: "Temp User To Delete",
    role: "USER",
  });
  assert(tempRes.status === 201 || tempRes.status === 200, `Temp user created`);

  const tempUserId = tempRes.data?.id;
  assert(!!tempUserId, `Got temp user ID: ${tempUserId}`);

  // Delete the user
  const deleteRes = await api("DELETE", `/api/users/${tempUserId}`);
  assert(deleteRes.status === 204, `User deletion returned 204`);

  // Verify user is gone
  const afterDeleteList = await api("GET", "/api/users");
  const tempStillExists = afterDeleteList.data?.some(u => u.id === tempUserId);
  assert(!tempStillExists, `Deleted user no longer in user list`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 14. AI RISK ENGINE — Verify scoring across event types
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 14. AI Risk Engine — Full Score Review ──────────────");

  const scoredEvents = allEvents.filter(e => e.risk_score !== null && e.risk_score !== undefined);
  assert(scoredEvents.length >= 5, `At least 5 events scored by AI engine (got ${scoredEvents.length})`);

  const labels = {};
  scoredEvents.forEach(e => {
    const label = e.risk_label || "UNSCORED";
    labels[label] = (labels[label] || 0) + 1;
  });
  console.log(`  📊 Risk label distribution: ${JSON.stringify(labels)}`);

  const highRisk = scoredEvents.filter(e => e.risk_label === "HIGH");
  if (highRisk.length > 0) {
    console.log(`  ⚠️  ${highRisk.length} HIGH risk events detected (expected for unauthorized attempts)`);
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 15. BONUS: Verify preflight check works (backend read-only)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── 15. Backend Role Check ─────────────────────────────");

  const managerRole = await contract.MANAGER_ROLE();
  const adminHasRole = await contract.hasRole(managerRole, admin.address);
  assert(adminHasRole === true, `Admin has MANAGER_ROLE on-chain`);

  const user2HasRole = await contract.hasRole(managerRole, user2.address);
  assert(user2HasRole === false, `User2 does NOT have MANAGER_ROLE`);

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // CLEANUP
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n─── Cleanup ────────────────────────────────────────────");
  try { fs.unlinkSync(testDocPath); } catch {}
  console.log("  🧹 Test files cleaned up");

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // RESULTS
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  console.log("\n═══════════════════════════════════════════════════════════");
  console.log(`  RESULTS:  ${passed} passed  /  ${failed} failed  /  ${total} total`);
  console.log("═══════════════════════════════════════════════════════════\n");

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("\n💥 Fatal error:", err);
  process.exit(1);
});
