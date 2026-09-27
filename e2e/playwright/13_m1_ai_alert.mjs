// Checklist test M1 (AI-assisted alert, trained local model), end to end in the browser.
//
//   cd e2e/playwright && npm install && node 13_m1_ai_alert.mjs [--headed] [--keep]
//
// Needs the stack running (npm start) with a trained model (backend/ml/models/risk_model.joblib).
// Unlike scripts 01-12 this one runs standalone with the Playwright library and your installed
// Chrome, and brings its own people: scripts/e2e_m1_fixture.py seeds labelled E2E-M1 people with
// three weeks of ordinary history, and their secrets stay in this process's memory. At the end
// the test Auditor dismisses the test alert, and the fixture retires the people and deletes the
// documents, unless --keep is given (then run `python scripts/e2e_m1_fixture.py cleanup` later).
// The audit trail is append-only, so each run's history, actions and alert remain in it,
// attributed to the retired E2E-M1 identities.
//
//   1. E2E-M1 Ordinary User signs in and views three familiar documents at a normal pace.
//   2. E2E-M1 Burst User signs in and quickly views 12 Finance documents never touched before.
//   3. E2E-M1 Auditor opens Security alerts.
// Expected: no AI alert for 1; exactly one AI alert for 2, with reasons in plain words.
//
// Sign-in uses the login authenticator code (computed here from the seeded secret); every view
// uses the login passkey through a Chrome DevTools virtual authenticator, as scripts 01-12 did.

import { spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const APP = 'http://localhost:5173';
const SHOTS = join(ROOT, 'docs', 'evidence', 'playwright');
const headed = process.argv.includes('--headed');
const keep = process.argv.includes('--keep');

const fixture = (...args) => {
  const r = spawnSync('python', [join(ROOT, 'scripts', 'e2e_m1_fixture.py'), ...args], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`fixture ${args[0]} failed:\n${r.stderr || r.stdout}`);
  return r.stdout.trim();
};

function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secret.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
  const h = createHmac('sha1', key).update(msg).digest();
  const o = h[h.length - 1] & 0x0f;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

async function personPage(browser, who) {
  const context = await browser.newContext({ viewport: { width: 1366, height: 900 } });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
               isUserVerified: true, automaticPresenceSimulation: true },
  });
  await cdp.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: { credentialId: who.passkey.credentialId, privateKey: who.passkey.privateKey, rpId: 'localhost',
                  isResidentCredential: false, signCount: 0 },
  });
  page.on('response', (r) => { if (r.status() >= 500) errors.push(`${who.name}: ${r.status()} ${r.url()}`); });
  await page.goto(APP + '/');
  await page.getByLabel('Wallet address').fill(who.address);
  await page.getByLabel('Login authenticator code (TOTP 1)').fill(totp(who.totp));
  await page.getByRole('button', { name: 'Sign in with authenticator code' }).click();
  await page.locator('.masthead').waitFor({ timeout: 20000 });
  return page;
}

async function viewDocument(page, serial) {
  await page.goto(`${APP}/digital/${encodeURIComponent(serial)}`);
  await page.getByRole('button', { name: 'View document' }).click();
  await page.getByRole('dialog', { name: 'View this document' }).getByRole('button', { name: /^Use .*passkey$/ }).click();
  const viewer = page.getByRole('dialog', { name: /Protected view/ });
  await viewer.waitFor({ timeout: 30000 });
  const title = await viewer.getByRole('heading').first().innerText();
  await viewer.getByRole('button', { name: 'Close' }).first().click();
  return title.replace('Protected view, ', '');
}

const errors = [];
const log = (s) => console.log(s);
const shot = (page, name) => page.screenshot({ path: join(SHOTS, `${name}.png`), fullPage: true, mask: [page.locator('[data-sensitive]')] });

async function viewRisks(auditor, name) {
  const r = await auditor.request.get(`${APP}/api/audit/events?identity=${encodeURIComponent(name)}&event_type=DOCUMENT_VIEWED&limit=100`);
  const since = Date.now() - 30 * 60 * 1000;
  return (await r.json()).filter((e) => Date.parse(e.created_at) >= since && !(e.risk_factors || {}).seed)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));
}

const secrets = JSON.parse(fixture('seed', '--emit-secrets'));
log(`Seeded E2E-M1 people, ${secrets.documents.engineering.length + secrets.documents.finance.length} documents, ${secrets.history_events} history events.`);
mkdirSync(SHOTS, { recursive: true });
const browser = await chromium.launch({ channel: 'chrome', headless: !headed });
let passed = false;
try {
  // 1) ordinary work at a normal pace
  const ordinary = await personPage(browser, secrets.ordinary);
  for (const serial of secrets.documents.engineering.filter((s) => /ENG-0[123]$/.test(s))) {
    log(`  ordinary user viewed ${serial} (${await viewDocument(ordinary, serial)})`);
    await ordinary.waitForTimeout(15000);
  }

  // 2) the burst: 12 never-touched Finance documents, one after another
  const burst = await personPage(browser, secrets.burst);
  for (const serial of secrets.documents.finance) log(`  burst user viewed ${serial} (${await viewDocument(burst, serial)})`);

  // 3) the Auditor's queue
  const auditor = await personPage(browser, secrets.auditor);
  await auditor.goto(`${APP}/alerts`);
  await auditor.getByRole('heading', { name: 'Security alerts' }).waitFor();
  await auditor.getByRole('button', { name: 'All visible' }).click();
  await auditor.waitForTimeout(1500);
  const rows = (name) => auditor.locator('tbody tr').filter({ hasText: name });
  const ordinaryRows = await rows(secrets.ordinary.name).count();
  const burstRows = await rows(secrets.burst.name).count();
  await shot(auditor, '13_m1_alert_queue');

  let reason = '', raisedBy = '';
  if (burstRows) {
    await rows(secrets.burst.name).first().click();
    const dlg = auditor.getByRole('dialog', { name: /Alert ALT-/ });
    await dlg.waitFor();
    const facts = await dlg.innerText();
    reason = (facts.match(/Reason\s*\n?\s*(.+)/) || [])[1] || '';
    raisedBy = (facts.match(/Raised by\s*\n?\s*(.+)/) || [])[1] || '';
    await shot(auditor, '13_m1_alert_detail');
    // close the test alert the way an Auditor would, so it doesn't sit in real reviewers' queues
    const id = (await dlg.getByRole('heading').first().innerText()).replace('Alert ', '');
    await dlg.getByLabel(/Note/).fill('Automated checklist test M1 (E2E-M1 test identity); not a real incident.');
    await dlg.getByRole('button', { name: 'Dismiss as false alarm' }).click();
    await auditor.getByText(`${id} dismissed`).waitFor({ timeout: 20000 });
    log(`  auditor dismissed test alert ${id}`);
  }

  log('\nRisk of each view (from the audit trail):');
  for (const [label, who] of [['ordinary', secrets.ordinary], ['burst', secrets.burst]]) {
    for (const e of await viewRisks(auditor, who.name)) {
      const ai = (e.risk_factors || {}).ai || {};
      log(`  ${label.padEnd(8)} ${e.asset_serial.padEnd(14)} ${String(e.risk_label).padEnd(8)} ${Number(e.risk_score ?? 0).toFixed(1).padStart(5)}  ${(ai.reasons || []).join('; ')}`);
    }
  }

  log('\nResults:');
  const checks = [
    ['no alert about the ordinary user', ordinaryRows === 0, `${ordinaryRows} alert(s)`],
    ['exactly one alert about the burst user', burstRows === 1, `${burstRows} alert(s)`],
    ['raised by AI-assisted risk analysis', raisedBy.includes('AI-assisted'), raisedBy || '-'],
    ['reason in plain words', /Unusual activity/.test(reason) && reason.length > 40, reason || '-'],
    ['alert shows the strongest evidence of the burst', /documents never touched before/.test(reason), reason || '-'],
    ['no server errors', errors.length === 0, errors.slice(0, 3).join(' | ') || 'none'],
  ];
  for (const [name, ok, detail] of checks) log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}: ${detail}`);
  passed = checks.every(([, ok]) => ok);
  log(`\nM1 ${passed ? 'PASSED' : 'FAILED'}. Screenshots: docs/evidence/playwright/13_m1_alert_queue.png, 13_m1_alert_detail.png`);
} finally {
  await browser.close();
  if (keep) log('Fixture data kept (--keep). Remove it with: python scripts/e2e_m1_fixture.py cleanup');
  else log(fixture('cleanup'));
}
process.exit(passed ? 0 : 1);
