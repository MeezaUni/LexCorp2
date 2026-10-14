async (page) => {
  const FX = 'http://127.0.0.1:8765';
  const fx = async (path, body) => (body ? page.request.post(FX + path, { data: body, timeout: 95000 }) : page.request.get(FX + path, { timeout: 95000 })).then((r) => r.json());
  const browser = page.context().browser();
  const cs = browser.contexts();
  const P = { admin: cs[1].pages()[0], user1: cs[2].pages()[0], manager: cs[3].pages()[0], auditor: cs[4].pages()[0], user2: cs[5].pages()[0] };
  const log = []; const errors = [];
  for (const [k, p] of Object.entries(P)) {
    p.removeAllListeners('console'); p.removeAllListeners('response');
    p.on('console', (m) => { if (m.type() === 'error' && !/status of 40[1349]/.test(m.text())) errors.push(`${k}: ${m.text().slice(0, 160)}`); });
    p.on('response', (r) => { if (r.status() >= 500) errors.push(`${k}: ${r.status()} ${r.url()}`); });
  }
  const shot = (p, n, full = false) => p.screenshot({ path: `.playwright-mcp/e2e/shots/${n}.png`, fullPage: full, mask: [p.locator('[data-sensitive]')] });
  const code = async (id, f) => (await fx(`/code/${id}/${f}`)).code;
  const m = P.manager, a = P.admin, u = P.user1;
  const custodian = (await fx('/identity/user1')).address;
  const SERIAL = 'PHY-AV-0004', MAC = '02:44:55:66:77:88';

  // Direct registration: a Manager records the asset with Factor 3 and their wallet; no approval queue.
  await m.goto('http://localhost:5173/physical');
  await m.getByRole('button', { name: 'Register asset' }).click();
  const d = m.getByRole('dialog', { name: 'Register a physical asset' });
  await d.getByLabel('Asset name').fill('Flight data recorder');
  await d.getByLabel('Serial number').fill(SERIAL);
  await d.getByLabel('Department').selectOption({ label: 'Avionics' });
  await d.getByLabel('MAC address').fill('not-a-mac');
  log.push('invalid MAC client validation shown: ' + (await d.getByText('Use six pairs of hex digits').count() > 0) + '; register disabled: ' + await d.getByRole('button', { name: 'Register and record' }).isDisabled());
  await d.getByLabel('MAC address').fill(MAC);
  await d.getByLabel('Location').fill('Hangar 1, secure store');
  await d.getByLabel('Custodian wallet').fill(custodian);
  await d.getByRole('button', { name: 'Register and record' }).click();
  const su = m.getByRole('dialog', { name: 'Register and record this asset' });
  const factorCode = su.getByLabel(/Code from your (Factor 3|login) authenticator/);
  await factorCode.fill(await code('manager', 'factor3'));
  await su.getByRole('button', { name: 'Register and record', exact: true }).click();
  await m.getByText(`${SERIAL} registered and recorded on the ledger`).waitFor({ timeout: 90000 });
  log.push(`${SERIAL}: registered and recorded on the ledger by the Manager's wallet`);
  // unknown custodian refused (before anything reaches the ledger)
  await m.getByRole('button', { name: 'Register asset' }).click();
  await d.getByLabel('Asset name').fill('Unknown custodian test');
  await d.getByLabel('Serial number').fill('PHY-AV-0099');
  await d.getByLabel('Department').selectOption({ label: 'Avionics' });
  await d.getByLabel('MAC address').fill('02:99:99:99:99:01');
  await d.getByLabel('Custodian wallet').fill('0x' + '12'.repeat(20));
  await d.getByRole('button', { name: 'Register and record' }).click();
  await factorCode.fill(await code('manager', 'factor3'));
  await su.getByRole('button', { name: 'Register and record', exact: true }).click();
  await su.locator('.notice.error').waitFor({ timeout: 30000 });
  log.push('unregistered custodian: ' + (await su.locator('.notice.error').innerText()));
  await su.getByRole('button', { name: 'Cancel' }).click();
  await d.getByRole('button', { name: 'Cancel' }).click();

  await a.goto('http://localhost:5173/requests');
  await a.waitForTimeout(1500);
  log.push(`${SERIAL} in the Admin's approval queue: ${await a.locator('tr', { hasText: SERIAL }).count()}`);

  await m.goto(`http://localhost:5173/physical/${SERIAL}`);
  await m.getByRole('heading', { name: 'NFT card' }).waitFor({ timeout: 20000 });
  await m.waitForTimeout(1200);
  await shot(m, '07_physical_detail_manager', true);
  const tokenId = (await m.locator('.ribbon').innerText()).match(/#(\d+)/)[1];

  await u.goto(`http://localhost:5173/physical/${SERIAL}`);
  await u.getByRole('heading', { name: 'Asset record' }).waitFor({ timeout: 20000 });
  await u.waitForTimeout(1200);
  await shot(u, '07_physical_detail_custodian', true);
  const ut = await u.locator('main').innerText();
  log.push(`custodian (USER): sees asset yes; MAC shown: ${ut.includes(MAC)}; location shown: ${ut.includes('secure store')}; NFT card panel: ${ut.includes('NFT card')}; status controls: ${ut.includes('Change status')}`);
  await P.auditor.goto(`http://localhost:5173/physical/${SERIAL}`);
  await P.auditor.getByRole('heading', { name: 'Asset record' }).waitFor({ timeout: 20000 });
  await P.auditor.waitForTimeout(800);
  const at = await P.auditor.locator('main').innerText();
  log.push(`auditor: MAC shown: ${at.includes(MAC)}; status controls: ${at.includes('Change status')}`);
  await P.user2.goto(`http://localhost:5173/physical/${SERIAL}`);
  await P.user2.waitForTimeout(2000);
  log.push('other-department user: ' + ((await P.user2.locator('h1').innerText())));

  const pub = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const q = await pub.newPage();
  await q.goto(`http://localhost:5173/verify/token/${tokenId}`);
  await q.locator('.verdict').waitFor({ timeout: 20000 });
  await q.waitForTimeout(600);
  await q.screenshot({ path: '.playwright-mcp/e2e/shots/07_public_verify_mobile.png', fullPage: true });
  const qt = await q.locator('main').innerText();
  log.push(`public QR: ${(await q.locator('.verdict').innerText())}; MAC shown: ${qt.includes(MAC)}; location shown: ${qt.includes('secure store')}; detail: ${qt.match(/(Public view|Authorized employee view)/)?.[0]}; horizontal overflow: ${await q.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)}`);
  await q.goto('http://localhost:5173/verify/token/999999');
  await q.locator('.verdict.bad').waitFor({ timeout: 20000 });
  log.push('invalid QR token: ' + (await q.locator('.verdict.bad').innerText()));
  await q.goto('http://localhost:5173/verify/action/VW-20260926-0001');
  await q.locator('.verdict').waitFor({ timeout: 20000 });
  await q.screenshot({ path: '.playwright-mcp/e2e/shots/07_public_verify_action_mobile.png', fullPage: true });
  const vt = await q.locator('main').innerText();
  log.push(`public watermark QR (VW-...0001): ${(await q.locator('.verdict').innerText())}; shows viewer name: ${vt.includes('Meera')}; shows IP: ${vt.includes('127.0.0.1')}`);
  await pub.close();
  return { log, errors: errors.slice(0, 8) };
}
