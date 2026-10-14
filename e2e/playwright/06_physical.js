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

  // A Manager registers and records a physical asset directly: Factor 3, then their own wallet
  // mints it on the ledger. There is no approval step, so it never enters a /requests queue.
  async function register(serial, name, macOrUnique, isMac) {
    await m.goto('http://localhost:5173/physical');
    await m.getByRole('button', { name: 'Register asset' }).click();
    const d = m.getByRole('dialog', { name: 'Register a physical asset' });
    await d.getByLabel('Asset name').fill(name);
    await d.getByLabel('Serial number').fill(serial);
    await d.getByLabel('Department').selectOption({ label: 'Avionics' });
    if (isMac) await d.getByLabel('MAC address').fill(macOrUnique);
    else { await d.getByRole('button', { name: 'No, use a unique address' }).click(); await d.getByLabel('Unique device address').fill(macOrUnique); }
    await d.getByLabel('Location').fill('Hangar 3, bay 2');
    await d.getByLabel('Custodian wallet').fill(custodian);
    await d.getByRole('button', { name: 'Register and record' }).click();
    const su = m.getByRole('dialog', { name: 'Register and record this asset' });
    await su.getByLabel(/Code from your (Factor 3|login) authenticator/).fill(await code('manager', 'factor3'));
    await su.getByRole('button', { name: 'Register and record', exact: true }).click();
    const outcome = await Promise.race([
      m.getByText(`${serial} registered and recorded on the ledger`).waitFor({ timeout: 90000 }).then(() => 'recorded'),
      su.locator('.notice.error').waitFor({ timeout: 90000 }).then(async () => 'refused: ' + (await su.locator('.notice.error').innerText())),
    ]);
    if (outcome !== 'recorded') { await shot(m, `06_duplicate_refused`); await su.getByRole('button', { name: 'Cancel' }).click(); await d.getByRole('button', { name: 'Cancel' }).click(); }
    return outcome;
  }
  log.push('PHY-AV-0001 (MAC): ' + await register('PHY-AV-0001', 'Inertial navigation unit', '02:1A:2B:3C:4D:5E', true));
  log.push('PHY-AV-0002 (same MAC): ' + await register('PHY-AV-0002', 'Inertial navigation unit spare', '02:1a:2b:3c:4d:5e', true));
  log.push('PHY-AV-0001 (same serial): ' + await register('PHY-AV-0001', 'Duplicate serial', '02:99:88:77:66:55', true));
  log.push('PHY-AV-0003 (unique address): ' + await register('PHY-AV-0003', 'Cockpit display module', 'CHIP-7F3A-9921-00B4', false));
  await m.goto('http://localhost:5173/physical');
  await m.waitForTimeout(1000);
  await shot(m, '06_physical_register');
  for (const s of ['PHY-AV-0001', 'PHY-AV-0003']) {
    const row = await m.locator('tr', { hasText: s }).innerText();
    log.push(`${s} register row: ledger ${/Recorded/.test(row) ? 'recorded' : 'NOT recorded'}`);
  }

  // registered directly: nothing waits in the Admin's or the Manager's approval queue
  await a.goto('http://localhost:5173/requests');
  await a.waitForTimeout(1500);
  await m.goto('http://localhost:5173/requests');
  await m.waitForTimeout(1500);
  for (const s of ['PHY-AV-0001', 'PHY-AV-0003']) {
    log.push(`${s} in approval queues (admin, manager): ${await a.locator('tr', { hasText: s }).count()}, ${await m.locator('tr', { hasText: s }).count()}`);
  }

  // detail: card, QR, MAC visible to manager
  await m.goto('http://localhost:5173/physical/PHY-AV-0001');
  await m.getByRole('heading', { name: 'NFT card' }).waitFor({ timeout: 20000 });
  await m.waitForTimeout(1200);
  await shot(m, '06_physical_detail_manager', true);
  log.push('manager sees MAC: ' + (await m.getByText('02:1A:2B:3C:4D:5E', { exact: false }).count() > 0));
  // status change (Factor 3) + maintenance
  await m.getByRole('button', { name: 'Change status' }).click();
  const sd = m.getByRole('dialog', { name: 'Change lifecycle status' });
  await sd.getByLabel('New status').selectOption('MAINTENANCE');
  await sd.getByLabel('Reason (recorded)').fill('Scheduled calibration');
  await sd.getByLabel('Factor 3 authenticator code').fill(await code('manager', 'factor3'));
  await sd.getByRole('button', { name: 'Change status', exact: true }).click();
  await m.getByText(/Status changed from/).waitFor({ timeout: 20000 });
  await m.getByRole('button', { name: 'Record maintenance' }).click();
  const md = m.getByRole('dialog', { name: 'Record maintenance' });
  await md.getByLabel('Work performed').fill('Gyro calibration');
  await md.getByRole('button', { name: 'Record', exact: true }).click();
  await m.getByText('Maintenance recorded.').waitFor({ timeout: 20000 });
  log.push('status -> maintenance (Factor 3) and maintenance entry recorded');
  const tokenId = (await m.locator('.ribbon').innerText()).match(/#(\d+)/)[1];

  // custodian user: MAC and unique address redacted
  await u.goto('http://localhost:5173/physical/PHY-AV-0001');
  await u.getByRole('heading', { name: 'Asset record' }).waitFor({ timeout: 20000 });
  await u.waitForTimeout(1000);
  await shot(u, '06_physical_detail_custodian', true);
  const uText = await u.locator('main').innerText();
  log.push(`custodian sees MAC: ${uText.includes('02:1A:2B:3C:4D:5E')}; NFT card panel: ${uText.includes('NFT card')}`);
  // auditor: unrestricted role
  await P.auditor.goto('http://localhost:5173/physical/PHY-AV-0001');
  await P.auditor.getByRole('heading', { name: 'Asset record' }).waitFor({ timeout: 20000 });
  await P.auditor.waitForTimeout(800);
  log.push('auditor sees MAC: ' + (await P.auditor.locator('main').innerText()).includes('02:1A:2B:3C:4D:5E'));

  // public QR scan (signed out, phone-sized viewport)
  const pub = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const q = await pub.newPage();
  await q.goto(`http://localhost:5173/verify/token/${tokenId}`);
  await q.getByRole('status').first().waitFor({ timeout: 20000 });
  await q.waitForTimeout(800);
  await q.screenshot({ path: '.playwright-mcp/e2e/shots/06_public_verify_mobile.png', fullPage: true });
  const qText = await q.locator('main').innerText();
  log.push(`public verify: ${qText.includes('confirmed on the ledger') ? 'verified' : 'NOT verified'}; shows MAC: ${qText.includes('02:1A')}; shows location: ${qText.includes('Hangar')}; detail: ${qText.match(/(Public view|Authorized employee view)/)?.[0]}`);
  await q.goto('http://localhost:5173/verify/token/999999');
  await q.locator('.verdict.bad').waitFor({ timeout: 20000 });
  log.push('invalid token QR: ' + (await q.locator('.verdict.bad').innerText()));
  await pub.close();
  return { log, errors: errors.slice(0, 10) };
}
