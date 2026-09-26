async (page) => {
  const FX = 'http://127.0.0.1:8765';
  const fx = async (path, body) => (body ? page.request.post(FX + path, { data: body, timeout: 95000 }) : page.request.get(FX + path, { timeout: 95000 })).then((r) => r.json());
  const cs = page.context().browser().contexts();
  const P = { admin: cs[1].pages()[0], user1: cs[2].pages()[0], manager: cs[3].pages()[0], auditor: cs[4].pages()[0], user2: cs[5].pages()[0] };
  const log = []; const errors = [];
  for (const [k, p] of Object.entries(P)) {
    p.removeAllListeners('console'); p.removeAllListeners('response');
    p.on('console', (m) => { if (m.type() === 'error' && !/status of 40[1349]/.test(m.text())) errors.push(`${k}: ${m.text().slice(0, 160)}`); });
    p.on('response', (r) => { if (r.status() >= 500) errors.push(`${k}: ${r.status()} ${r.url()}`); });
  }
  const shot = (p, n, full = false) => p.screenshot({ path: `.playwright-mcp/e2e/shots/${n}.png`, fullPage: full, mask: [p.locator('[data-sensitive]')] });
  const code = async (id, f) => (await fx(`/code/${id}/${f}`)).code;
  async function signIn(id) {
    const p = P[id];
    await p.goto('http://localhost:5173/');
    await p.waitForTimeout(1200);
    if (await p.locator('.masthead').count()) return 'already signed in';
    await p.getByLabel('Wallet address').fill((await fx(`/identity/${id}`)).address);
    await p.getByLabel('Login authenticator code (TOTP 1)').fill(await code(id, 'login'));
    await p.getByRole('button', { name: 'Sign in with authenticator code' }).click();
    await p.locator('.masthead').waitFor({ timeout: 20000 });
    return 'signed in with TOTP 1';
  }
  for (const id of ['auditor', 'manager', 'admin', 'user2']) log.push(`${id}: ${await signIn(id)}`);

  const au = P.auditor, m = P.manager, a = P.admin;
  await au.goto('http://localhost:5173/alerts');
  await au.getByRole('heading', { name: 'Security alerts' }).waitFor();
  await au.waitForTimeout(1200);
  await shot(au, '08_alerts_auditor', true);
  const rowsText = await au.locator('tbody tr').allInnerTexts();
  log.push(`auditor queue rows: ${rowsText.length}`);
  const pick = (who, event) => au.locator('tbody tr').filter({ hasText: who }).filter({ hasText: event }).first();

  // 1) user1 revision alert -> forward to Avionics manager -> manager dismisses
  await pick('Meera Iyer', 'Revision submitted').click();
  let dlg = au.getByRole('dialog', { name: /Alert ALT-/ });
  const id1 = (await dlg.getByRole('heading').first().innerText()).replace('Alert ', '');
  await dlg.getByLabel(/Note/).fill('Revision outside usual pattern; department manager to confirm.');
  await dlg.getByRole('button', { name: 'Forward to Manager' }).click();
  await au.getByText(`${id1} forwarded`).waitFor({ timeout: 20000 });
  log.push(`auditor forwarded ${id1}`);
  // the auditor can still read it, but cannot act at the manager stage
  await au.getByRole('button', { name: 'All visible' }).click();
  await au.locator('tbody tr', { hasText: id1 }).click();
  log.push('auditor on manager-stage alert: ' + (await au.getByRole('dialog').locator('.notice.info').innerText()).slice(0, 80));
  await au.getByRole('dialog').getByRole('button', { name: 'Close' }).first().click();

  await m.goto('http://localhost:5173/alerts');
  await m.locator('tbody tr', { hasText: id1 }).click();
  dlg = m.getByRole('dialog', { name: `Alert ${id1}` });
  await shot(m, '08_alert_detail_manager');
  await dlg.getByLabel(/Note/).fill('Confirmed with the engineer: planned revision for the watchdog requirement.');
  await dlg.getByRole('button', { name: 'Dismiss as false alarm' }).click();
  await m.getByText(`${id1} dismissed`).waitFor({ timeout: 20000 });
  log.push(`manager dismissed ${id1}`);

  // manager cannot decide on alerts about themselves
  await m.getByRole('button', { name: 'All visible' }).click();
  const own = m.locator('tbody tr').filter({ hasText: 'Priya Raman' }).first();
  if (await own.count()) {
    await own.click();
    log.push('manager viewing own-subject alert: ' + ((await m.getByRole('dialog').locator('.notice.warning').count()) ? 'blocked (another reviewer must decide)' : 'not at manager stage'));
    await m.getByRole('dialog').getByRole('button', { name: 'Close' }).first().click();
  }

  // 2) user2 view alert -> auditor forwards -> no Radar manager -> Admin review -> revoke identity
  await au.goto('http://localhost:5173/alerts');
  await au.waitForTimeout(800);
  await pick('Kiran Das', 'Document viewed').click();
  dlg = au.getByRole('dialog', { name: /Alert ALT-/ });
  const id2 = (await dlg.getByRole('heading').first().innerText()).replace('Alert ', '');
  await dlg.getByRole('button', { name: 'Forward to Manager' }).click();
  await au.getByText(`${id2} forwarded`).waitFor({ timeout: 20000 });
  const detail = await au.request.get(`http://localhost:5173/api/alerts/${id2}`).then((r) => r.json());
  log.push(`forwarded ${id2}; state now ${detail.state} (Radar Systems has no manager)`);

  await a.goto('http://localhost:5173/alerts');
  await a.locator('tbody tr', { hasText: id2 }).click();
  dlg = a.getByRole('dialog', { name: `Alert ${id2}` });
  await dlg.getByLabel(/Decision note/).fill('Access pattern confirmed as misuse after interview.');
  await shot(a, '08_alert_admin_stage');
  await dlg.getByRole('button', { name: 'Revoke identity' }).click();
  const rv = a.getByRole('dialog', { name: /Revoke the identity of/ });
  await rv.getByLabel('Factor 3 authenticator code').fill(await code('admin', 'factor3'));
  await shot(a, '08_revoke_factor3');
  await rv.getByRole('button', { name: 'Revoke identity', exact: true }).click();
  await a.getByText(`Identity revoked from ${id2}`).waitFor({ timeout: 60000 });
  log.push(`admin revoked subject of ${id2} (Factor 3)`);
  const hist = await a.request.get(`http://localhost:5173/api/alerts/${id2}`).then((r) => r.json());
  log.push('history: ' + hist.history.map((h) => `${h.action}:${h.to}`).join(' > '));

  // the revoked user's live session ends; sign-in is refused
  const u2 = P.user2;
  await u2.goto('http://localhost:5173/digital');
  await u2.waitForTimeout(2500);
  log.push('revoked user after navigation: ' + (await u2.locator('h1, h2').first().innerText()));
  await shot(u2, '08_revoked_user_signed_out');
  await u2.getByLabel('Wallet address').fill((await fx('/identity/user2')).address);
  await u2.getByLabel('Login authenticator code (TOTP 1)').fill(await code('user2', 'login'));
  await u2.getByRole('button', { name: 'Sign in with authenticator code' }).click();
  await u2.locator('.notice.error').waitFor({ timeout: 20000 });
  log.push('revoked user sign-in: ' + (await u2.locator('.notice.error').innerText()).replace(/\s+/g, ' '));
  return { log, errors: errors.slice(0, 8) };
}
