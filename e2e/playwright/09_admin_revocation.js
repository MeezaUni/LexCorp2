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
  for (const id of ['admin', 'user2']) log.push(`${id}: ${await signIn(id)}`);
  const a = P.admin, u2 = P.user2;
  const ID = 'ALT-20260926-0011';
  await a.goto('http://localhost:5173/alerts');
  await a.getByRole('button', { name: 'All open' }).click();
  await a.locator('tbody tr', { hasText: ID }).click();
  let dlg = a.getByRole('dialog', { name: `Alert ${ID}` });
  await dlg.getByRole('button', { name: /Take over/ }).click();
  await a.getByText(`${ID} moved to Administrator review.`).waitFor({ timeout: 20000 });
  log.push('admin took over parked alert (no Radar manager)');
  await a.getByRole('button', { name: 'Waiting for me' }).click();
  await a.locator('tbody tr', { hasText: ID }).click();
  dlg = a.getByRole('dialog', { name: `Alert ${ID}` });
  await dlg.getByLabel(/Decision note/).fill('Access pattern confirmed as misuse after interview.');
  await shot(a, '09_alert_admin_stage');
  await dlg.getByRole('button', { name: 'Revoke identity' }).click();
  const rv = a.getByRole('dialog', { name: /Revoke the identity of/ });
  await rv.getByLabel('Factor 3 authenticator code').fill(await code('admin', 'factor3'));
  await shot(a, '09_revoke_factor3');
  await rv.getByRole('button', { name: 'Revoke identity', exact: true }).click();
  await a.getByText(`Identity revoked from ${ID}.`).waitFor({ timeout: 60000 });
  const hist = await a.request.get(`http://localhost:5173/api/alerts/${ID}`).then((r) => r.json());
  log.push('history: ' + hist.history.map((h) => `${h.action}->${h.to} by ${h.actor_role || 'system'}`).join(' | '));

  await u2.goto('http://localhost:5173/digital');
  await u2.waitForTimeout(2500);
  const heading = await u2.locator('h1').first().innerText();
  const notice = (await u2.locator('.notice').count()) ? await u2.locator('.notice').first().innerText() : '';
  log.push(`revoked user's live session: page="${heading}" notice="${notice.replace(/\s+/g, ' ').slice(0, 120)}"`);
  await shot(u2, '09_revoked_user_signed_out');
  await u2.getByLabel('Wallet address').fill((await fx('/identity/user2')).address);
  await u2.getByLabel('Login authenticator code (TOTP 1)').fill(await code('user2', 'login'));
  await u2.getByRole('button', { name: 'Sign in with authenticator code' }).click();
  await u2.locator('.notice.error').waitFor({ timeout: 20000 });
  log.push('revoked user sign-in attempt: ' + (await u2.locator('.notice.error').innerText()).replace(/\s+/g, ' '));
  await a.goto('http://localhost:5173/admin');
  await a.waitForTimeout(1500);
  log.push('admin register row for Kiran Das: ' + (await a.locator('tr', { hasText: 'Kiran Das' }).innerText()).replace(/\s+/g, ' '));
  return { log, errors: errors.slice(0, 8) };
}
