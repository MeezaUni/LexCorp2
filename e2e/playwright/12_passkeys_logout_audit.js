async (page) => {
  const FX = 'http://127.0.0.1:8765';
  const fx = async (path, body) => (body ? page.request.post(FX + path, { data: body, timeout: 95000 }) : page.request.get(FX + path, { timeout: 95000 })).then((r) => r.json());
  const cs = page.context().browser().contexts();
  const P = { admin: cs[1].pages()[0], user1: cs[2].pages()[0], manager: cs[3].pages()[0], auditor: cs[4].pages()[0] };
  const code = async (id, f) => (await fx(`/code/${id}/${f}`)).code;
  const log = []; const errors = [];
  for (const [k, p] of Object.entries(P)) {
    p.removeAllListeners('console'); p.removeAllListeners('response');
    p.on('console', (m) => { if (m.type() === 'error' && !/status of 40[1349]/.test(m.text())) errors.push(`${k}: ${m.text().slice(0, 140)}`); });
    p.on('response', (r) => { if (r.status() >= 500) errors.push(`${k}: ${r.status()} ${r.url()}`); });
  }
  const shot = (p, n, full = false) => p.screenshot({ path: `.playwright-mcp/e2e/shots/${n}.png`, fullPage: full, mask: [p.locator('[data-sensitive]')] });
  async function signIn(id) {
    const p = P[id];
    await p.goto('http://localhost:5173/');
    await p.waitForTimeout(1200);
    if (await p.locator('.masthead').count()) return;
    await p.getByLabel('Wallet address').fill((await fx(`/identity/${id}`)).address);
    await p.getByLabel('Login authenticator code (TOTP 1)').fill(await code(id, 'login'));
    await p.getByRole('button', { name: 'Sign in with authenticator code' }).click();
    await p.locator('.masthead').waitFor({ timeout: 20000 });
  }
  // logout, then sign in with the login passkey
  const u = P.user1;
  await signIn('user1');
  await u.getByRole('button', { name: 'Sign out' }).click();
  await u.getByRole('tab', { name: 'Sign in' }).waitFor();
  log.push('logout notice: ' + ((await u.locator('.notice').count()) ? await u.locator('.notice').first().innerText() : 'none'));
  const after = await u.request.get('http://localhost:5173/api/auth/me');
  log.push(`/auth/me after logout: HTTP ${after.status()}`);
  await u.getByLabel('Wallet address').fill((await fx('/identity/user1')).address);
  await u.getByRole('button', { name: 'Sign in with login passkey' }).click();
  await u.locator('.masthead').waitFor({ timeout: 20000 });
  log.push('signed in with Login Passkey 1 (virtual authenticator)');
  await u.waitForTimeout(1200);
  await shot(u, '12_user_dashboard');
  // wrong-address passkey sign-in is refused
  await u.getByRole('button', { name: 'Sign out' }).click();
  await u.getByLabel('Wallet address').fill((await fx('/identity/manager')).address);
  await u.getByRole('button', { name: 'Sign in with login passkey' }).click();
  await u.locator('.notice.error').waitFor({ timeout: 20000 });
  log.push("passkey of user1's device used for manager's address: " + (await u.locator('.notice.error').innerText()).replace(/\s+/g, ' ').slice(0, 120));

  // manager registers Passkey 3 (proved with Factor 3 code), then uses it for a Factor 3 action
  const m = P.manager;
  await signIn('manager');
  await m.goto('http://localhost:5173/identity');
  const panel = m.locator('section.panel', { has: m.getByRole('heading', { name: 'Factor 3: approve, mint and modify' }) });
  if (await m.getByRole('dialog').count()) await m.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
  await panel.getByRole('heading', { name: 'Passkeys' }).waitFor();
  if ((await panel.innerText()).includes('No passkey registered.')) {
    await panel.getByRole('button', { name: 'Register passkey on this device' }).click();
    const d = m.getByRole('dialog', { name: 'Add a passkey to this factor' });
    await d.getByLabel('Factor 3 authenticator code').fill(await code('manager', 'factor3'));
    await d.getByRole('button', { name: 'Continue', exact: true }).click();
    await m.getByText('Passkey registered.', { exact: true }).waitFor({ timeout: 30000 });
  }
  log.push('manager Passkey 3 present: ' + !(await panel.innerText()).includes('No passkey registered.') + ' (registered earlier with Factor 3 proof; duplicate registration of the same authenticator refused by WebAuthn)');
  await m.goto('http://localhost:5173/physical/PHY-AV-0004');
  await m.getByRole('button', { name: 'Change status' }).click();
  const sd = m.getByRole('dialog', { name: 'Change lifecycle status' });
  await sd.getByLabel('New status').selectOption('ASSIGNED');
  await sd.getByLabel('Reason (recorded)').fill('Issued to flight test team');
  await sd.getByRole('button', { name: 'Use Passkey 3' }).click();
  await m.getByText(/Status changed from/).waitFor({ timeout: 30000 });
  log.push('Factor 3 satisfied by Passkey 3 for a status change');
  // Passkey 1 (login) cannot satisfy Factor 2: user1 has no Passkey 2, so "Use Passkey 2" must fail
  await signIn('user1');
  await u.goto('http://localhost:5173/digital/DOC-AV-2026-0101-V2');
  await u.getByRole('button', { name: 'View document' }).click();
  const vd = u.getByRole('dialog', { name: 'View this document' });
  await vd.getByRole('button', { name: 'Use Passkey 2' }).click();
  await vd.locator('.notice.error').waitFor({ timeout: 30000 });
  log.push('login passkey offered for Factor 2: ' + (await vd.locator('.notice.error').innerText()).replace(/\s+/g, ' ').slice(0, 120));
  await vd.getByRole('button', { name: 'Cancel' }).click();

  // auditor: audit trail filters and dashboard
  const au = P.auditor;
  await signIn('auditor');
  await au.goto('http://localhost:5173/audit');
  await au.getByLabel('Category').selectOption('CHAIN');
  await au.getByRole('button', { name: 'Apply filters' }).click();
  await au.waitForTimeout(1500);
  log.push(`audit CHAIN events: ${await au.locator('tbody tr').count()}`);
  await au.getByLabel('Category').selectOption('');
  await au.getByLabel('Risk').selectOption('HIGH');
  await au.getByRole('button', { name: 'Apply filters' }).click();
  await au.waitForTimeout(1500);
  log.push(`audit HIGH events: ${await au.locator('tbody tr').count()}`);
  await shot(au, '12_audit_high');
  await au.locator('tbody tr').first().click();
  await au.getByRole('dialog').waitFor();
  await shot(au, '12_audit_event_detail');
  await au.getByRole('dialog').getByRole('button', { name: 'Close' }).first().click();
  await au.goto('http://localhost:5173/');
  await au.waitForTimeout(1500);
  await shot(au, '12_auditor_dashboard');
  await m.goto('http://localhost:5173/');
  await m.waitForTimeout(1500);
  await shot(m, '12_manager_dashboard');
  return { log, errors: errors.slice(0, 8) };
}
