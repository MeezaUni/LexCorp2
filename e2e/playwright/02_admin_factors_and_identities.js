async (page) => {
  const FX = 'http://127.0.0.1:8765';
  const fx = async (path, body) => (body ? page.request.post(FX + path, { data: body, timeout: 95000 }) : page.request.get(FX + path, { timeout: 95000 })).then((r) => r.json());
  const ctx = page.context().browser().contexts()[1];
  const p = ctx.pages()[0];
  const log = [];
  const errors = [];
  p.on('console', (m) => { if (m.type() === 'error') errors.push(m.text().slice(0, 200)); });
  p.on('response', (r) => { if (r.status() >= 500) errors.push(`${r.status()} ${r.url()}`); });
  const mask = () => [p.locator('[data-sensitive]')];

  // Factor 2 and Factor 3 authenticators
  await p.goto('http://localhost:5173/identity');
  for (const [factor, heading] of [['factor2', 'Factor 2: view and submit'], ['factor3', 'Factor 3: approve, mint and modify']]) {
    const panel = p.locator('section.panel', { has: p.getByRole('heading', { name: heading }) });
    await panel.getByRole('button', { name: 'Set up authenticator' }).click();
    const dlg = p.getByRole('dialog');
    await dlg.getByRole('button', { name: 'Generate key' }).click();
    const secret = (await dlg.locator('.secret-box').innerText()).trim();
    await fx(`/totp/admin/${factor}`, { secret });
    await dlg.getByLabel('Code shown in the app').fill((await fx(`/code/admin/${factor}`)).code);
    await dlg.getByRole('button', { name: 'Confirm' }).click();
    await p.getByText('Authenticator configured.').waitFor();
    log.push(`${factor} authenticator configured`);
  }
  await p.screenshot({ path: '.playwright-mcp/e2e/shots/02_identity_admin.png', fullPage: true, mask: mask() });

  // Register identities (custodial wallet generation path; self-generated path is tested separately)
  const people = [
    ['manager', 'Priya Raman', 'Manager', 'Avionics'],
    ['auditor', 'Arjun Mehta', 'Auditor', 'Cyber Security'],
    ['user2', 'Kiran Das', 'User', 'Radar Systems'],
  ];
  await p.goto('http://localhost:5173/admin');
  for (const [id, name, role, dept] of people) {
    await p.getByRole('button', { name: 'Register identity' }).click();
    const dlg = p.getByRole('dialog', { name: 'Register an identity' });
    await dlg.getByLabel('Full name').fill(name);
    await dlg.getByLabel('Role').selectOption({ label: role });
    await dlg.getByLabel('Department').selectOption({ label: dept });
    await dlg.getByRole('button', { name: /generate a wallet for them/ }).click();
    const phrase = (await dlg.locator('.secret-box').innerText()).trim();
    const address = (await dlg.getByLabel('Wallet address').inputValue()).trim();
    await dlg.getByLabel('I have recorded the phrase for secure hand-over.').check();
    if (id === 'manager') await p.screenshot({ path: '.playwright-mcp/e2e/shots/02_register_identity.png', mask: mask() });
    await dlg.getByRole('button', { name: 'Register', exact: true }).click();
    const su = p.getByRole('dialog', { name: 'Confirm identity registration' });
    await su.getByLabel('Factor 3 authenticator code').fill((await fx('/code/admin/factor3')).code);
    await su.getByRole('button', { name: 'Register identity' }).click();
    const pinDlg = p.getByRole('dialog', { name: 'Identity registered' });
    await pinDlg.waitFor({ timeout: 60000 });
    const pin = (await pinDlg.getByTestId('one-time-pin').innerText()).trim();
    const ledger = (await pinDlg.locator('dd').last().innerText()).trim();
    await fx(`/identity/${id}`, { key: phrase, pin, address });
    if (id === 'manager') await p.screenshot({ path: '.playwright-mcp/e2e/shots/02_pin_shown_once.png', mask: mask() });
    await pinDlg.getByRole('button', { name: 'I have handed the PIN over' }).click();
    log.push(`${id}: registered as ${role}/${dept}; ledger roles: ${ledger}`);
  }
  await p.waitForTimeout(800);
  await p.screenshot({ path: '.playwright-mcp/e2e/shots/02_admin_identities.png', fullPage: true, mask: mask() });
  return { log, errors };
}
