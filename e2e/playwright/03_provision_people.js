async (page) => {
  const FX = 'http://127.0.0.1:8765';
  const fx = async (path, body) => (body ? page.request.post(FX + path, { data: body, timeout: 95000 }) : page.request.get(FX + path, { timeout: 95000 })).then((r) => r.json());
  const browser = page.context().browser();
  const admin = browser.contexts()[1].pages()[0];
  const log = [];
  const errors = [];

  async function newDevice() {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const p = await ctx.newPage();
    const cdp = await ctx.newCDPSession(p);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    p.on('console', (m) => { if (m.type() === 'error') errors.push(m.text().slice(0, 200)); });
    p.on('response', (r) => { if (r.status() >= 500) errors.push(`${r.status()} ${r.url()}`); });
    p.__cdp = cdp;
    return p;
  }

  // --- self-generated wallet for a new Avionics user (no custodial hand-over)
  const u1 = await newDevice();
  await u1.goto('http://localhost:5173/');
  await u1.getByRole('tab', { name: 'Create a wallet' }).click();
  await u1.getByRole('button', { name: 'Generate wallet on this device' }).click();
  const boxes = u1.locator('.secret-box');
  const selfAddress = (await boxes.nth(0).innerText()).trim();
  const selfPhrase = (await boxes.nth(1).innerText()).trim();
  await u1.screenshot({ path: '.playwright-mcp/e2e/shots/03_create_wallet.png', mask: [u1.locator('[data-sensitive]')] });
  await u1.getByLabel('I have recorded the recovery phrase in a safe place.').check();
  await u1.getByRole('button', { name: 'Clear it from the screen' }).click();
  log.push('user1 generated own wallet on device; phrase cleared from screen');
  // admin registers ONLY the address
  await admin.goto('http://localhost:5173/admin');
  await admin.getByRole('button', { name: 'Register identity' }).click();
  let dlg = admin.getByRole('dialog', { name: 'Register an identity' });
  await dlg.getByLabel('Full name').fill('Meera Iyer');
  await dlg.getByLabel('Role').selectOption({ label: 'User' });
  await dlg.getByLabel('Department').selectOption({ label: 'Avionics' });
  await dlg.getByLabel('Wallet address').fill(selfAddress);
  await dlg.getByRole('button', { name: 'Register', exact: true }).click();
  let su = admin.getByRole('dialog', { name: 'Confirm identity registration' });
  await su.getByLabel('Factor 3 authenticator code').fill((await fx('/code/admin/factor3')).code);
  await su.getByRole('button', { name: 'Register identity' }).click();
  const pinDlg = admin.getByRole('dialog', { name: 'Identity registered' });
  await pinDlg.waitFor({ timeout: 60000 });
  const pin1 = (await pinDlg.getByTestId('one-time-pin').innerText()).trim();
  await pinDlg.getByRole('button', { name: 'I have handed the PIN over' }).click();
  await fx('/identity/user1', { key: selfPhrase, pin: pin1, address: selfAddress });
  log.push('user1 registered by admin from a self-generated address');

  // --- provision + enrol each identity on its own device
  const devices = { user1: u1 };
  for (const id of ['manager', 'auditor', 'user2', 'user1']) {
    const p = devices[id] || await newDevice();
    const ident = await fx(`/identity/${id}`);
    await p.goto('http://localhost:5173/');
    await p.getByRole('tab', { name: 'First-time provisioning' }).click();
    await p.getByLabel('Recovery phrase or private key').fill(ident.key);
    await p.getByLabel('Provisioning PIN').fill(ident.pin);
    await p.getByRole('button', { name: /Provision wallet/ }).click();
    await p.getByRole('heading', { name: 'Security enrolment' }).waitFor({ timeout: 30000 });
    // enrolment is mandatory: the application is not reachable yet
    const appReachable = await p.getByRole('navigation', { name: 'Primary' }).count();
    await p.getByRole('button', { name: 'Start authenticator setup' }).click();
    await fx(`/totp/${id}/login`, { secret: (await p.getByTestId('totp-secret').innerText()).trim() });
    await p.getByLabel('Code shown in the app').fill((await fx(`/code/${id}/login`)).code);
    await p.getByRole('button', { name: 'Confirm authenticator' }).click();
    await p.getByRole('button', { name: 'Register login passkey' }).click();
    await p.locator('.masthead').waitFor({ timeout: 30000 });
    // Factor 2 + Factor 3 authenticators
    await p.goto('http://localhost:5173/identity');
    for (const [factor, heading] of [['factor2', 'Factor 2: view and submit'], ['factor3', 'Factor 3: approve, mint and modify']]) {
      const panel = p.locator('section.panel', { has: p.getByRole('heading', { name: heading }) });
      await panel.getByRole('button', { name: 'Set up authenticator' }).click();
      const d = p.getByRole('dialog');
      await d.getByRole('button', { name: 'Generate key' }).click();
      await fx(`/totp/${id}/${factor}`, { secret: (await d.locator('.secret-box').innerText()).trim() });
      await d.getByLabel('Code shown in the app').fill((await fx(`/code/${id}/${factor}`)).code);
      await d.getByRole('button', { name: 'Confirm' }).click();
      await p.getByText('Authenticator configured.').waitFor();
    }
    log.push(`${id}: provisioned, TOTP1 + Passkey1 enrolled (app hidden during enrolment: ${appReachable === 0}), Factor 2 + 3 set`);
  }
  return { log, errors, contexts: browser.contexts().length };
}
