async (page) => {
  const FX = 'http://127.0.0.1:8765';
  const fx = async (path, body) => (body ? page.request.post(FX + path, { data: body, timeout: 95000 }) : page.request.get(FX + path, { timeout: 95000 })).then((r) => r.json());
  const browser = page.context().browser();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const p = await ctx.newPage();
  const cdp = await ctx.newCDPSession(p);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  const log = [];
  const errors = [];
  p.on('console', (m) => { if (m.type() === 'error') errors.push(m.text().slice(0, 160)); });
  p.on('response', (r) => { if (r.status() >= 500) errors.push(`${r.status()} ${r.url()}`); });

  const boot = await fx('/bootstrap');
  await p.goto('http://localhost:5173/');
  await p.getByRole('tab', { name: 'First-time provisioning' }).click();
  await p.getByLabel('Recovery phrase or private key').fill(boot.key);
  await p.getByLabel('Provisioning PIN').fill(boot.pin);
  await p.getByRole('button', { name: /Provision wallet/ }).click();
  await p.getByRole('heading', { name: 'Security enrolment' }).waitFor({ timeout: 30000 });
  log.push('provisioned -> enrolment shown');
  await p.screenshot({ path: '.playwright-mcp/e2e/shots/01_enrolment.png', mask: [p.locator('[data-sensitive]')] });

  await p.getByRole('button', { name: 'Start authenticator setup' }).click();
  const secret = (await p.getByTestId('totp-secret').innerText()).trim();
  await fx('/totp/admin/login', { secret });
  await fx('/identity/admin', { key: boot.key, address: boot.address });
  await p.screenshot({ path: '.playwright-mcp/e2e/shots/01_totp_step.png', mask: [p.locator('[data-sensitive]')] });
  const { code } = await fx('/code/admin/login');
  await p.getByLabel('Code shown in the app').fill(code);
  await p.getByRole('button', { name: 'Confirm authenticator' }).click();
  await p.getByRole('button', { name: 'Register login passkey' }).waitFor();
  log.push('TOTP 1 configured');
  await p.getByRole('button', { name: 'Register login passkey' }).click();
  await p.getByRole('link', { name: 'Dashboard' }).waitFor({ timeout: 30000 });
  log.push('Passkey 1 registered (virtual authenticator) -> dashboard');
  await p.waitForTimeout(1500);
  await p.screenshot({ path: '.playwright-mcp/e2e/shots/01_admin_dashboard.png', mask: [p.locator('[data-sensitive]')] });
  const creds = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  return { log, errors, contexts: browser.contexts().length, credentials: creds.credentials.length, url: p.url() };
}
