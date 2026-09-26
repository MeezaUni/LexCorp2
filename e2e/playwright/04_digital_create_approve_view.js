async (page) => {
  const FX = 'http://127.0.0.1:8765';
  const fx = async (path, body) => (body ? page.request.post(FX + path, { data: body, timeout: 95000 }) : page.request.get(FX + path, { timeout: 95000 })).then((r) => r.json());
  const cs = page.context().browser().contexts();
  const P = { admin: cs[1].pages()[0], user1: cs[2].pages()[0], manager: cs[3].pages()[0], auditor: cs[4].pages()[0], user2: cs[5].pages()[0] };
  const log = []; const errors = [];
  for (const [k, p] of Object.entries(P)) {
    p.removeAllListeners('console'); p.removeAllListeners('response');
    p.on('console', (m) => { if (m.type() === 'error') errors.push(`${k}: ${m.text().slice(0, 200)}`); });
    p.on('response', (r) => { if (r.status() >= 500) errors.push(`${k}: ${r.status()} ${r.url()}`); });
  }
  const shot = (p, n, full = false) => p.screenshot({ path: `.playwright-mcp/e2e/shots/${n}.png`, fullPage: full, mask: [p.locator('[data-sensitive]')] });
  const stepUp = async (p, id, factor, dialogName, confirm) => {
    const d = p.getByRole('dialog', { name: dialogName });
    await d.getByLabel(`${factor === 'factor3' ? 'Factor 3' : 'Factor 2'} authenticator code`).fill((await fx(`/code/${id}/${factor}`)).code);
    await d.getByRole('button', { name: confirm, exact: true }).click();
    return d;
  };
  const SERIAL = 'DOC-AV-2026-0101';

  // user1 registers a document
  const u = P.user1;
  await u.goto('http://localhost:5173/digital');
  await u.getByRole('button', { name: 'Register document' }).click();
  const reg = u.getByRole('dialog', { name: 'Register a document' });
  await reg.getByLabel('Document file').setInputFiles('.playwright-mcp/e2e/files/flight_control_spec_v1.pdf');
  await reg.getByText('Stored in the vault').waitFor({ timeout: 30000 });
  await reg.getByLabel('Title').fill('Flight control computer interface specification');
  await reg.getByLabel('Asset ID (serial)').fill(SERIAL);
  await reg.getByLabel('Purpose (recorded with the request)').fill('Programme baseline');
  await shot(u, '04_register_document');
  await reg.getByRole('button', { name: 'Submit for approval' }).click();
  await stepUp(u, 'user1', 'factor2', 'Confirm document submission', 'Submit');
  await u.getByText('Submitted for approval').waitFor({ timeout: 30000 });
  await u.waitForTimeout(800);
  await shot(u, '04_digital_register_pending');
  log.push('user1 submitted document (Factor 2)');

  // manager approves -> signs mint -> server verifies on chain
  const m = P.manager;
  await m.goto('http://localhost:5173/requests');
  const row = m.locator('tr', { hasText: SERIAL });
  await row.getByRole('button', { name: 'Review' }).click();
  await shot(m, '04_review_creation');
  const d = await stepUp(m, 'manager', 'factor3', /Decide on/, 'Approve and sign');
  await m.getByText(/approved and recorded on the ledger/).waitFor({ timeout: 90000 });
  log.push('manager approved (Factor 3); ledger mint signed and verified: ' + (await m.locator('.notice').first().innerText()).replace(/\s+/g, ' ').slice(0, 160));

  // owner opens the record: ledger state, versions
  await u.goto(`http://localhost:5173/digital/${SERIAL}`);
  await u.getByRole('heading', { name: 'Record' }).waitFor();
  await shot(u, '04_document_record', true);
  log.push('record ribbon: ' + (await u.locator('.ribbon').innerText()).replace(/\s+/g, ' '));

  // controlled view with Factor 2
  await u.getByRole('button', { name: 'View document' }).click();
  await stepUp(u, 'user1', 'factor2', 'View this document', 'View');
  const viewer = u.getByRole('dialog', { name: /Protected view/ });
  await viewer.waitFor({ timeout: 30000 });
  await u.waitForTimeout(2500);
  await shot(u, '04_view_watermarked');
  log.push('view dialog: ' + (await viewer.getByRole('heading').innerText()));
  await viewer.getByRole('button', { name: 'Close' }).click();
  return { log, errors };
}
