async (page) => {
  const FX = 'http://127.0.0.1:8765';
  const fx = async (path, body) => (body ? page.request.post(FX + path, { data: body, timeout: 95000 }) : page.request.get(FX + path, { timeout: 95000 })).then((r) => r.json());
  const cs = page.context().browser().contexts();
  const P = { admin: cs[1].pages()[0], user1: cs[2].pages()[0], manager: cs[3].pages()[0], auditor: cs[4].pages()[0], user2: cs[5].pages()[0] };
  const log = []; const errors = [];
  for (const [k, p] of Object.entries(P)) {
    p.removeAllListeners('console'); p.removeAllListeners('response');
    p.on('console', (m) => { if (m.type() === 'error' && !/status of 40[134]/.test(m.text())) errors.push(`${k}: ${m.text().slice(0, 200)}`); });
    p.on('response', (r) => { if (r.status() >= 500) errors.push(`${k}: ${r.status()} ${r.url()}`); });
  }
  const shot = (p, n, full = false) => p.screenshot({ path: `.playwright-mcp/e2e/shots/${n}.png`, fullPage: full, mask: [p.locator('[data-sensitive]')] });
  const code = async (id, f) => (await fx(`/code/${id}/${f}`)).code;
  const stepUp = async (p, id, factor, dialogName, confirm) => {
    const d = p.getByRole('dialog', { name: dialogName });
    await d.getByLabel(`${factor === 'factor3' ? 'Factor 3' : 'Factor 2'} authenticator code`).fill(await code(id, factor));
    await d.getByRole('button', { name: confirm, exact: true }).click();
    return d;
  };
  const SERIAL = 'DOC-AV-2026-0101';
  const u = P.user1, m = P.manager, u2 = P.user2;
  const approveAll = async (label) => {
    await m.goto('http://localhost:5173/requests');
    const row = m.locator('tr', { hasText: label }).first();
    await row.getByRole('button', { name: 'Review' }).click();
    const d = m.getByRole('dialog', { name: /Decide on/ });
    await d.getByLabel('Factor 3 authenticator code').fill(await code('manager', 'factor3'));
    return d;
  };

  // --- controlled download
  await u.goto(`http://localhost:5173/digital/${SERIAL}`);
  await u.getByRole('button', { name: 'Request download' }).click();
  const rq = u.getByRole('dialog', { name: 'Request a download' });
  await rq.getByLabel('Purpose').fill('Design review pack');
  await stepUp(u, 'user1', 'factor2', 'Request a download', 'Send request');
  await u.getByText(/Request DL-/).waitFor({ timeout: 30000 });
  const dlId = (await u.getByText(/Request DL-/).innerText()).match(/DL-\d{8}-\d{4}/)[0];
  log.push(`download requested ${dlId}`);
  let d = await approveAll(dlId);
  await d.getByRole('button', { name: 'Confirm approval', exact: true }).click();
  await m.getByText(`${dlId} approved.`).waitFor({ timeout: 30000 });
  log.push('manager approved download (Factor 3)');
  await u.goto('http://localhost:5173/requests');
  const myRow = u.locator('tr', { hasText: dlId });
  await myRow.getByRole('button', { name: 'Download copy' }).click();
  const fd = u.getByRole('dialog', { name: `Download ${dlId}` });
  await fd.getByLabel('Factor 3 authenticator code').fill(await code('user1', 'factor3'));
  const [dl] = await Promise.all([u.waitForEvent('download'), fd.getByRole('button', { name: 'Download', exact: true }).click()]);
  const savedAs = `.playwright-mcp/e2e/downloads/${dl.suggestedFilename()}`;
  await dl.saveAs(savedAs);
  log.push(`downloaded ${dl.suggestedFilename()} (Factor 3, single use)`);
  await u.waitForTimeout(800);
  await shot(u, '05_my_requests_after_download', true);
  const reuse = await u.request.post(`http://localhost:5173/api/assets/document/download/${dlId}/fetch`);
  log.push(`second fetch of same download without new approval -> HTTP ${reuse.status()}`);

  // --- modification copy -> revision upload -> approval + anchor
  await u.goto(`http://localhost:5173/digital/${SERIAL}`);
  await u.getByRole('button', { name: 'Request modification copy' }).click();
  await u.getByRole('dialog', { name: 'Request a modification copy' }).getByLabel('Purpose').fill('Add watchdog requirements');
  await stepUp(u, 'user1', 'factor2', 'Request a modification copy', 'Send request');
  await u.getByText(/Request DL-/).waitFor({ timeout: 30000 });
  const modDl = (await u.getByText(/Request DL-/).innerText()).match(/DL-\d{8}-\d{4}/)[0];
  d = await approveAll(modDl);
  await d.getByRole('button', { name: 'Confirm approval', exact: true }).click();
  await m.getByText(`${modDl} approved.`).waitFor({ timeout: 30000 });
  await u.goto('http://localhost:5173/requests');
  const modRow = u.locator('tr', { hasText: modDl });
  await modRow.getByRole('button', { name: 'Download copy' }).click();
  const md = u.getByRole('dialog', { name: `Download ${modDl}` });
  await md.getByLabel('Factor 3 authenticator code').fill(await code('user1', 'factor3'));
  const [dl2] = await Promise.all([u.waitForEvent('download'), md.getByRole('button', { name: 'Download', exact: true }).click()]);
  await dl2.saveAs(`.playwright-mcp/e2e/downloads/${dl2.suggestedFilename()}`);
  await u.reload();
  await u.locator('tr', { hasText: modDl }).getByRole('button', { name: 'Upload revision' }).click();
  const up = u.getByRole('dialog', { name: `Submit revision of ${SERIAL}` });
  await up.getByLabel('Revised file').setInputFiles('.playwright-mcp/e2e/files/flight_control_spec_v2.pdf');
  await up.getByLabel('Factor 3 authenticator code').fill(await code('user1', 'factor3'));
  await up.getByRole('button', { name: 'Submit revision', exact: true }).click();
  await u.getByText(/Revision MOD-/).waitFor({ timeout: 30000 });
  const modId = (await u.getByText(/Revision MOD-/).innerText()).match(/MOD-\d{8}-\d{4}/)[0];
  log.push(`revision submitted ${modId} from ${modDl}`);
  d = await approveAll(modId);
  await shot(m, '05_review_revision');
  await d.getByRole('button', { name: 'Approve and sign', exact: true }).click();
  await m.getByText(/approved and recorded on the ledger/).waitFor({ timeout: 90000 });
  log.push('revision approved and anchored: ' + (await m.locator('.notice').first().innerText()).replace(/\s+/g, ' ').slice(0, 140));
  await u.goto(`http://localhost:5173/digital/${SERIAL}`);
  await u.getByRole('heading', { name: 'Versions' }).waitFor();
  await u.waitForTimeout(800);
  await shot(u, '05_versions', true);
  log.push('versions: ' + (await u.locator('section', { has: u.getByRole('heading', { name: 'Versions' }) }).locator('tbody tr').count()));

  // --- delegated access with a one-view limit for a Radar Systems user
  const u2addr = (await fx('/identity/user2')).address;
  await u.getByRole('button', { name: 'Delegate access' }).click();
  const dg = u.getByRole('dialog', { name: 'Delegate access to this document' });
  await dg.getByLabel('Identity wallet address or DID').fill(u2addr);
  await dg.getByLabel('Suggested view limit').fill('1');
  await stepUp(u, 'user1', 'factor2', 'Delegate access to this document', 'Send for approval');
  await u.getByText(/Access request ACR-/).waitFor({ timeout: 30000 });
  const acr = (await u.getByText(/Access request ACR-/).innerText()).match(/ACR-\d{8}-\d{4}/)[0];
  d = await approveAll(acr);
  await d.getByLabel('View limit').fill('1');
  await shot(m, '05_review_delegation');
  await d.getByRole('button', { name: 'Confirm approval', exact: true }).click();
  await m.getByText(`${acr} approved.`).waitFor({ timeout: 30000 });
  log.push(`delegation ${acr} approved with view limit 1`);
  await u2.goto('http://localhost:5173/digital');
  await u2.waitForTimeout(1200);
  const visible = await u2.locator('tbody tr').allInnerTexts();
  log.push(`user2 (Radar) register rows: ${visible.length}: ${visible.map((t) => t.split('\t')[0]).join(', ')}`);
  await u2.goto(`http://localhost:5173/digital/${SERIAL}`);
  for (const attempt of [1, 2]) {
    await u2.getByRole('button', { name: 'View document' }).click();
    const vd = await stepUp(u2, 'user2', 'factor2', 'View this document', 'View');
    if (attempt === 1) {
      await u2.getByRole('dialog', { name: /Protected view/ }).waitFor({ timeout: 30000 });
      await u2.waitForTimeout(2000);
      await shot(u2, '05_delegated_view');
      await u2.getByRole('dialog', { name: /Protected view/ }).getByRole('button', { name: 'Close' }).click();
      log.push('user2 view 1: watermarked copy shown');
    } else {
      await vd.locator('.notice.error').waitFor({ timeout: 30000 });
      log.push('user2 view 2: refused -> ' + (await vd.locator('.notice.error').innerText()));
      await shot(u2, '05_view_limit_reached');
      await vd.getByRole('button', { name: 'Cancel' }).click();
    }
  }
  return { log, errors };
}
