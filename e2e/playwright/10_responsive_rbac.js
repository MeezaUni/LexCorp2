async (page) => {
  const FX = 'http://127.0.0.1:8765';
  const fx = async (path, body) => (body ? page.request.post(FX + path, { data: body, timeout: 95000 }) : page.request.get(FX + path, { timeout: 95000 })).then((r) => r.json());
  const cs = page.context().browser().contexts();
  const P = { admin: cs[1].pages()[0], user1: cs[2].pages()[0], manager: cs[3].pages()[0], auditor: cs[4].pages()[0] };
  const code = async (id, f) => (await fx(`/code/${id}/${f}`)).code;
  const errors = {}; const failed = {};
  for (const [k, p] of Object.entries(P)) {
    errors[k] = []; failed[k] = [];
    p.removeAllListeners('console'); p.removeAllListeners('response');
    p.on('console', (m) => { if (m.type() === 'error') errors[k].push(m.text().slice(0, 140)); });
    p.on('response', (r) => { if (r.status() >= 400 && r.url().includes('/api/')) failed[k].push(`${r.status()} ${r.url().replace('http://localhost:5173', '')}`); });
  }
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
  const out = { nav: {}, guards: {}, viewports: {} };
  for (const id of ['admin', 'user1', 'manager', 'auditor']) {
    await signIn(id);
    const p = P[id];
    await p.setViewportSize({ width: 1440, height: 900 });
    await p.goto('http://localhost:5173/');
    await p.locator('.nav a').first().waitFor();
    out.nav[id] = (await p.locator('.nav a').allInnerTexts()).map((t) => t.replace(/\n\d+$/, '').trim());
  }
  // direct URL + API guards for the USER role
  const u = P.user1;
  for (const path of ['/admin', '/alerts', '/audit']) {
    await u.goto(`http://localhost:5173${path}`);
    await u.locator('h1').waitFor();
    out.guards[`user ${path}`] = await u.locator('h1').innerText();
  }
  for (const [path, method] of [['/api/users/departments', 'get'], ['/api/alerts', 'get'], ['/api/audit/events', 'get'], ['/api/audit/stats', 'get'], ['/api/chain/status', 'get'], ['/api/chain/roles/reconcile', 'post'], ['/api/users?include_revoked=true', 'get']]) {
    const r = await u.request[method](`http://localhost:5173${path}`);
    let body = ''; try { const j = await r.json(); body = Array.isArray(j) ? `${j.length} rows` : (j.detail || JSON.stringify(j).slice(0, 60)); } catch { body = ''; }
    out.guards[`user API ${method.toUpperCase()} ${path}`] = `${r.status()} ${body}`;
  }
  const mRes = await P.manager.request.get('http://localhost:5173/api/chain/status');
  out.guards['manager API GET /api/chain/status'] = `${mRes.status()}`;
  const aRes = await P.auditor.request.post('http://localhost:5173/api/users', { data: { wallet_address: '0x' + '34'.repeat(20), role: 'USER', department: 'Avionics' } });
  out.guards['auditor API POST /api/users'] = `${aRes.status()}`;

  // responsive sweep (admin sees every page; the user sees the restricted set)
  const sizes = { desktop: [1920, 1080], laptop: [1366, 768], tablet: [768, 1024], mobile: [390, 844] };
  const pages = { dashboard: '/', digital: '/digital', digitalRecord: '/digital/DOC-AV-2026-0101', physical: '/physical', physicalRecord: '/physical/PHY-AV-0004', requests: '/requests', alerts: '/alerts', audit: '/audit', identity: '/identity', admin: '/admin' };
  for (const [vn, [w, h]] of Object.entries(sizes)) {
    const a = P.admin;
    await a.setViewportSize({ width: w, height: h });
    const res = {};
    for (const [pn, path] of Object.entries(pages)) {
      await a.goto(`http://localhost:5173${path}`);
      await a.locator('h1').waitFor({ timeout: 20000 });
      if (!(await a.locator('.masthead').count())) { await a.setViewportSize({ width: 1440, height: 900 }); await signIn('admin'); await a.setViewportSize({ width: w, height: h }); await a.goto(`http://localhost:5173${path}`); await a.locator('.masthead').waitFor({ timeout: 20000 }); }
      await a.waitForTimeout(900);
      const overflow = await a.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      const clipped = await a.evaluate(() => [...document.querySelectorAll('.btn')].filter((b) => { const r = b.getBoundingClientRect(); return r.width > 0 && (r.right > window.innerWidth + 1 || r.left < -1); }).length);
      res[pn] = overflow > 1 || clipped ? `overflow ${overflow}px, off-screen buttons ${clipped}` : 'ok';
      if (['dashboard', 'digitalRecord', 'physicalRecord', 'requests', 'audit', 'admin', 'alerts'].includes(pn)) {
        await a.screenshot({ path: `.playwright-mcp/e2e/shots/10_${vn}_${pn}.png`, fullPage: vn === 'mobile', mask: [a.locator('[data-sensitive]')] });
      }
    }
    if (vn === 'mobile' || vn === 'tablet') {
      await a.goto('http://localhost:5173/');
      await a.locator('#primary-nav').waitFor({ state: 'attached', timeout: 20000 });
      const sidebarVisibleBefore = await a.locator('#primary-nav').evaluate((el) => el.getBoundingClientRect().right > 0);
      await a.getByRole('button', { name: 'Menu' }).click();
      await a.waitForTimeout(400);
      const open = await a.locator('#primary-nav').evaluate((el) => el.getBoundingClientRect().right > 50);
      await a.screenshot({ path: `.playwright-mcp/e2e/shots/10_${vn}_nav_open.png` });
      await a.locator('#primary-nav').getByRole('link', { name: 'Audit trail' }).click();
      await a.locator('h1', { hasText: 'Audit trail' }).waitFor();
      const closedAfterNav = await a.locator('#primary-nav').evaluate((el) => el.getBoundingClientRect().right <= 1);
      res.navigation = `drawer hidden initially: ${!sidebarVisibleBefore}; opens: ${open}; navigates and closes: ${closedAfterNav}`;
    }
    out.viewports[vn] = res;
  }
  await P.admin.setViewportSize({ width: 1440, height: 900 });
  // sign-in and enrolment-free pages on a phone
  const ctx = await page.context().browser().newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const s = await ctx.newPage();
  await s.goto('http://localhost:5173/');
  await s.getByRole('tab', { name: 'Sign in' }).waitFor();
  await s.screenshot({ path: '.playwright-mcp/e2e/shots/10_mobile_signin.png', fullPage: true });
  out.viewports.mobile.signin = (await s.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)) > 1 ? 'overflow' : 'ok';
  await ctx.close();
  const summarize = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, [...new Set(v)].slice(0, 6)]));
  return { ...out, consoleErrors: summarize(errors), failedApi: summarize(failed) };
}
