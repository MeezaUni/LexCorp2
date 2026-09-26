import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { listAlerts, pendingDocuments, pendingDownloads, pendingPhysical } from '../services/api';
import { Button, shortWallet } from './ui';

/** Original LexCorp2 mark: a custody seal (square frame, inset bar and key notch). */
export function Mark({ size = 30 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect x="1.5" y="1.5" width="29" height="29" rx="3" fill="none" stroke="#fff" strokeWidth="2" />
      <rect x="7" y="7" width="5" height="18" fill="#fff" />
      <rect x="7" y="20" width="18" height="5" fill="#fff" />
      <rect x="17" y="7" width="8" height="8" fill="#1f5fbf" />
    </svg>
  );
}

const G = {
  dashboard: 'M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z',
  digital: 'M6 2h9l5 5v15H6zM14 2v6h6M9 13h8M9 17h8',
  physical: 'M3 7l9-4 9 4v10l-9 4-9-4zM3 7l9 4 9-4M12 11v10',
  requests: 'M4 5h16v4H4zM4 11h16v4H4zM4 17h10v3H4z',
  alerts: 'M12 3l10 18H2zM12 10v5M12 18v.5',
  audit: 'M5 3h14v18H5zM8 8h8M8 12h8M8 16h5',
  identity: 'M12 12a4 4 0 100-8 4 4 0 000 8zM4 21c1-4 4-6 8-6s7 2 8 6',
  admin: 'M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z',
};
const Glyph = ({ d }) => (
  <svg className="glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" aria-hidden="true"><path d={d} /></svg>
);

const STAGE = { AUDITOR: 'AUDITOR_REVIEW', MANAGER: 'MANAGER_REVIEW', ADMIN: 'ADMIN_REVIEW' };

function useCounts(user) {
  const [counts, setCounts] = useState({ approvals: 0, alerts: 0 });
  useEffect(() => {
    if (!user || user.onboarding_pending) return undefined;
    let alive = true;
    const load = async () => {
      const next = { approvals: 0, alerts: 0 };
      try {
        if (['ADMIN', 'MANAGER'].includes(user.role)) {
          const [d, p, dl] = await Promise.all([pendingDocuments(), pendingPhysical(), pendingDownloads()]);
          next.approvals = new Set([...d.filter((a) => a.action_type !== 'DOWNLOAD'), ...p, ...dl.filter((a) => !a.details?.requires_owner_approval || a.details?.owner_approved_by)].map((a) => a.action_id)).size;
        } else {
          const dl = await pendingDownloads().catch(() => []);
          next.approvals = dl.filter((a) => a.details?.requires_owner_approval && !a.details?.owner_approved_by && a.actor_did !== user.did).length;
        }
        if (STAGE[user.role]) next.alerts = (await listAlerts()).filter((a) => a.state === STAGE[user.role]).length;
      } catch { /* counts are informational */ }
      if (alive) setCounts(next);
    };
    load();
    const t = window.setInterval(load, 30000);
    window.addEventListener('lexcorp:refresh-counts', load);
    return () => { alive = false; window.clearInterval(t); window.removeEventListener('lexcorp:refresh-counts', load); };
  }, [user]);
  return counts;
}

export function refreshCounts() {
  window.dispatchEvent(new Event('lexcorp:refresh-counts'));
}

export default function Shell() {
  const { user, signOut, lastActivity } = useAuth();
  const [open, setOpen] = useState(false);
  const [now, setNow] = useState(Date.now());
  const location = useLocation();
  const counts = useCounts(user);
  useEffect(() => { setOpen(false); }, [location.pathname]);
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 30000); return () => clearInterval(t); }, []);
  const minutesLeft = Math.min(15, Math.max(0, 15 - Math.floor((now - lastActivity) / 60000)));

  const role = user.role;
  const items = [
    { to: '/', label: 'Dashboard', g: G.dashboard, end: true },
    { to: '/digital', label: 'Digital assets', g: G.digital },
    { to: '/physical', label: 'Physical assets', g: G.physical },
    { to: '/requests', label: ['ADMIN', 'MANAGER'].includes(role) ? 'Requests & approvals' : 'My requests', g: G.requests, count: counts.approvals },
    STAGE[role] && { to: '/alerts', label: 'Security alerts', g: G.alerts, count: counts.alerts, alert: true },
    role !== 'USER' && { to: '/audit', label: 'Audit trail', g: G.audit },
    { to: '/identity', label: 'My identity', g: G.identity },
    ['ADMIN', 'MANAGER'].includes(role) && { to: '/admin', label: role === 'ADMIN' ? 'Administration' : 'People', g: G.admin },
  ].filter(Boolean);

  return (
    <div className={`shell${open ? ' nav-open' : ''}`}>
      <header className="masthead">
        <NavLink to="/" className="brand" aria-label="LexCorp2 dashboard">
          <Mark />
          <span><span className="brand-name">LexCorp2</span><span className="brand-sub">Asset Assurance &amp; Custody</span></span>
        </NavLink>
        <button type="button" className="menu-button" aria-expanded={open} aria-controls="primary-nav" onClick={() => setOpen(!open)}>
          {open ? 'Close menu' : 'Menu'}
        </button>
        <div className="masthead-spacer" />
        <span className={`env-tag ${import.meta.env.MODE}`} title="Build mode">{import.meta.env.MODE === 'production' ? 'Production build' : 'Development build'}</span>
        <span className="session-chip" title="Session bound to this device's network address; ends after 15 minutes without activity">
          <span className={`dot${minutesLeft <= 3 ? ' warn' : ''}`} aria-hidden="true" />
          <span className="label">Session secure, {minutesLeft} min idle limit</span>
        </span>
      </header>

      <aside className="sidebar" id="primary-nav" aria-label="Primary">
        <ul className="nav">
          {items.map((it) => (
            <li key={it.to}>
              <NavLink to={it.to} end={it.end}>
                <Glyph d={it.g} />
                <span>{it.label}</span>
                {it.count > 0 && <span className={`count${it.alert ? ' alert' : ''}`} aria-label={`${it.count} waiting`}>{it.count}</span>}
              </NavLink>
            </li>
          ))}
        </ul>
        <div className="identity-card">
          <div className="name">{user.name || 'Unnamed identity'}</div>
          <div className="role">{roleName(role)}{user.department ? `, ${user.department}` : ''}</div>
          <div className="wallet" title={user.wallet_address}>{shortWallet(user.wallet_address)}</div>
          <Button variant="on-dark" size="sm" onClick={() => signOut('You signed out.')}>Sign out</Button>
        </div>
      </aside>
      <div className="scrim" onClick={() => setOpen(false)} aria-hidden="true" />

      <main className="main" id="main">
        <Outlet />
      </main>
    </div>
  );
}

export const roleName = (r) => ({ ADMIN: 'Administrator', MANAGER: 'Manager', AUDITOR: 'Auditor', USER: 'User' }[r] || r);
