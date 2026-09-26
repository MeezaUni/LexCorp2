import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { roleName } from '../components/Shell';
import { Empty, Facts, Id, Loading, Notice, PageHeader, Panel, Status, formatDate, shortWallet } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import * as api from '../services/api';

const STAGE = { AUDITOR: 'AUDITOR_REVIEW', MANAGER: 'MANAGER_REVIEW', ADMIN: 'ADMIN_REVIEW' };
const settle = async (p) => { try { return await p; } catch { return null; } };

export default function Dashboard() {
  const { user, canApprove, isSecurity, isAdmin } = useAuth();
  const [d, setD] = useState(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      const role = user.role;
      const [registry, mine, docs, phys, dls, alerts, stats, events, chain, users, resets, health] = await Promise.all([
        settle(api.getRegistry()),
        settle(api.myDownloads()),
        canApprove ? settle(api.pendingDocuments()) : null,
        canApprove ? settle(api.pendingPhysical()) : null,
        settle(api.pendingDownloads()),
        isSecurity ? settle(api.listAlerts()) : null,
        role !== 'USER' ? settle(api.auditStats()) : null,
        role !== 'USER' ? settle(api.auditEvents({ limit: 8 })) : null,
        ['ADMIN', 'AUDITOR'].includes(role) ? settle(api.chainStatus()) : null,
        isAdmin ? settle(api.listUsers({ include_revoked: true })) : null,
        isAdmin ? settle(api.listResetRequests()) : null,
        settle(fetch('/health').then((r) => r.json())),
      ]);
      if (alive) setD({ registry, mine, docs, phys, dls, alerts, stats, events, chain, users, resets, health });
    })();
    return () => { alive = false; };
  }, [user, canApprove, isSecurity, isAdmin]);

  if (!d) return (<><PageHeader title="Dashboard" /><div className="content"><Loading label="Collecting current status" /></div></>);

  const digital = (d.registry || []).filter((a) => !a.is_physical);
  const physical = (d.registry || []).filter((a) => a.is_physical);
  const approvals = canApprove ? new Set([...(d.docs || []).filter((a) => a.action_type !== 'DOWNLOAD'), ...(d.phys || []),
    ...(d.dls || []).filter((a) => !a.details?.requires_owner_approval || a.details?.owner_approved_by)].map((a) => a.action_id)).size : 0;
  const ownerConsents = (d.dls || []).filter((a) => a.details?.requires_owner_approval && !a.details?.owner_approved_by && a.actor_did !== user.did).length;
  const myOpen = (d.mine || []).filter((a) => ['PENDING', 'APPROVED'].includes(a.status));
  const readyToFetch = (d.mine || []).filter((a) => a.status === 'APPROVED').length;
  const myAlerts = (d.alerts || []).filter((a) => a.state === STAGE[user.role]).length;
  const pendingResets = (d.resets || []).length;

  const rows = [
    { measure: 'Digital assets in your scope', note: 'Documents you own, hold access to, or manage', n: d.registry ? digital.length : null, to: '/digital' },
    { measure: 'Physical assets in your scope', note: user.role === 'USER' ? 'Assets assigned to you' : 'Registered equipment for your departments', n: d.registry ? physical.length : null, to: '/physical' },
    canApprove && { measure: 'Awaiting your approval', note: 'Creations, modifications, access and download requests', n: approvals, to: '/requests', attention: approvals > 0 },
    ownerConsents > 0 && { measure: 'Download requests for your documents', note: 'Your consent as owner is needed first', n: ownerConsents, to: '/requests', attention: true },
    { measure: 'Your open requests', note: readyToFetch ? `${readyToFetch} approved and ready to download` : 'Download and modification requests in progress', n: myOpen.length, to: '/requests' },
    isSecurity && { measure: 'Security alerts in your review stage', note: `${roleName(user.role)} stage of the escalation chain`, n: myAlerts, to: '/alerts', attention: myAlerts > 0 },
    d.stats && { measure: 'High-risk events, last 7 days', note: 'Within the audit records you are permitted to read', n: d.stats.high_risk_7d, to: '/audit', attention: d.stats.high_risk_7d > 0 },
    d.stats && { measure: 'Denied or failed actions, last 7 days', note: 'Refusals, failed sign-ins, duplicate registrations', n: d.stats.denied_7d, to: '/audit' },
    isAdmin && { measure: 'Registered identities', note: `${(d.users || []).filter((u) => !u.is_active).length} revoked or disabled`, n: d.users?.length ?? null, to: '/admin' },
    isAdmin && { measure: 'Login reset requests', note: 'Require out-of-band verification and your Factor 3', n: pendingResets, to: '/admin', attention: pendingResets > 0 },
  ].filter(Boolean);

  const ribbon = [
    { content: <>Ledger <strong>{d.health?.chain_verified ? 'verified' : 'not verified'}</strong>{d.chain?.head_block != null && <>, block {d.chain.head_block}</>}</>, warn: d.health && !d.health.chain_verified },
    { content: <>Indexer <strong>{d.health?.indexer || 'unknown'}</strong></> },
    canApprove && { content: <><strong>{approvals}</strong> awaiting your approval</> },
    isSecurity && { content: <><strong>{myAlerts}</strong> alerts in your stage</>, warn: myAlerts > 0 },
  ];

  return (
    <>
      <PageHeader title={`${greeting()}, ${user.name || 'colleague'}`}
        lede={`${roleName(user.role)}${user.department ? `, ${user.department}` : ''}. Figures below are read live from LexCorp2 and cover only what your role may see.`}
        ribbon={ribbon} />
      <div className="content">
        <div className="grid-main-side">
          <Panel title="Situation" flush>
            <table className="board">
              <tbody>
                {rows.map((r) => (
                  <tr key={r.measure}>
                    <td className="measure">{r.measure}<small>{r.note}</small></td>
                    <td className={`figure${r.attention ? ' attention' : ''}`}>{r.n ?? '—'}</td>
                    <td className="go"><Link className="btn btn-quiet btn-sm" to={r.to}>Open</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
          <div className="stack">
            <Panel title="Your identity">
              <Facts items={[
                ['Name', user.name || 'Unnamed'],
                ['Role', roleName(user.role)],
                ['Department', user.department || 'None'],
                ['Wallet', <Id key="w">{shortWallet(user.wallet_address)}</Id>],
                ['Factor 2 (view and submit)', factorState(user.is_totp_factor2_enabled, user.has_factor2_passkey)],
                ['Factor 3 (approve and modify)', factorState(user.is_totp_factor3_enabled, user.has_factor3_passkey)],
              ]} />
              {(!(user.is_totp_factor2_enabled || user.has_factor2_passkey) || (user.role !== 'USER' && !(user.is_totp_factor3_enabled || user.has_factor3_passkey))) && (
                <div style={{ marginTop: 12 }}><Notice tone="warning">Some actions need a factor you have not set up yet. <Link to="/identity">Set it up in My identity</Link>.</Notice></div>
              )}
            </Panel>
            {d.chain && (
              <Panel title="Ledger integrity">
                <Facts items={[
                  ['Status', <Status key="s" value={d.chain.ok ? 'VERIFIED' : 'REJECTED'}>{d.chain.ok ? 'All checks passed' : 'Check failed'}</Status>],
                  ['Chain', d.chain.chain_id],
                  ['Contract', <Id key="c">{shortWallet(d.chain.contract_address)}</Id>],
                  ['Head block', d.chain.head_block],
                  ...Object.entries(d.chain.checks || {}).map(([k, v]) => [k.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase()), v === true ? 'Pass' : String(v)]),
                ]} />
              </Panel>
            )}
          </div>
        </div>
        {d.events && (
          <Panel title="Recent audit activity" aside={<Link className="btn btn-quiet btn-sm" to="/audit">Full audit trail</Link>} flush>
            {d.events.length === 0 ? <Empty title="No audit events yet" /> : (
              <ul className="timeline">
                {d.events.map((e) => (
                  <li key={e.id}>
                    <time dateTime={e.created_at}>{formatDate(e.created_at)}</time>
                    <div className="row" style={{ gap: 8 }}>
                      <strong>{humanEvent(e.event_type)}</strong>
                      {e.asset_serial && <Id>{e.asset_serial}</Id>}
                      {e.risk_label && ['HIGH', 'CRITICAL', 'MEDIUM'].includes(e.risk_label) && <Status value={e.risk_label}>{`${e.risk_label.charAt(0)}${e.risk_label.slice(1).toLowerCase()} risk`}</Status>}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        )}
        {!d.events && (
          <Panel title="Your recent requests" aside={<Link className="btn btn-quiet btn-sm" to="/requests">All requests</Link>} flush>
            {(d.mine || []).length === 0 ? <Empty title="No requests yet">Open a document in Digital assets to view it or request a copy.</Empty> : (
              <ul className="timeline">
                {d.mine.slice(0, 6).map((a) => (
                  <li key={a.action_id}>
                    <time dateTime={a.created_at}>{formatDate(a.created_at)}</time>
                    <div className="row" style={{ gap: 8 }}><Id>{a.action_id}</Id><span>{a.details?.mode === 'MODIFICATION' ? 'Modification copy' : 'Download'} of <Id>{a.asset_serial}</Id></span><Status value={a.status} /></div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        )}
      </div>
    </>
  );
}

function factorState(totp, passkey) {
  if (totp && passkey) return 'Authenticator and passkey';
  if (totp) return 'Authenticator';
  if (passkey) return 'Passkey';
  return <Status value="PENDING">Not set up</Status>;
}

function greeting() {
  const h = new Date().getHours();
  return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
}

const EVENT_NAMES = {
  DocumentProposed: 'Document submitted', DOCUMENT_VIEWED: 'Document viewed', DOCUMENT_DOWNLOADED: 'Controlled copy downloaded',
  AssetActionApproved: 'Request approved', AssetActionRejected: 'Request rejected', USER_PROVISIONED: 'Identity provisioned',
  AuthenticationSucceeded: 'Signed in', AuthenticationFailed: 'Sign-in failed', WALLET_PROVISIONED: 'Wallet provisioned',
  PHYSICAL_ASSET_CREATED: 'Physical asset registered', PHYSICAL_ASSET_MINTED: 'Physical asset recorded on ledger',
  DOCUMENT_MINTED: 'Document recorded on ledger', DOCUMENT_REVISION_ANCHORED: 'Revision anchored on ledger',
  REVISION_SUBMITTED: 'Revision submitted', ACCESS_GRANTED: 'Access granted', ACCESS_REVOKED: 'Access revoked',
  IDENTITY_REVOKED: 'Identity revoked', ROLE_CHANGED: 'Role changed', CHAIN_ROLES_UPDATED: 'Ledger roles updated',
  SESSION_TERMINATED_IP_CHANGE: 'Session ended: address changed', SESSION_EXPIRED_INACTIVITY: 'Session expired',
  TOTP_ENROLLED: 'Authenticator enrolled', PASSKEY_REGISTERED: 'Passkey registered', LOGOUT: 'Signed out',
  RoleGranted: 'Ledger role granted', RoleRevoked: 'Ledger role revoked', DigitalAssetMinted: 'Ledger: document minted',
  AssetMinted: 'Ledger: physical asset minted', DigitalAssetUpdated: 'Ledger: revision anchored',
};
export const humanEvent = (t) => EVENT_NAMES[t] || (t || '').replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
